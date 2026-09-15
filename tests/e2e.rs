//! End-to-end tests over real TCP sockets.
//!
//! The unit tests in `proxy.rs` drive the router in-process with `oneshot`,
//! which hands whole `Bytes` to the body stream and never negotiates content
//! encoding. These tests run Gatekeeper and an upstream on real localhost
//! ports so the wire path is exercised: gzip negotiation, and SSE tokens split
//! across genuine TCP chunk boundaries.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use gatekeeper::detector::Detector;
use gatekeeper::proxy::{ProxyState, router, upstream_client};
use regex::Regex;
use tokio::net::TcpListener;

/// PII fixtures are assembled from fragments rather than written as literals:
/// tooling that rewrites this file would otherwise replace a literal address
/// with a token and the test would silently assert on the wrong string.
fn email() -> String {
    format!("{}@{}.{}", "dana.whitfield", "example", "com")
}

fn prompt() -> String {
    format!("Email {} {} at {}", "Dana", "Whitfield", email())
}

fn token_pattern() -> Regex {
    Regex::new(r"\[[A-Z][A-Z_]*_[0-9a-f]{12}\]").expect("token pattern is valid")
}

fn digest_pattern() -> Regex {
    Regex::new(r"\b[0-9A-F]{12}\b").expect("digest pattern is valid")
}

/// Echoes the request body back, gzipping it when the caller said it could
/// take gzip. This is the upstream behaviour that used to defeat restoration.
async fn echo(request: Request) -> Response {
    let wants_gzip = request
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("gzip"));
    let bytes = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("upstream read the request body");

    if !wants_gzip {
        return ([(header::CONTENT_TYPE, "application/json")], bytes).into_response();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&bytes).expect("gzip accepts the body");
    let compressed = encoder.finish().expect("gzip stream finishes");
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CONTENT_ENCODING, "gzip"),
        ],
        compressed,
    )
        .into_response()
}

/// Streams one token back split three ways: the first TCP write ends inside
/// the token, and the token itself spans two `data:` lines. That forces both
/// the partial-line carry and the partial-token carry to do their job across a
/// boundary the kernel chose, not one a test handed over whole.
async fn stream(request: Request) -> Response {
    let bytes = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("upstream read the request body");
    let text = String::from_utf8(bytes.to_vec()).expect("utf-8 request body");
    let token = token_pattern()
        .find(&text)
        .expect("upstream was handed an anonymized body")
        .as_str();
    let digest = token
        .strip_suffix(']')
        .and_then(|token| token.rsplit_once('_'))
        .map(|(_, digest)| digest)
        .expect("canonical token has a digest")
        .to_ascii_uppercase();
    let mutated = format!("CONTACT:{digest}");

    // Token is ASCII, so byte slicing is safe.
    let (quarter, half) = (mutated.len() / 4, mutated.len() / 2);
    let head = format!("data: {{\"text\":\"{}", &mutated[..quarter]);
    let tail = format!(
        "{}\ndata: {}\"}}\n\ndata: [DONE]\n\n",
        &mutated[quarter..half],
        &mutated[half..]
    );

    let body = async_stream::stream! {
        yield Ok::<_, std::io::Error>(Bytes::from(head));
        // Long enough that the two writes land in separate TCP segments.
        tokio::time::sleep(Duration::from_millis(50)).await;
        yield Ok(Bytes::from(tail));
    };

    (
        [(header::CONTENT_TYPE, "text/event-stream")],
        Body::from_stream(body),
    )
        .into_response()
}

/// SSE that compresses when the caller allows it. Gatekeeper asks upstream for
/// `identity`, so this fixture normally answers in plain text and every
/// placeholder gets restored. `always_gzipped_stream` below covers the case
/// where an upstream ignores that and compresses anyway.
async fn gzipped_stream(request: Request) -> Response {
    gzip_stream_upstream(request, false).await
}

/// The same body from an upstream that ignores `accept-encoding: identity`.
async fn always_gzipped_stream(request: Request) -> Response {
    gzip_stream_upstream(request, true).await
}

async fn gzip_stream_upstream(request: Request, ignore_identity: bool) -> Response {
    let wants_gzip = ignore_identity
        || request
            .headers()
            .get(header::ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("gzip"));
    let bytes = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("upstream read the request body");
    let text = String::from_utf8(bytes.to_vec()).expect("utf-8 request body");
    let token = token_pattern()
        .find(&text)
        .expect("upstream was handed an anonymized body")
        .as_str()
        .to_owned();
    let event = format!("data: {{\"text\":\"{token}\"}}\n\ndata: [DONE]\n\n");

    if !wants_gzip {
        return ([(header::CONTENT_TYPE, "text/event-stream")], event).into_response();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(event.as_bytes())
        .expect("gzip accepts the event");
    let compressed = encoder.finish().expect("gzip stream finishes");

    (
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CONTENT_ENCODING, "gzip"),
        ],
        compressed,
    )
        .into_response()
}

async fn anthropic_stream(request: Request) -> Response {
    let bytes = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("upstream read the request body");
    let text = String::from_utf8(bytes.to_vec()).expect("utf-8 request body");
    let token = token_pattern()
        .find(&text)
        .expect("upstream was handed an anonymized body")
        .as_str();
    let split = token.len() / 2;

    let first_events = [
        (
            "message_start",
            serde_json::json!({
                "type": "message_start",
                "message": {
                    "id": "msg_test",
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": "claude-test",
                    "stop_reason": null,
                    "stop_sequence": null,
                    "usage": {"input_tokens": 12, "output_tokens": 1}
                }
            }),
        ),
        (
            "content_block_start",
            serde_json::json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""}
            }),
        ),
        (
            "content_block_delta",
            serde_json::json!({
                "type": "content_block_delta",
                "index": 0,
                // First half of a split placeholder. The other half arrives in a
                // later TCP chunk, so the per-field carry must survive the gap.
                "delta": {"type": "text_delta", "text": &token[..split]}
            }),
        ),
    ]
    .into_iter()
    .map(|(event, data)| format!("event: {event}\ndata: {data}\n\n"))
    .collect::<String>();
    let split_delta_events = [(
        "content_block_delta",
        serde_json::json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": &token[split..]}
        }),
    )]
    .into_iter()
    .map(|(event, data)| format!("event: {event}\ndata: {data}\n\n"))
    .collect::<String>();
    let remaining_events = [
        (
            "content_block_stop",
            serde_json::json!({"type": "content_block_stop", "index": 0}),
        ),
        (
            "message_delta",
            serde_json::json!({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                "usage": {"output_tokens": 8}
            }),
        ),
        ("message_stop", serde_json::json!({"type": "message_stop"})),
    ]
    .into_iter()
    .map(|(event, data)| format!("event: {event}\ndata: {data}\n\n"))
    .collect::<String>();

    let body = async_stream::stream! {
        yield Ok::<_, std::io::Error>(Bytes::from(first_events));
        tokio::time::sleep(Duration::from_millis(50)).await;
        yield Ok(Bytes::from(split_delta_events));
        tokio::time::sleep(Duration::from_millis(50)).await;
        yield Ok(Bytes::from(remaining_events));
    };

    (
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (
                header::HeaderName::from_static("x-request-id"),
                "req_stream_test",
            ),
        ],
        Body::from_stream(body),
    )
        .into_response()
}

async fn anthropic_message(request: Request) -> Response {
    let bytes = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("upstream read the request body");
    let text = String::from_utf8(bytes.to_vec()).expect("utf-8 request body");
    let token = token_pattern()
        .find(&text)
        .expect("upstream was handed an anonymized body")
        .as_str();
    let message = serde_json::json!({
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": token}],
        "model": "claude-test",
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {"input_tokens": 12, "output_tokens": 8}
    });

    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::HeaderName::from_static("x-request-id"),
                "req_message_test",
            ),
        ],
        message.to_string(),
    )
        .into_response()
}

async fn openai_chat(request: Request) -> Response {
    let bytes = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("upstream read the request body");
    let text = String::from_utf8(bytes.to_vec()).expect("utf-8 request body");
    let token = token_pattern()
        .find(&text)
        .expect("upstream was handed an anonymized body")
        .as_str();
    let completion = serde_json::json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-test",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": token},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}
    });

    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::HeaderName::from_static("x-request-id"),
                "req_openai_chat_test",
            ),
        ],
        completion.to_string(),
    )
        .into_response()
}

async fn openai_stream(request: Request) -> Response {
    let bytes = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("upstream read the request body");
    let text = String::from_utf8(bytes.to_vec()).expect("utf-8 request body");
    let token = token_pattern()
        .find(&text)
        .expect("upstream was handed an anonymized body")
        .as_str();
    let split = token.len() / 2;
    let chunks = [
        serde_json::json!({
            "id": "chatcmpl-test",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-test",
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": &token[..split]}, "finish_reason": null}]
        }),
        serde_json::json!({
            "id": "chatcmpl-test",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-test",
            "choices": [{"index": 0, "delta": {"content": &token[split..]}, "finish_reason": null}]
        }),
        serde_json::json!({
            "id": "chatcmpl-test",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-test",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
        }),
    ];
    let body = chunks
        .into_iter()
        .map(|chunk| format!("data: {chunk}\n\n"))
        .collect::<String>()
        + "data: [DONE]\n\n";

    (
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (
                header::HeaderName::from_static("x-request-id"),
                "req_openai_stream_test",
            ),
        ],
        body,
    )
        .into_response()
}

async fn request_target(request: Request) -> Json<serde_json::Value> {
    Json(serde_json::json!({"target": request.uri().to_string()}))
}

async fn malformed_json(request: Request) -> Response {
    let bytes = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("upstream read the request body");
    let text = String::from_utf8(bytes.to_vec()).expect("utf-8 request body");
    let value = token_pattern()
        .find(&text)
        .map_or("plain", |found| found.as_str());
    (
        [(header::CONTENT_TYPE, "application/json")],
        format!(r#"{{"content":"{value}""#),
    )
        .into_response()
}

async fn empty_json() -> Response {
    ([(header::CONTENT_TYPE, "application/json")], Body::empty()).into_response()
}

async fn binary_json() -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        Bytes::from_static(&[0xff, 0xfe, 0xfd]),
    )
        .into_response()
}

async fn serve(app: Router) -> String {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bound an ephemeral port");
    let address = listener.local_addr().expect("listener has a local address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server runs");
    });
    format!("http://{address}")
}

/// Remembers the first placeholder it is ever sent and replays it in every
/// later response, standing in for a model that emits a token it was not given
/// in this request.
async fn replay(request: Request) -> Response {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<Option<String>>> = std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(None));

    let bytes = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("upstream read the request body");
    let text = String::from_utf8_lossy(&bytes);
    if let Some(found) = token_pattern().find(&text) {
        let mut slot = seen.lock().expect("replay mutex");
        slot.get_or_insert_with(|| found.as_str().to_owned());
    }
    let replayed = seen
        .lock()
        .expect("replay mutex")
        .clone()
        .unwrap_or_default();

    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({ "content": replayed }).to_string(),
    )
        .into_response()
}

async fn spawn_redirect_upstream() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bound an ephemeral port");
    let address = listener.local_addr().expect("listener has a local address");
    let base = format!("http://{address}");
    let location = HeaderValue::from_str(&format!("{base}/landing")).expect("valid location");
    let landing_requests = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&landing_requests);
    let app = Router::new()
        .route(
            "/v1/messages",
            post(move || {
                let location = location.clone();
                async move {
                    (
                        StatusCode::FOUND,
                        [(header::LOCATION, location)],
                        "redirect response",
                    )
                }
            }),
        )
        .route(
            "/landing",
            get(move || {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({"status": "wrong endpoint"}))
                }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server runs");
    });

    (base, landing_requests)
}

async fn spawn_upstream() -> String {
    serve(
        Router::new()
            .route("/v1/messages", post(echo))
            .route("/v1/stream", post(stream))
            .route("/v1/gzip-stream", post(gzipped_stream))
            .route("/v1/gzip-always", post(always_gzipped_stream))
            .route("/v1/anthropic-stream", post(anthropic_stream))
            .route("/v1/anthropic-message", post(anthropic_message))
            .route("/v1/chat/completions", post(openai_chat))
            .route("/v1/chat/completions/stream", post(openai_stream))
            .route("/base/v1/responses", post(request_target))
            .route("/v1/malformed", post(malformed_json))
            .route("/v1/empty", post(empty_json))
            .route("/v1/binary", post(binary_json))
            .route("/v1/replay", post(replay)),
    )
    .await
}

async fn spawn_gatekeeper(target: &str) -> String {
    let state = ProxyState::new(
        target.parse().expect("valid target URL"),
        upstream_client().expect("upstream client"),
        Arc::new(Detector::default()),
        1024 * 1024,
        None,
    );
    serve(router(state)).await
}

/// The test client must not decompress on its own, or a gzipped response would
/// look identical to a plain one. `reqwest` is built without the `gzip`
/// feature, so this only needs to avoid asking for it implicitly.
fn client() -> reqwest::Client {
    upstream_client().expect("test client")
}

/// Guards the test below: if the upstream fixture ever stopped compressing,
/// `client_never_receives_gzipped_tokens` would pass for the wrong reason.
#[tokio::test]
async fn upstream_fixture_gzips_when_asked() {
    let upstream = spawn_upstream().await;

    let response = client()
        .post(format!("{upstream}/v1/messages"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT_ENCODING, "gzip")
        .body(r#"{"content":"hello"}"#)
        .send()
        .await
        .expect("upstream responded");

    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok()),
        Some("gzip")
    );
    let bytes = response.bytes().await.expect("read upstream body");
    assert_eq!(&bytes[..2], &[0x1f, 0x8b], "gzip magic bytes");
}

/// Without the `identity` fix this fails loudly rather than leaking: gzip bytes
/// are not parseable JSON, so Gatekeeper returns 502. See
/// `gzipped_sse_does_not_leak_tokens_to_the_client` for the path that leaks
/// silently instead.
#[tokio::test]
async fn client_never_receives_gzipped_tokens() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let prompt = prompt();

    let response = client()
        .post(format!("{gatekeeper}/v1/messages"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT_ENCODING, "gzip, deflate, br")
        .json(&serde_json::json!({"messages": [{"content": prompt}]}))
        .send()
        .await
        .expect("gatekeeper responded");

    assert!(
        response.headers().get(header::CONTENT_ENCODING).is_none(),
        "response was compressed, so tokens would reach the client verbatim"
    );

    let body = response.text().await.expect("utf-8 response body");
    assert!(body.contains(&email()), "email was not restored: {body}");
    assert!(
        !token_pattern().is_match(&body),
        "a token survived into the client: {body}"
    );
}

/// Gatekeeper's response-side guard: it asks upstream for `identity`, so the
/// SSE path receives plain text, restores it, and hands the client uncompressed
/// bytes. An upstream that ignores the request is covered by
/// `compressed_bytes_are_forwarded_without_being_mangled`.
#[tokio::test]
async fn gzipped_sse_does_not_leak_tokens_to_the_client() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let email = email();

    let response = client()
        .post(format!("{gatekeeper}/v1/gzip-stream"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT_ENCODING, "gzip")
        .json(&serde_json::json!({"messages": [{"content": email}]}))
        .send()
        .await
        .expect("gatekeeper responded");

    assert!(
        response.headers().get(header::CONTENT_ENCODING).is_none(),
        "response was compressed, so Gatekeeper could not restore it"
    );

    let bytes = response.bytes().await.expect("read response body");
    let body = String::from_utf8(bytes.to_vec()).expect("utf-8 response body");
    assert!(body.contains(&email), "email was not restored: {body}");
    assert!(
        !token_pattern().is_match(&body),
        "a token survived into the client: {body}"
    );
}

/// An upstream that ignores `accept-encoding: identity` gets its compressed
/// bytes back exactly as they arrived, `content-encoding` included. Gatekeeper
/// cannot restore inside them — that is the documented limit of restoring in
/// plain text — but it must not corrupt them either, or the client's own gunzip
/// fails instead of merely showing a token.
#[tokio::test]
async fn compressed_bytes_are_forwarded_without_being_mangled() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let email = email();

    let response = client()
        .post(format!("{gatekeeper}/v1/gzip-always"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({"messages": [{"content": email}]}))
        .send()
        .await
        .expect("gatekeeper responded");

    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok()),
        Some("gzip"),
        "the upstream's own encoding must survive"
    );
    let bytes = response.bytes().await.expect("read response body");
    assert_eq!(&bytes[..2], &[0x1f, 0x8b], "gzip magic bytes");

    let mut gunzipped = String::new();
    GzDecoder::new(&bytes[..])
        .read_to_string(&mut gunzipped)
        .expect("the forwarded bytes still gunzip");
    assert!(
        token_pattern().is_match(&gunzipped),
        "the placeholder should still be there for the client to see: {gunzipped}"
    );
    assert!(
        !gunzipped.contains(&email),
        "a compressed response cannot be restored: {gunzipped}"
    );
}

/// A placeholder minted for one request must stay opaque in a later request's
/// response: restoration is scoped to the request that created the mapping.
#[tokio::test]
async fn placeholder_from_an_earlier_request_is_not_restored() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;

    // First request mints a mapping for the email and teaches the upstream its
    // placeholder.
    client()
        .post(format!("{gatekeeper}/v1/replay"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({"messages": [{"content": prompt()}]}))
        .send()
        .await
        .expect("gatekeeper responded");

    // Second request carries no PII, so it owns no mappings.
    let body = client()
        .post(format!("{gatekeeper}/v1/replay"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({"messages": [{"content": "summarize the changelog"}]}))
        .send()
        .await
        .expect("gatekeeper responded")
        .text()
        .await
        .expect("utf-8 response body");

    assert!(
        !body.contains(&email()),
        "another request's value leaked into this response: {body}"
    );
    assert!(
        token_pattern().is_match(&body),
        "replayed placeholder should reach the client verbatim: {body}"
    );
}

#[tokio::test]
async fn upstream_redirect_is_forwarded_without_a_second_request() {
    let (upstream, landing_requests) = spawn_redirect_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let response = client()
        .post(format!("{gatekeeper}/v1/messages"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({"messages": [{"content": prompt()}]}))
        .send()
        .await
        .expect("gatekeeper responded");

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some(format!("{upstream}/landing").as_str())
    );
    assert_eq!(
        response.text().await.expect("redirect body"),
        "redirect response"
    );
    assert_eq!(landing_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn canonical_anthropic_sse_stays_parseable() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let response = client()
        .post(format!("{gatekeeper}/v1/anthropic-stream"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({"messages": [{"content": email()}]}))
        .send()
        .await
        .expect("gatekeeper responded");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some("req_stream_test")
    );
    let body = response.text().await.expect("utf-8 stream body");
    let events = body
        .lines()
        .filter_map(|line| line.strip_prefix("event: "))
        .collect::<Vec<_>>();
    assert_eq!(
        events,
        [
            "message_start",
            "content_block_start",
            "content_block_delta",
            "content_block_delta",
            "content_block_stop",
            "message_delta",
            "message_stop",
        ]
    );
    for payload in body.lines().filter_map(|line| line.strip_prefix("data: ")) {
        serde_json::from_str::<serde_json::Value>(payload).expect("valid Anthropic SSE JSON");
    }
    // An SSE parser only ends an event on the blank separator, so a frame that
    // lost it would merge two events into one unparseable payload.
    assert_eq!(
        body.lines().filter(|line| line.is_empty()).count(),
        7,
        "SSE event separators were not preserved: {body}"
    );
    assert!(body.contains(&email()), "email was not restored: {body}");
    assert!(body.ends_with("data: {\"type\":\"message_stop\"}\n\n"));
}

#[tokio::test]
async fn canonical_anthropic_message_keeps_its_shape() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let response = client()
        .post(format!("{gatekeeper}/v1/anthropic-message"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({"messages": [{"content": email()}]}))
        .send()
        .await
        .expect("gatekeeper responded");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some("req_message_test")
    );
    let message: serde_json::Value = response.json().await.expect("valid Message JSON");
    assert_eq!(message["type"], "message");
    assert_eq!(message["role"], "assistant");
    assert_eq!(message["content"][0]["type"], "text");
    assert_eq!(message["content"][0]["text"], email());
    assert_eq!(message["usage"]["input_tokens"], 12);
}

#[tokio::test]
async fn canonical_openai_chat_completion_keeps_its_shape() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let response = client()
        .post(format!("{gatekeeper}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({"messages": [{"role": "user", "content": email()}]}))
        .send()
        .await
        .expect("gatekeeper responded");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some("req_openai_chat_test")
    );
    let completion: serde_json::Value = response.json().await.expect("valid completion JSON");
    assert_eq!(completion["object"], "chat.completion");
    assert_eq!(completion["choices"][0]["message"]["role"], "assistant");
    assert_eq!(completion["choices"][0]["message"]["content"], email());
    assert_eq!(completion["usage"]["total_tokens"], 20);
}

#[tokio::test]
async fn canonical_openai_sse_stays_parseable() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let response = client()
        .post(format!("{gatekeeper}/v1/chat/completions/stream"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({"messages": [{"role": "user", "content": email()}], "stream": true}))
        .send()
        .await
        .expect("gatekeeper responded");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some("req_openai_stream_test")
    );
    let body = response.text().await.expect("utf-8 stream body");
    let payloads = body
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .collect::<Vec<_>>();
    assert_eq!(payloads.last(), Some(&"[DONE]"));
    for payload in &payloads[..payloads.len() - 1] {
        let chunk: serde_json::Value =
            serde_json::from_str(payload).expect("valid OpenAI SSE JSON");
        assert_eq!(chunk["object"], "chat.completion.chunk");
    }
    assert!(body.contains(&email()), "email was not restored: {body}");
    assert!(body.ends_with("data: [DONE]\n\n"));
}

#[tokio::test]
async fn incoming_path_and_query_are_appended_to_the_upstream_base_path() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&format!("{upstream}/base")).await;
    let response = client()
        .post(format!(
            "{gatekeeper}/v1/responses?include=message.output_text&limit=2"
        ))
        .header(header::CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await
        .expect("gatekeeper responded");

    assert_eq!(response.status(), StatusCode::OK);
    let target: serde_json::Value = response.json().await.expect("valid target JSON");
    assert_eq!(
        target["target"],
        "/base/v1/responses?include=message.output_text&limit=2"
    );
}

/// A query written into `TARGET_URL` is part of the upstream's identity, not a
/// caller parameter: an Azure-style gateway base stops working if dropping it
/// takes the request's `api-version` with it.
#[tokio::test]
async fn query_on_the_target_url_is_not_dropped() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&format!("{upstream}/base?api-version=2024-02-01")).await;

    let without_caller_query = client()
        .post(format!("{gatekeeper}/v1/responses"))
        .header(header::CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await
        .expect("gatekeeper responded");
    let target: serde_json::Value = without_caller_query
        .json()
        .await
        .expect("valid target JSON");
    assert_eq!(
        target["target"],
        "/base/v1/responses?api-version=2024-02-01"
    );

    let with_caller_query = client()
        .post(format!("{gatekeeper}/v1/responses?limit=2"))
        .header(header::CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await
        .expect("gatekeeper responded");
    let target: serde_json::Value = with_caller_query.json().await.expect("valid target JSON");
    assert_eq!(
        target["target"],
        "/base/v1/responses?limit=2&api-version=2024-02-01"
    );
}

#[tokio::test]
async fn malformed_json_keeps_status_and_restores_request_values() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let response = client()
        .post(format!("{gatekeeper}/v1/malformed"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({"content": email()}))
        .send()
        .await
        .expect("gatekeeper responded");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.text().await.expect("utf-8 malformed JSON"),
        format!(r#"{{"content":"{}""#, email())
    );
}

#[tokio::test]
async fn malformed_json_without_mappings_passes_through_unchanged() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let response = client()
        .post(format!("{gatekeeper}/v1/malformed"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"content":"plain request"}"#)
        .send()
        .await
        .expect("gatekeeper responded");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.text().await.expect("utf-8 malformed JSON"),
        r#"{"content":"plain""#
    );
}

#[tokio::test]
async fn empty_json_response_stays_empty() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let response = client()
        .post(format!("{gatekeeper}/v1/empty"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({"content": email()}))
        .send()
        .await
        .expect("gatekeeper responded");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .bytes()
            .await
            .expect("empty response body")
            .is_empty()
    );
}

#[tokio::test]
async fn binary_json_with_mappings_returns_gateway_error() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let response = client()
        .post(format!("{gatekeeper}/v1/binary"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({"content": email()}))
        .send()
        .await
        .expect("gatekeeper responded");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let error: serde_json::Value = response.json().await.expect("valid error JSON");
    assert_eq!(error["type"], "error");
    assert_eq!(error["error"]["type"], "gateway_error");
}

#[tokio::test]
async fn mangled_hashes_restore_across_real_tcp_chunks() {
    let upstream = spawn_upstream().await;
    let gatekeeper = spawn_gatekeeper(&upstream).await;
    let email = email();

    let response = client()
        .post(format!("{gatekeeper}/v1/stream"))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({"messages": [{"content": email}]}))
        .send()
        .await
        .expect("gatekeeper responded");

    let body = response.text().await.expect("utf-8 stream body");
    assert!(body.contains(&email), "email was not restored: {body}");
    assert!(
        !token_pattern().is_match(&body),
        "a token survived into the client: {body}"
    );
    assert!(
        !digest_pattern().is_match(&body),
        "a bare digest survived into the client: {body}"
    );
    assert!(
        !body.contains("CONTACT:"),
        "token decoration survived: {body}"
    );
    assert!(
        body.ends_with("data: [DONE]\n\n"),
        "stream truncated: {body}"
    );
}
