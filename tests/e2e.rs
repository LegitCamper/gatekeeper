//! End-to-end tests over real TCP sockets.
//!
//! The unit tests in `proxy.rs` drive the router in-process with `oneshot`,
//! which hands whole `Bytes` to the body stream and never negotiates content
//! encoding. These tests run Gatekeeper and an upstream on real localhost
//! ports so the wire path is exercised: gzip negotiation, and SSE tokens split
//! across genuine TCP chunk boundaries.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use gatekeeper::detector::Detector;
use gatekeeper::proxy::{ProxyState, router};
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

/// SSE that compresses when the caller allows it. This is the path where a
/// compressed upstream leaks *silently*: the JSON path at least fails loudly on
/// unparseable bytes, but the stream paths hand non-UTF-8 through untouched, so
/// tokens reach a client that gunzips for itself.
async fn gzipped_stream(request: Request) -> Response {
    let wants_gzip = request
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

async fn spawn_upstream() -> String {
    serve(
        Router::new()
            .route("/v1/messages", post(echo))
            .route("/v1/stream", post(stream))
            .route("/v1/gzip-stream", post(gzipped_stream))
            .route("/v1/replay", post(replay)),
    )
    .await
}

async fn spawn_gatekeeper(target: &str) -> String {
    let state = ProxyState::new(
        target.parse().expect("valid target URL"),
        reqwest::Client::new(),
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
    reqwest::Client::new()
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

/// The silent-leak case. When Gatekeeper forwards `accept-encoding: gzip`, the
/// SSE path cannot decode the response, passes the bytes through untouched, and
/// the client's own gunzip reveals the tokens. No error is raised anywhere.
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
