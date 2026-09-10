//! Axum routes and transparent upstream proxying.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_stream::try_stream;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::{Request, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use url::{Position, Url};

use crate::detector::{Detector, restore};
use crate::vault::MemoryVault;

#[derive(Clone)]
pub struct ProxyState {
    target_url: Url,
    client: reqwest::Client,
    detector: Arc<Detector>,
    vault: Arc<MemoryVault>,
    max_body_bytes: usize,
    upstream_auth: Option<(HeaderName, HeaderValue)>,
}

impl ProxyState {
    pub fn new(
        target_url: Url,
        client: reqwest::Client,
        detector: Arc<Detector>,
        vault: Arc<MemoryVault>,
        max_body_bytes: usize,
        upstream_auth: Option<(HeaderName, HeaderValue)>,
    ) -> Self {
        Self {
            target_url,
            client,
            detector,
            vault,
            max_body_bytes,
            upstream_auth,
        }
    }
}

pub fn router(state: ProxyState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/healthz", get(health))
        .route("/scan", post(scan))
        .fallback(proxy)
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

#[derive(Deserialize)]
struct ScanRequest {
    text: String,
}

async fn scan(State(state): State<ProxyState>, request: Request<Body>) -> Response<Body> {
    let body = match to_bytes(request.into_body(), state.max_body_bytes).await {
        Ok(body) => body,
        Err(_) => return json_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };
    let input: ScanRequest = match serde_json::from_slice(&body) {
        Ok(input) => input,
        Err(error) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("invalid /scan request: {error}"),
            );
        }
    };

    Json(json!({
        "matches": state.detector.scan(&input.text),
        "anonymized": state.detector.anonymize(&input.text),
    }))
    .into_response()
}

async fn proxy(State(state): State<ProxyState>, request: Request<Body>) -> Response<Body> {
    let content_type = content_type(request.headers()).map(str::to_owned);
    let connection_headers = connection_headers(request.headers());
    let method = request.method().clone();
    let target = match target_url(&state.target_url, request.uri()) {
        Ok(target) => target,
        Err(error) => {
            return json_error(
                StatusCode::BAD_GATEWAY,
                format!("invalid upstream URL: {error}"),
            );
        }
    };
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, state.max_body_bytes).await {
        Ok(body) => body,
        Err(_) => return json_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };

    let outgoing_body = if content_type.as_deref().is_some_and(is_json) {
        match anonymize_json_body(&body, &state.detector) {
            Ok((body, mappings)) => {
                tracing::debug!("anonymize_json_body: found {} mappings", mappings.len());
                if !mappings.is_empty() {
                    state.vault.store(mappings);
                    tracing::debug!("stored mappings in vault");
                }
                body
            }
            Err(error) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid JSON request body: {error}"),
                );
            }
        }
    } else {
        tracing::debug!("request not JSON, skipping anonymization");
        body
    };

    let mut upstream = state.client.request(method, target);
    for (name, value) in &parts.headers {
        let replaced_by_upstream_auth = state
            .upstream_auth
            .as_ref()
            .is_some_and(|_| is_auth_header(name));
        if !replaced_by_upstream_auth && !filtered_header(name, &connection_headers) {
            upstream = upstream.header(name, value);
        }
    }
    if let Some((name, value)) = &state.upstream_auth {
        upstream = upstream.header(name, value);
    }

    let upstream = match upstream.body(outgoing_body).send().await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "upstream request failed");
            return json_error(
                StatusCode::BAD_GATEWAY,
                format!("upstream request failed: {error}"),
            );
        }
    };

    upstream_response(upstream, &state).await
}

async fn upstream_response(upstream: reqwest::Response, state: &ProxyState) -> Response<Body> {
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let response_connection_headers = connection_headers(&headers);
    let response_type = content_type(&headers).map(str::to_owned);
    let mappings = state.vault.lookup();

    tracing::debug!("upstream_response: content-type={:?}, mappings={}", response_type, mappings.len());

    let body = if response_type.as_deref().is_some_and(is_json) {
        let bytes = match collect_limited(upstream.bytes_stream(), state.max_body_bytes).await {
            Ok(bytes) => bytes,
            Err(LimitedBodyError::TooLarge) => {
                return json_error(StatusCode::PAYLOAD_TOO_LARGE, "upstream body too large");
            }
            Err(LimitedBodyError::Upstream(error)) => {
                tracing::warn!(%error, "failed reading upstream response");
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    format!("upstream response failed: {error}"),
                );
            }
        };
        let mut value: Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(error) => {
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    format!("invalid JSON upstream response: {error}"),
                );
            }
        };
        restore_json(&mut value, &mappings);
        match serde_json::to_vec(&value) {
            Ok(value) => Body::from(value),
            Err(error) => {
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    format!("failed to encode upstream response: {error}"),
                );
            }
        }
    } else if response_type.as_deref().is_some_and(is_event_stream) {
        Body::from_stream(restored_sse(upstream.bytes_stream(), mappings))
    } else {
        Body::from_stream(upstream.bytes_stream())
    };

    let mut response = Response::builder().status(status);
    if let Some(response_headers) = response.headers_mut() {
        for (name, value) in &headers {
            if !filtered_header(name, &response_connection_headers) {
                response_headers.append(name, value.clone());
            }
        }
    }
    match response.body(body) {
        Ok(response) => response,
        Err(error) => json_error(
            StatusCode::BAD_GATEWAY,
            format!("failed to build upstream response: {error}"),
        ),
    }
}

fn anonymize_json_body(
    body: &[u8],
    detector: &Detector,
) -> Result<(Bytes, HashMap<String, String>), serde_json::Error> {
    let mut value: Value = serde_json::from_slice(body)?;
    let mut mappings = HashMap::new();
    anonymize_json(&mut value, detector, &mut mappings);
    Ok((Bytes::from(serde_json::to_vec(&value)?), mappings))
}

fn anonymize_json(value: &mut Value, detector: &Detector, mappings: &mut HashMap<String, String>) {
    match value {
        Value::String(text) => {
            let anonymized = detector.anonymize(text);
            *text = anonymized.text;
            mappings.extend(anonymized.mappings);
        }
        Value::Array(values) => {
            for value in values {
                anonymize_json(value, detector, mappings);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                anonymize_json(value, detector, mappings);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn restore_json(value: &mut Value, mappings: &HashMap<String, String>) {
    match value {
        Value::String(text) => *text = restore(text, mappings),
        Value::Array(values) => {
            for value in values {
                restore_json(value, mappings);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                restore_json(value, mappings);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn restored_sse(
    source: impl Stream<Item = Result<Bytes, reqwest::Error>>,
    mappings: HashMap<String, String>,
) -> impl Stream<Item = Result<Bytes, reqwest::Error>> {
    try_stream! {
        futures_util::pin_mut!(source);
        let mut carry = BytesMut::new();
        let mut token_carry = String::new();
        while let Some(chunk) = source.next().await {
            carry.extend_from_slice(&chunk?);
            while let Some(newline) = carry.iter().position(|byte| *byte == b'\n') {
                let line_end = newline + 1;
                let line = &carry[..line_end];
                match std::str::from_utf8(line) {
                    Ok(_) => {
                        let line = carry.split_to(line_end);
                        let line = std::str::from_utf8(&line).expect("validated UTF-8 SSE line");
                        yield Bytes::from(restore_sse_line(line, &mut token_carry, &mappings));
                    }
                    Err(error) if error.error_len().is_none() => break,
                    Err(_) => {
                        yield carry.split_to(line_end).freeze();
                    }
                }
            }
        }
        if !carry.is_empty() {
            match std::str::from_utf8(&carry) {
                Ok(_) => {
                    let line = carry.split().freeze();
                    let line = std::str::from_utf8(&line).expect("validated UTF-8 SSE tail");
                    yield Bytes::from(restore_sse_line(line, &mut token_carry, &mappings));
                }
                Err(_) => yield carry.split().freeze(),
            }
        }
        if !token_carry.is_empty() {
            yield Bytes::from(std::mem::take(&mut token_carry));
        }
    }
}

fn restore_sse_line(
    line: &str,
    token_carry: &mut String,
    mappings: &HashMap<String, String>,
) -> String {
    let (content, newline) = line
        .strip_suffix('\n')
        .map_or((line, ""), |content| (content, "\n"));
    let mut restored = String::with_capacity(line.len());

    if let Some(payload) = content.strip_prefix("data:") {
        let separator_len = payload.starts_with(' ') as usize;
        let (separator, payload) = payload.split_at(separator_len);
        restored.push_str("data:");
        restored.push_str(separator);
        let payload = if token_carry.is_empty() {
            payload.to_owned()
        } else {
            let mut joined = std::mem::take(token_carry);
            joined.push_str(payload);
            joined
        };
        restored.push_str(&restore_stream_text(&payload, token_carry, mappings));
    } else {
        if !token_carry.is_empty() {
            restored.push_str(&std::mem::take(token_carry));
        }
        restored.push_str(&restore_stream_text(content, token_carry, mappings));
    }
    restored.push_str(newline);
    restored
}

fn restore_stream_text(
    text: &str,
    token_carry: &mut String,
    mappings: &HashMap<String, String>,
) -> String {
    let mut output = String::with_capacity(text.len());
    let mut cursor = 0;

    while cursor < text.len() {
        let Some(relative) = text[cursor..].find('[') else {
            output.push_str(&text[cursor..]);
            break;
        };
        let start = cursor + relative;
        output.push_str(&text[cursor..start]);
        let tail = &text[start..];

        if let Some((token, original)) = mappings
            .iter()
            .find(|(token, _)| tail.starts_with(token.as_str()))
        {
            output.push_str(original);
            cursor = start + token.len();
        } else if mappings.keys().any(|token| token.starts_with(tail)) {
            token_carry.push_str(tail);
            break;
        } else {
            output.push('[');
            cursor = start + 1;
        }
    }

    output
}

enum LimitedBodyError {
    TooLarge,
    Upstream(reqwest::Error),
}

async fn collect_limited(
    source: impl Stream<Item = Result<Bytes, reqwest::Error>>,
    limit: usize,
) -> Result<Bytes, LimitedBodyError> {
    futures_util::pin_mut!(source);
    let mut body = BytesMut::new();
    while let Some(chunk) = source.next().await {
        let chunk = chunk.map_err(LimitedBodyError::Upstream)?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(LimitedBodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

fn target_url(base: &Url, uri: &axum::http::Uri) -> Result<Url, url::ParseError> {
    let origin = &base[..Position::BeforePath];
    let base_path = base.path().trim_end_matches('/');
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path(), axum::http::uri::PathAndQuery::as_str);
    Url::parse(&format!("{origin}{base_path}{path_and_query}"))
}

fn content_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
}

fn is_json(content_type: &str) -> bool {
    content_type.eq_ignore_ascii_case("application/json")
        || content_type
            .get(content_type.len().saturating_sub(5)..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case("+json"))
}

fn is_event_stream(content_type: &str) -> bool {
    content_type.eq_ignore_ascii_case("text/event-stream")
}

fn connection_headers(headers: &HeaderMap) -> HashSet<HeaderName> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect()
}

/// Client-supplied credentials, dropped when Gatekeeper injects its own so a
/// stale key from the caller cannot reach the upstream alongside it.
fn is_auth_header(name: &HeaderName) -> bool {
    name == header::AUTHORIZATION || name.as_str() == "x-api-key"
}

fn filtered_header(name: &HeaderName, connection_headers: &HashSet<HeaderName>) -> bool {
    name == header::HOST
        || name == header::CONTENT_LENGTH
        || name == header::CONNECTION
        || name.as_str().eq_ignore_ascii_case("keep-alive")
        || name == header::PROXY_AUTHENTICATE
        || name == header::PROXY_AUTHORIZATION
        || name == header::TE
        || name == header::TRAILER
        || name == header::TRANSFER_ENCODING
        || name == header::UPGRADE
        || connection_headers.contains(name)
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response<Body> {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::TcpListener;
    use tower::ServiceExt;

    use super::*;
    use crate::vault::VaultConfig;

    const PROMPT: &str = "Email Alice Johnson at alice@example.com";

    fn state(target: &str) -> ProxyState {
        state_with_auth(target, None)
    }

    fn state_with_auth(target: &str, upstream_auth: Option<(&str, &str)>) -> ProxyState {
        ProxyState::new(
            target.parse().expect("valid target URL"),
            reqwest::Client::new(),
            Arc::new(Detector::default()),
            Arc::new(MemoryVault::new(VaultConfig {
                ttl: Duration::from_secs(60),
                max_entries: 100,
            })),
            1024 * 1024,
            upstream_auth.map(|(name, value)| {
                (
                    HeaderName::try_from(name).expect("valid header name"),
                    HeaderValue::try_from(value).expect("valid header value"),
                )
            }),
        )
    }

    async fn body_text(response: Response<Body>) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collected");
        String::from_utf8(bytes.to_vec()).expect("utf-8 body")
    }

    /// Upstream that echoes the request body it received, so a test can assert
    /// on exactly what Gatekeeper forwarded.
    async fn echo_upstream(content_type: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bound port");
        let address = listener.local_addr().expect("local address");
        let app = Router::new().fallback(move |request: Request<Body>| async move {
            let bytes = to_bytes(request.into_body(), usize::MAX)
                .await
                .expect("upstream body");
            ([(header::CONTENT_TYPE, content_type)], bytes)
        });
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("upstream serves");
        });

        format!("http://{address}")
    }

    /// Upstream that echoes the request headers it received as JSON.
    async fn header_echo_upstream() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bound port");
        let address = listener.local_addr().expect("local address");
        let app = Router::new().fallback(|request: Request<Body>| async move {
            let headers: HashMap<String, String> = request
                .headers()
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                })
                .collect();
            Json(json!(headers))
        });
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("upstream serves");
        });

        format!("http://{address}")
    }

    #[tokio::test]
    async fn upstream_auth_replaces_client_credentials() {
        let upstream = header_echo_upstream().await;
        let router = router(state_with_auth(&upstream, Some(("x-api-key", "real-key"))));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-api-key", "client-key")
            .header(header::AUTHORIZATION, "Bearer client-bearer")
            .body(Body::from("{}"))
            .expect("request built");

        let seen = body_text(router.oneshot(request).await.expect("response")).await;

        assert!(seen.contains("real-key"), "{seen}");
        assert!(!seen.contains("client-key"), "{seen}");
        assert!(!seen.contains("client-bearer"), "{seen}");
    }

    #[tokio::test]
    async fn client_credentials_pass_through_without_upstream_auth() {
        let upstream = header_echo_upstream().await;
        let router = router(state(&upstream));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-api-key", "client-key")
            .body(Body::from("{}"))
            .expect("request built");

        let seen = body_text(router.oneshot(request).await.expect("response")).await;

        assert!(seen.contains("client-key"), "{seen}");
    }

    #[test]
    fn anonymizes_nested_json_strings() {
        let detector = Detector::default();
        let body = json!({
            "model": "claude-opus-5",
            "max_tokens": 256,
            "stream": false,
            "messages": [{"role": "user", "content": PROMPT}],
        });
        let raw = serde_json::to_vec(&body).expect("serialized body");

        let (anonymized, mappings) = anonymize_json_body(&raw, &detector).expect("anonymized body");
        let text = String::from_utf8(anonymized.to_vec()).expect("utf-8 body");

        assert!(!text.contains("alice@example.com"));
        assert!(!text.contains("Alice Johnson"));
        // Non-string values and non-PII strings pass through untouched.
        assert!(text.contains("\"max_tokens\":256"));
        assert!(text.contains("claude-opus-5"));
        assert_eq!(mappings.len(), 2);

        let mut restored: Value = serde_json::from_slice(&anonymized).expect("valid JSON");
        restore_json(&mut restored, &mappings);
        assert_eq!(restored, body);
    }

    #[tokio::test]
    async fn restores_sse_token_split_across_events() {
        let detector = Detector::default();
        let anonymized = detector.anonymize("mail alice@example.com");
        let token = anonymized
            .mappings
            .keys()
            .next()
            .expect("email token")
            .clone();
        let split = token.len() / 2;
        let event = format!(
            ": keep\nevent: completion\ndata: {{\"text\":\"{}\ndata: {}\"}}\n\ndata: [DONE]\n\n",
            &token[..split],
            &token[split..]
        );
        let stream = restored_sse(
            futures_util::stream::iter([Ok(Bytes::from(event))]),
            anonymized.mappings,
        );
        futures_util::pin_mut!(stream);

        let mut output = String::new();
        while let Some(chunk) = stream.next().await {
            output.push_str(std::str::from_utf8(&chunk.expect("chunk")).expect("utf-8"));
        }

        assert!(output.contains("alice@example.com"));
        assert!(!output.contains(&token));
        assert!(output.contains(": keep\nevent: completion\n"));
        assert!(output.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn stream_restore_leaves_unknown_and_partial_tokens_unchanged() {
        let mappings =
            HashMap::from([(String::from("[EMAIL_0123456789ab]"), String::from("known"))]);
        let mut carry = String::new();

        assert_eq!(
            restore_stream_text("unknown [EMAIL_ffffffffffff]", &mut carry, &mappings),
            "unknown [EMAIL_ffffffffffff]"
        );
        assert_eq!(
            restore_stream_text("[EMAIL_0123", &mut carry, &mappings),
            ""
        );
        assert_eq!(carry, "[EMAIL_0123");
        let mut second = std::mem::take(&mut carry);
        second.push_str("456789ab]");
        assert_eq!(restore_stream_text(&second, &mut carry, &mappings), "known");
        assert!(carry.is_empty());
    }
    #[tokio::test]
    async fn restores_sse_across_arbitrary_chunk_boundaries() {
        let detector = Detector::default();
        let anonymized = detector.anonymize(PROMPT);
        let event = format!("data: {{\"text\":\"{}\"}}\n\n", anonymized.text);

        // Split mid-token to prove the stream buffers partial lines.
        let split = event.len() / 2;
        let chunks = vec![
            Ok(Bytes::from(event[..split].to_owned())),
            Ok(Bytes::from(event[split..].to_owned())),
        ];
        let stream = restored_sse(futures_util::stream::iter(chunks), anonymized.mappings);
        futures_util::pin_mut!(stream);

        let mut output = String::new();
        while let Some(chunk) = stream.next().await {
            output.push_str(std::str::from_utf8(&chunk.expect("chunk")).expect("utf-8"));
        }

        assert!(output.contains("alice@example.com"));
        assert!(output.contains("Alice Johnson"));
    }

    fn messages_request() -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"messages": [{"content": PROMPT}]}))
                    .expect("serialized body"),
            ))
            .expect("built request")
    }

    #[tokio::test]
    async fn upstream_never_receives_the_original_values() {
        // The upstream echoes as text/plain, which is not a restored content
        // type, so the client sees verbatim what Gatekeeper forwarded.
        let target = echo_upstream("text/plain").await;

        let response = router(state(&target))
            .oneshot(messages_request())
            .await
            .expect("proxied response");
        assert_eq!(response.status(), StatusCode::OK);

        let forwarded = body_text(response).await;
        assert!(!forwarded.contains("alice@example.com"));
        assert!(!forwarded.contains("Alice Johnson"));
        assert!(forwarded.contains("[EMAIL_"));
        assert!(forwarded.contains("[NAME_"));
    }

    #[tokio::test]
    async fn client_sees_restored_ip_in_json_responses() {
        let target = echo_upstream("application/json").await;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "messages": [{"content": "Connect to 192.0.2.42"}]
                }))
                .expect("serialized body"),
            ))
            .expect("built request");

        let response = router(state(&target))
            .oneshot(request)
            .await
            .expect("proxied response");

        assert!(body_text(response).await.contains("192.0.2.42"));
    }

    #[tokio::test]
    async fn client_sees_restored_values_in_json_responses() {
        let target = echo_upstream("application/json").await;

        let response = router(state(&target))
            .oneshot(messages_request())
            .await
            .expect("proxied response");
        assert_eq!(response.status(), StatusCode::OK);

        assert_eq!(
            body_text(response).await,
            serde_json::to_string(&json!({"messages": [{"content": PROMPT}]}))
                .expect("serialized body")
        );
    }

    #[tokio::test]
    async fn token_restores_across_different_requests() {
        let target = echo_upstream("application/json").await;
        let state = state(&target);
        let original = "alice@example.com";
        let token = state.detector.anonymize(original).text;
        let app = router(state);

        let stored = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"content": original})).expect("serialized body"),
            ))
            .expect("built request");
        let response = app.clone().oneshot(stored).await.expect("first response");
        assert!(body_text(response).await.contains(original));

        let follow_up = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"content": token})).expect("serialized body"),
            ))
            .expect("built request");
        let response = app.oneshot(follow_up).await.expect("second response");

        assert!(body_text(response).await.contains(original));
    }

    #[tokio::test]
    async fn non_json_bodies_pass_through_untouched() {
        let target = echo_upstream("text/plain").await;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/upload")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(PROMPT))
            .expect("built request");

        let response = router(state(&target))
            .oneshot(request)
            .await
            .expect("proxied response");

        assert_eq!(body_text(response).await, PROMPT);
    }

    #[tokio::test]
    async fn health_reports_ok() {
        let response = router(state("http://127.0.0.1:1"))
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("built request"),
            )
            .await
            .expect("health response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, r#"{"status":"ok"}"#);
    }

    #[tokio::test]
    async fn scan_returns_matches_and_anonymized_text() {
        let response = router(state("http://127.0.0.1:1"))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/scan")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"text": PROMPT})).expect("serialized body"),
                    ))
                    .expect("built request"),
            )
            .await
            .expect("scan response");
        assert_eq!(response.status(), StatusCode::OK);

        let value: Value = serde_json::from_str(&body_text(response).await).expect("valid JSON");
        assert_eq!(value["matches"].as_array().expect("matches array").len(), 2);
        let anonymized = value["anonymized"]["text"]
            .as_str()
            .expect("anonymized text");
        assert!(!anonymized.contains("alice@example.com"));
    }
}
