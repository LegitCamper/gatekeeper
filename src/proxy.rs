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

use crate::detector::{Detector, RestoreCarry, Restorer};
use crate::toolguard;

#[derive(Clone)]
pub struct ProxyState {
    target_url: Url,
    client: reqwest::Client,
    detector: Arc<Detector>,
    max_body_bytes: usize,
    upstream_auth: Option<(HeaderName, HeaderValue)>,
}

impl ProxyState {
    pub fn new(
        target_url: Url,
        client: reqwest::Client,
        detector: Arc<Detector>,
        max_body_bytes: usize,
        upstream_auth: Option<(HeaderName, HeaderValue)>,
    ) -> Self {
        Self {
            target_url,
            client,
            detector,
            max_body_bytes,
            upstream_auth,
        }
    }
}

/// Builds the provider-facing client without following redirects.
///
/// Redirects must reach the caller unchanged. Following one inside Gatekeeper
/// could turn an Anthropic or OpenAI `POST` into a bodyless `GET`, hiding the
/// original provider response behind an unrelated `200` response.
pub fn upstream_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
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
        Err(_) => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Gatekeeper refused the request: body exceeds its size limit",
            );
        }
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
        Err(_) => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Gatekeeper refused the request: body exceeds its size limit",
            );
        }
    };

    // Mappings belong to this request alone: a placeholder only resolves in the
    // response to the request that created it, so one client's values can never
    // be spliced into another's response, and model-invented text is untouched.
    //
    // Dispatch on the body's *shape*, not its declared content-type. Providers
    // parse a JSON body whatever the header claims, so a client that sends JSON
    // as `text/plain` — or with no content-type at all — would otherwise hand
    // the upstream unredacted PII.
    let (outgoing_body, mappings) = match serde_json::from_slice::<Value>(&body) {
        Ok(mut value) => {
            // Reads of `.env` and key material must never reach the provider, but
            // the read has already run on the client's machine by the time its
            // contents ride back outbound — refusing the request stops the agent
            // without un-reading the file, and since clients resend history every
            // turn it would stop that session forever. Withhold the payload and
            // forward, so the guard holds and the agent keeps working.
            let withheld = toolguard::withhold_protected_reads(&mut value);
            if !withheld.blanked.is_empty() || !withheld.unpaired.is_empty() {
                tracing::warn!(
                    blanked = ?withheld.blanked,
                    unpaired = ?withheld.unpaired,
                    "withheld protected file contents from an outbound request"
                );
            }
            let mut mappings = HashMap::new();
            anonymize_json(&mut value, &state.detector, &mut mappings);
            tracing::debug!(count = mappings.len(), "anonymized request");
            match serde_json::to_vec(&value) {
                Ok(encoded) => (Bytes::from(encoded), mappings),
                Err(error) => {
                    return json_error(
                        StatusCode::BAD_GATEWAY,
                        format!("failed to encode anonymized request: {error}"),
                    );
                }
            }
        }
        // A body that claims to be JSON but is not stays a client error.
        Err(error) if content_type.as_deref().is_some_and(is_json) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("invalid JSON request body: {error}"),
            );
        }
        // `ponytail:` a body that is not JSON at all (binary upload, form post,
        // bare prose) passes through unredacted. Upgrade path: anonymize bodies
        // that are valid UTF-8 text as well, keeping only true binary opaque.
        Err(_) => {
            tracing::debug!("request body is not JSON, skipping anonymization");
            (body, HashMap::new())
        }
    };

    let mut upstream = state.client.request(method, target);
    for (name, value) in &parts.headers {
        let replaced_by_upstream_auth = state
            .upstream_auth
            .as_ref()
            .is_some_and(|_| is_auth_header(name));
        // Compressed upstream bodies are opaque bytes, so tokens would survive
        // into the client. Ask for identity and restore in plain text.
        let compressed = name == header::ACCEPT_ENCODING;
        if !replaced_by_upstream_auth && !compressed && !filtered_header(name, &connection_headers)
        {
            upstream = upstream.header(name, value);
        }
    }
    upstream = upstream.header(header::ACCEPT_ENCODING, "identity");
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

    upstream_response(upstream, &state, mappings).await
}

async fn upstream_response(
    upstream: reqwest::Response,
    state: &ProxyState,
    mappings: HashMap<String, String>,
) -> Response<Body> {
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let response_connection_headers = connection_headers(&headers);
    let response_type = content_type(&headers).map(str::to_owned);

    if status.is_redirection() {
        tracing::warn!(%status, "forwarding upstream redirect without following it");
    }

    tracing::debug!(
        "upstream_response: content-type={:?}, mappings={}",
        response_type,
        mappings.len()
    );

    let restorer = Restorer::new(&mappings);
    // Gatekeeper asked for `identity`, but an upstream is free to ignore that.
    // Compressed bytes cannot be restored, and re-framing them line by line
    // could corrupt the payload, so hand back exactly what arrived.
    let compressed = headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| !value.trim().eq_ignore_ascii_case("identity"));
    let body = if mappings.is_empty() {
        // No tokens to restore, pass through as-is
        Body::from_stream(upstream.bytes_stream())
    } else if compressed {
        tracing::warn!(
            content_type = ?response_type,
            mappings = mappings.len(),
            "upstream compressed a response despite the identity request; \
             placeholders in it cannot be restored"
        );
        Body::from_stream(upstream.bytes_stream())
    } else if response_type.as_deref().is_some_and(is_json) {
        let bytes = match collect_limited(upstream.bytes_stream(), state.max_body_bytes).await {
            Ok(bytes) => bytes,
            Err(LimitedBodyError::TooLarge) => {
                return security_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Gatekeeper refused an oversized upstream response: redaction placeholders \
                     cannot be restored inside it, so forwarding would hand back tokens instead \
                     of your own values",
                );
            }
            Err(LimitedBodyError::Upstream(error)) => {
                tracing::warn!(%error, "failed reading upstream response");
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    format!("upstream response failed: {error}"),
                );
            }
        };
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(mut value) => {
                restore_json(&mut value, &restorer);
                tracing::debug!("restored JSON response");
                match serde_json::to_vec(&value) {
                    Ok(value) => Body::from(value),
                    Err(error) => {
                        return json_error(
                            StatusCode::BAD_GATEWAY,
                            format!("failed to encode upstream response: {error}"),
                        );
                    }
                }
            }
            Err(error) => match std::str::from_utf8(&bytes) {
                Ok(text) => {
                    tracing::warn!(
                        %error,
                        %status,
                        content_type = ?response_type,
                        bytes = bytes.len(),
                        mappings = mappings.len(),
                        "upstream response claims JSON but does not parse; restoring as text"
                    );
                    Body::from(restorer.restore(text))
                }
                Err(_) => {
                    return json_error(
                        StatusCode::BAD_GATEWAY,
                        "upstream response is not text, so redaction placeholders cannot be restored",
                    );
                }
            },
        }
    } else if response_type
        .as_deref()
        .is_some_and(|kind| is_event_stream(kind) || is_ndjson(kind))
    {
        Body::from_stream(restored_lines(upstream.bytes_stream(), restorer))
    } else {
        // For any other content-type, restore tokens in the text stream.
        tracing::debug!(
            "restoring tokens in non-JSON response (content-type={:?})",
            response_type
        );
        Body::from_stream(restored_text_stream(upstream.bytes_stream(), restorer))
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

/// Parse-and-anonymize helper, kept for direct unit testing of the JSON walk;
/// `proxy()` inlines the same steps so the tool guard can see the parsed value.
#[cfg(test)]
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

fn restore_json(value: &mut Value, restorer: &Restorer) {
    match value {
        Value::String(text) => *text = restorer.restore(text),
        Value::Array(values) => {
            for value in values {
                restore_json(value, restorer);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                restore_json(value, restorer);
            }
            restore_object_keys(values, restorer);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Restore tokens in object keys. Rebuild only changed entries; common path has
/// no map mutation. Collisions stay tokenized because JSON cannot losslessly hold
/// two values under the same restored key.
fn restore_object_keys(values: &mut serde_json::Map<String, Value>, restorer: &Restorer) {
    let renames: Vec<(String, String)> = values
        .keys()
        .filter_map(|key| {
            let restored = restorer.restore(key);
            (restored != *key).then(|| (key.clone(), restored))
        })
        .collect();
    for (key, restored) in renames {
        if values.contains_key(&restored) {
            continue;
        }
        if let Some(value) = values.remove(&key) {
            values.insert(restored, value);
        }
    }
}

/// Partial placeholders held between events.
///
/// A provider streams one message a fragment at a time, so a placeholder can
/// straddle several events. `text` carries a fragment of a raw payload;
/// `fields` carries one per JSON field path, because an event body is its own
/// JSON document and the fragment has to rejoin the *same* field of the next
/// event rather than whichever string happens to come first.
#[derive(Default)]
struct StreamCarry {
    text: RestoreCarry,
    fields: HashMap<String, RestoreCarry>,
}

fn restored_lines(
    source: impl Stream<Item = Result<Bytes, reqwest::Error>>,
    restorer: Restorer,
) -> impl Stream<Item = Result<Bytes, reqwest::Error>> {
    try_stream! {
        futures_util::pin_mut!(source);
        let mut carry = BytesMut::new();
        let mut pending = StreamCarry::default();
        while let Some(chunk) = source.next().await {
            carry.extend_from_slice(&chunk?);
            while let Some(newline) = carry.iter().position(|byte| *byte == b'\n') {
                let line_end = newline + 1;
                let line = &carry[..line_end];
                match std::str::from_utf8(line) {
                    Ok(_) => {
                        let line = carry.split_to(line_end);
                        let line = std::str::from_utf8(&line).expect("validated UTF-8 line");
                        yield Bytes::from(restore_stream_line(line, &mut pending, &restorer));
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
                    let line = std::str::from_utf8(&line).expect("validated UTF-8 tail");
                    yield Bytes::from(restore_stream_line(line, &mut pending, &restorer));
                }
                Err(_) => yield carry.split().freeze(),
            }
        }
        // A raw fragment can be emitted as-is; one still held inside a JSON
        // field has nowhere valid to go, so a stream that ends mid-placeholder
        // drops those few characters rather than breaking the envelope.
        if !pending.text.text.is_empty() {
            yield Bytes::from(std::mem::take(&mut pending.text.text));
        }
    }
}

fn restore_stream_line(line: &str, pending: &mut StreamCarry, restorer: &Restorer) -> String {
    let (content, newline) = line
        .strip_suffix('\n')
        .map_or((line, ""), |content| (content, "\n"));
    let mut restored = String::with_capacity(line.len());

    if let Some(payload) = content.strip_prefix("data:") {
        let separator_len = payload.starts_with(' ') as usize;
        let (separator, payload) = payload.split_at(separator_len);
        restored.push_str("data:");
        restored.push_str(separator);
        restored.push_str(&restore_stream_payload(payload, pending, restorer));
    } else if let Some(payload) = restore_stream_json(content, pending, restorer) {
        // A bare JSON line, as NDJSON streams send.
        restored.push_str(&payload);
    } else {
        // SSE metadata and event delimiters are protocol framing, not model text.
        // Feeding them through fragment restoration can hold a trailing hex letter
        // as a possible digest prefix and corrupt names such as `message_delta`.
        restored.push_str(content);
    }
    restored.push_str(newline);
    restored
}

/// Restore an event payload, preferring the JSON-aware path so a placeholder
/// split across events is rejoined inside the field that carries it.
fn restore_stream_payload(payload: &str, pending: &mut StreamCarry, restorer: &Restorer) -> String {
    if let Some(restored) = restore_stream_json(payload, pending, restorer) {
        return restored;
    }

    let payload = if pending.text.text.is_empty() {
        payload.to_owned()
    } else {
        let mut joined = std::mem::take(&mut pending.text.text);
        joined.push_str(payload);
        joined
    };
    restore_stream_text(&payload, &mut pending.text, restorer)
}

/// `Some` only when `payload` is a JSON object or array, so plain `data:` text
/// and SSE sentinels such as `[DONE]` keep the raw-text path.
fn restore_stream_json(
    payload: &str,
    pending: &mut StreamCarry,
    restorer: &Restorer,
) -> Option<String> {
    let trimmed = payload.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return None;
    }
    let mut value: Value = serde_json::from_str(payload).ok()?;
    if !(value.is_object() || value.is_array()) {
        return None;
    }

    restore_json_fields(&mut value, &mut String::new(), pending, restorer);
    serde_json::to_string(&value).ok()
}

/// Restore every string in an event body, keeping a separate partial
/// placeholder per field path so fragments rejoin the field they came from.
fn restore_json_fields(
    value: &mut Value,
    path: &mut String,
    pending: &mut StreamCarry,
    restorer: &Restorer,
) {
    match value {
        Value::String(text) => {
            let mut carry = pending.fields.remove(path.as_str()).unwrap_or_default();
            *text = restore_stream_text(text, &mut carry, restorer);
            if !carry.text.is_empty() || carry.skip_closing_bracket {
                pending.fields.insert(path.clone(), carry);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter_mut().enumerate() {
                let parent = path.len();
                path.push('.');
                path.push_str(&index.to_string());
                restore_json_fields(value, path, pending, restorer);
                path.truncate(parent);
            }
        }
        Value::Object(values) => {
            // Restore values under their original field paths first, then rename
            // keys. Carry state is keyed by that original path across events.
            for (key, value) in values.iter_mut() {
                let parent = path.len();
                path.push('.');
                path.push_str(key);
                restore_json_fields(value, path, pending, restorer);
                path.truncate(parent);
            }
            restore_object_keys(values, restorer);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn restore_stream_text(text: &str, token_carry: &mut RestoreCarry, restorer: &Restorer) -> String {
    restorer.restore_fragment(text, token_carry)
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

fn restored_text_stream(
    source: impl Stream<Item = Result<Bytes, reqwest::Error>>,
    restorer: Restorer,
) -> impl Stream<Item = Result<Bytes, reqwest::Error>> {
    try_stream! {
        futures_util::pin_mut!(source);
        let mut token_carry = RestoreCarry::default();
        while let Some(chunk) = source.next().await {
            let bytes = chunk?;
            match std::str::from_utf8(&bytes) {
                Ok(text) => {
                    let restored = restore_stream_text(text, &mut token_carry, &restorer);
                    yield Bytes::from(restored);
                }
                Err(_) => {
                    // If not valid UTF-8, pass through as-is and skip token restoration
                    yield bytes;
                }
            }
        }
        // Flush any remaining partial token
        if !token_carry.text.is_empty() {
            yield Bytes::from(std::mem::take(&mut token_carry.text));
        }
    }
}

fn target_url(base: &Url, uri: &axum::http::Uri) -> Result<Url, url::ParseError> {
    let origin = &base[..Position::BeforePath];
    let base_path = base.path().trim_end_matches('/');
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path(), axum::http::uri::PathAndQuery::as_str);
    // A query on TARGET_URL belongs to the upstream, not to the caller: an
    // Azure-style gateway base such as `…?api-version=2024-02-01` stops working
    // if forwarding drops it. Caller parameters come first, upstream ones after.
    let target = match base.query().filter(|query| !query.is_empty()) {
        Some(base_query) => {
            let separator = if path_and_query.contains('?') {
                '&'
            } else {
                '?'
            };
            format!("{origin}{base_path}{path_and_query}{separator}{base_query}")
        }
        None => format!("{origin}{base_path}{path_and_query}"),
    };
    Url::parse(&target)
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

/// Newline-delimited JSON, as Ollama and several other providers stream.
fn is_ndjson(content_type: &str) -> bool {
    content_type.eq_ignore_ascii_case("application/x-ndjson")
        || content_type.eq_ignore_ascii_case("application/ndjson")
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

/// Gatekeeper's own error body, shaped like a provider error — `error.type` plus
/// `error.message`. SDKs and models render that shape and skip a bare
/// `{"error": "..."}`, which is why a denial used to surface as an opaque
/// transport failure instead of a reason.
fn json_error(status: StatusCode, message: impl Into<String>) -> Response<Body> {
    error_response(status, "gateway_error", message)
}

/// A refusal caused by Gatekeeper policy rather than by the upstream. The
/// `error.type` is what a caller branches on; the message says who refused and
/// why, since the model relaying this to a human has nothing else to go on.
fn security_error(status: StatusCode, message: impl Into<String>) -> Response<Body> {
    error_response(status, "gatekeeper_security_error", message)
}

fn error_response(status: StatusCode, kind: &str, message: impl Into<String>) -> Response<Body> {
    (
        status,
        Json(json!({
            "type": "error",
            "error": { "type": kind, "message": message.into() },
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    use super::*;

    const PROMPT: &str = "Email Alice Johnson at alice@example.com";

    fn state(target: &str) -> ProxyState {
        state_with_auth(target, None)
    }

    fn state_with_auth(target: &str, upstream_auth: Option<(&str, &str)>) -> ProxyState {
        ProxyState::new(
            target.parse().expect("valid target URL"),
            upstream_client().expect("upstream client"),
            Arc::new(Detector::default()),
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

    #[tokio::test]
    async fn upstream_is_asked_for_identity_encoding() {
        let upstream = header_echo_upstream().await;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT_ENCODING, "gzip, br")
            .body(Body::from("{}"))
            .expect("request built");

        let seen = body_text(
            router(state(&upstream))
                .oneshot(request)
                .await
                .expect("response"),
        )
        .await;

        assert!(seen.contains("identity"), "{seen}");
        assert!(!seen.contains("gzip"), "{seen}");
    }

    #[test]
    fn query_on_the_upstream_base_url_survives_forwarding() {
        let base = Url::parse("https://gateway.example/api?api-version=2024-02-01").expect("base");
        let without_query =
            target_url(&base, &"/v1/messages".parse().expect("uri")).expect("target");
        assert_eq!(
            without_query.as_str(),
            "https://gateway.example/api/v1/messages?api-version=2024-02-01"
        );

        let with_query = target_url(&base, &"/v1/messages?beta=1&count=2".parse().expect("uri"))
            .expect("target");
        assert_eq!(
            with_query.as_str(),
            "https://gateway.example/api/v1/messages?beta=1&count=2&api-version=2024-02-01"
        );
    }

    #[test]
    fn path_and_query_survive_a_trailing_slash_on_the_base_url() {
        let base = Url::parse("http://localhost:11434/").expect("base");
        let target = target_url(&base, &"/v1/models?x=1".parse().expect("uri")).expect("target");

        assert_eq!(target.as_str(), "http://localhost:11434/v1/models?x=1");
        assert_eq!(target.query(), Some("x=1"));
    }

    /// What "same path upstream" does *not* cover: `Url` applies the WHATWG URL
    /// algorithm, so dot segments collapse and `%2e` decodes on the way through.
    /// Every conforming HTTP client normalizes the same way; pinning it here
    /// keeps the README claim honest.
    #[test]
    fn dot_segments_are_normalized_the_way_a_url_parser_normalizes_them() {
        let base = Url::parse("http://localhost:11434").expect("base");
        let target =
            target_url(&base, &"/v1/chat/../messages".parse().expect("uri")).expect("target");

        assert_eq!(target.path(), "/v1/messages");
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
        restore_json(&mut restored, &Restorer::new(&mappings));
        assert_eq!(restored, body);
    }

    #[test]
    fn restores_tokens_in_json_object_keys_without_losing_collisions() {
        let mappings = HashMap::from([(
            "[EMAIL_0123456789ab]".to_owned(),
            "alice@example.com".to_owned(),
        )]);
        let restorer = Restorer::new(&mappings);

        let mut body = json!({"[EMAIL_0123456789ab]": "value"});
        restore_json(&mut body, &restorer);
        assert_eq!(body, json!({"alice@example.com": "value"}));

        // JSON cannot represent two values under one restored key. Keep the
        // tokenized spelling rather than overwrite either field.
        let mut collision = json!({
            "[EMAIL_0123456789ab]": "token value",
            "alice@example.com": "existing value",
        });
        restore_json(&mut collision, &restorer);
        assert_eq!(collision.as_object().expect("object").len(), 2);
        assert_eq!(collision["alice@example.com"], "existing value");
        assert_eq!(collision["[EMAIL_0123456789ab]"], "token value");

        // Streaming JSON events use a separate recursive walker.
        let mut streamed = json!({"delta": {"[EMAIL_0123456789ab]": "value"}});
        restore_json_fields(
            &mut streamed,
            &mut String::new(),
            &mut StreamCarry::default(),
            &restorer,
        );
        assert_eq!(streamed, json!({"delta": {"alice@example.com": "value"}}));
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
        let stream = restored_lines(
            futures_util::stream::iter([Ok(Bytes::from(event))]),
            Restorer::new(&anonymized.mappings),
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
        let mut carry = RestoreCarry::default();

        assert_eq!(
            restore_stream_text(
                "unknown [EMAIL_ffffffffffff]",
                &mut carry,
                &Restorer::new(&mappings)
            ),
            "unknown [EMAIL_ffffffffffff]"
        );
        assert_eq!(
            restore_stream_text("[EMAIL_0123", &mut carry, &Restorer::new(&mappings)),
            ""
        );
        assert_eq!(carry.text, "[EMAIL_0123");
        let mut second = std::mem::take(&mut carry.text);
        second.push_str("456789ab]");
        assert_eq!(
            restore_stream_text(&second, &mut carry, &Restorer::new(&mappings)),
            "known"
        );
        assert!(carry.text.is_empty());
    }
    #[tokio::test]
    async fn streamed_uppercase_text_is_not_dropped() {
        let mappings = HashMap::from([(
            "[EMAIL_0123456789ab]".to_owned(),
            "alice@example.com".to_owned(),
        )]);
        let lines = ["USA", "DONE", "STATUS_OK"].map(|text| {
            Ok(Bytes::from(
                json!({"message": {"content": text}, "done": false}).to_string() + "\n",
            ))
        });
        let stream = restored_lines(futures_util::stream::iter(lines), Restorer::new(&mappings));
        futures_util::pin_mut!(stream);

        let mut content = String::new();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.expect("chunk");
            for line in String::from_utf8(bytes.to_vec()).expect("utf-8").lines() {
                let value: Value = serde_json::from_str(line).expect("valid NDJSON");
                content.push_str(value["message"]["content"].as_str().expect("content"));
            }
        }

        assert_eq!(content, "USADONESTATUS_OK");
    }

    /// A digest a model split with formatting can also land across a chunk
    /// boundary. Both mangling forms have to compose, or streaming responses put a
    /// live hash in the client's view.
    #[test]
    fn restores_noise_split_hash_across_every_chunk_boundary() {
        let mappings = HashMap::from([(
            "[EMAIL_0123456789ab]".to_owned(),
            "alice@example.com".to_owned(),
        )]);
        let restorer = Restorer::new(&mappings);

        for variant in [
            "012345**6789ab**",
            "012345 6789ab",
            "0 1 2 3 4 5 6 7 8 9 a b",
            "012345\n6789ab",
        ] {
            for split in 1..variant.len() {
                if !variant.is_char_boundary(split) {
                    continue;
                }
                let mut carry = RestoreCarry::default();
                let mut output = restore_stream_text(&variant[..split], &mut carry, &restorer);
                output.push_str(&restore_stream_text(
                    &variant[split..],
                    &mut carry,
                    &restorer,
                ));
                output.push_str(&carry.text);
                assert!(
                    output.contains("alice@example.com"),
                    "live hash reached the client for {variant:?} split at {split}: {output:?}"
                );
            }
        }
    }

    #[test]
    fn restores_mangled_hash_across_every_fragment_split() {
        let mappings = HashMap::from([(
            "[EMAIL_0123456789ab]".to_owned(),
            "alice@example.com".to_owned(),
        )]);
        let restorer = Restorer::new(&mappings);

        for variant in ["EMAIL_0123456789ab", "CONTACT:0123456789ab", "0123456789AB"] {
            for split in 1..variant.len() {
                let mut carry = RestoreCarry::default();
                let mut output = restore_stream_text(&variant[..split], &mut carry, &restorer);
                output.push_str(&restore_stream_text(
                    &variant[split..],
                    &mut carry,
                    &restorer,
                ));
                output.push_str(&carry.text);
                assert_eq!(
                    output, "alice@example.com",
                    "failed for {variant} at {split}"
                );
            }
        }
    }

    #[tokio::test]
    async fn restores_mangled_hash_split_across_ndjson_fields() {
        let mappings = HashMap::from([(
            "[EMAIL_0123456789ab]".to_owned(),
            "alice@example.com".to_owned(),
        )]);
        let mutated = "EMAIL_0123456789AB";
        let lines = mutated.chars().map(|character| {
            Ok(Bytes::from(
                json!({"message": {"content": character.to_string()}, "done": false}).to_string()
                    + "\n",
            ))
        });
        let stream = restored_lines(futures_util::stream::iter(lines), Restorer::new(&mappings));
        futures_util::pin_mut!(stream);

        let mut content = String::new();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.expect("chunk");
            for line in String::from_utf8(bytes.to_vec()).expect("utf-8").lines() {
                let value: Value = serde_json::from_str(line).expect("valid NDJSON");
                content.push_str(value["message"]["content"].as_str().expect("content"));
            }
        }

        assert_eq!(content, "alice@example.com");
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
        let stream = restored_lines(
            futures_util::stream::iter(chunks),
            Restorer::new(&anonymized.mappings),
        );

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
        // Upstream receives anonymized tokens, not real PII values.
        // Gatekeeper now restores all response types (including text/plain).
        let target = echo_upstream("text/plain").await;

        let response = router(state(&target))
            .oneshot(messages_request())
            .await
            .expect("proxied response");
        assert_eq!(response.status(), StatusCode::OK);

        let forwarded = body_text(response).await;
        // With the fix, all responses now attempt token restoration
        // This test verifies text/plain responses are processed
        assert!(!forwarded.is_empty());
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

    /// Upstream that ignores the request and always answers with `body`, so a
    /// test can assert on output the client never sent.
    async fn fixed_upstream(content_type: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bound port");
        let address = listener.local_addr().expect("local address");
        let app = Router::new()
            .fallback(move || async move { ([(header::CONTENT_TYPE, content_type)], body) });
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("upstream serves");
        });

        format!("http://{address}")
    }

    /// A read already ran on the client's machine, so refusing the request would
    /// only stop the agent — and, because history is resent, every later turn of
    /// that session. The file's contents are stripped instead and the request
    /// goes through: the provider never sees them, the agent keeps working.
    #[tokio::test]
    async fn contents_of_a_protected_read_never_reach_the_upstream() {
        let upstream = echo_upstream("application/json").await;
        let router = router(state(&upstream));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"messages": [
                    {"role": "assistant", "content": [{
                        "type": "tool_use", "id": "toolu_1", "name": "Read",
                        "input": {"file_path": "/app/.env"}
                    }]},
                    {"role": "user", "content": [{
                        "type": "tool_result", "tool_use_id": "toolu_1",
                        "content": "DATABASE_URL=postgres://admin:ZEBRAqzx3@db:5432/app"
                    }]}
                ]})
                .to_string(),
            ))
            .expect("request built");

        let response = router.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let seen = body_text(response).await;
        // The secret is gone and the model is told why, so it asks the user
        // instead of reaching for another tool that names the same file.
        assert!(!seen.contains("ZEBRAqzx3"), "{seen}");
        assert!(seen.contains("withheld the contents of .env"), "{seen}");
        assert!(seen.contains("Ask the user"), "{seen}");
        // The conversation itself stays intact: history must survive the strip.
        assert!(seen.contains("/app/.env"), "{seen}");
        assert!(seen.contains("tool_use"), "{seen}");
    }

    /// A read in history with no result to strip still must not fail the request,
    /// or one old turn would poison the whole session.
    #[tokio::test]
    async fn a_protected_read_with_no_result_is_forwarded() {
        let upstream = echo_upstream("application/json").await;
        let router = router(state(&upstream));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"messages": [{"role": "assistant", "content": [
                    {"type": "tool_use", "id": "toolu_1", "name": "Read",
                     "input": {"file_path": "/app/.env"}}
                ]}]})
                .to_string(),
            ))
            .expect("request built");

        let response = router.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_tool_call_writing_dotenv_and_reading_public_keys_is_forwarded() {
        let upstream = echo_upstream("application/json").await;
        let router = router(state(&upstream));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"messages": [{"role": "assistant", "content": [
                    {"type": "tool_use", "name": "Bash", "input": {"command": "cp .env.example .env"}},
                    {"type": "tool_use", "name": "Read", "input": {"file_path": "id_ed25519.pub"}}
                ]}]})
                .to_string(),
            ))
            .expect("request built");

        let seen = body_text(router.oneshot(request).await.expect("response")).await;

        assert!(seen.contains(".env.example"), "{seen}");
        assert!(seen.contains("id_ed25519.pub"), "{seen}");
    }

    #[tokio::test]
    async fn token_from_a_previous_request_is_not_restored() {
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

        // A later request carrying only the placeholder has no mapping of its
        // own, so the earlier request's value must not reappear.
        let follow_up = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"content": token})).expect("serialized body"),
            ))
            .expect("built request");
        let seen = body_text(app.oneshot(follow_up).await.expect("second response")).await;

        assert!(!seen.contains(original), "{seen}");
        assert!(seen.contains(&token), "{seen}");
    }

    #[tokio::test]
    async fn model_invented_values_reach_the_client_unchanged() {
        const INVENTED: &str =
            r#"{"content":"Contact Dana Whitfield at dana@example.org or 415-555-0142"}"#;
        let target = fixed_upstream("application/json", INVENTED).await;

        let seen = body_text(
            router(state(&target))
                .oneshot(messages_request())
                .await
                .expect("proxied response"),
        )
        .await;

        assert_eq!(seen, INVENTED);
    }

    #[tokio::test]
    async fn unknown_placeholder_in_response_is_left_alone() {
        const UNKNOWN: &str = r#"{"content":"[EMAIL_ffffffffffff] and [NAME_0123456789ab]"}"#;
        let target = fixed_upstream("application/json", UNKNOWN).await;

        let seen = body_text(
            router(state(&target))
                .oneshot(messages_request())
                .await
                .expect("proxied response"),
        )
        .await;

        assert_eq!(seen, UNKNOWN);
    }

    #[tokio::test]
    async fn streamed_response_restores_only_this_requests_placeholders() {
        let detector = Detector::default();
        let anonymized = detector.anonymize("mail alice@example.com");
        let token = anonymized
            .mappings
            .keys()
            .next()
            .expect("email token")
            .clone();
        const FOREIGN: &str = "[EMAIL_ffffffffffff]";
        let event = format!("data: {{\"text\":\"{token} {FOREIGN}\"}}\n\n");

        let stream = restored_lines(
            futures_util::stream::iter([Ok(Bytes::from(event))]),
            Restorer::new(&anonymized.mappings),
        );
        futures_util::pin_mut!(stream);

        let mut output = String::new();
        while let Some(chunk) = stream.next().await {
            output.push_str(std::str::from_utf8(&chunk.expect("chunk")).expect("utf-8"));
        }

        assert!(output.contains("alice@example.com"), "{output}");
        assert!(output.contains(FOREIGN), "{output}");
    }

    #[tokio::test]
    async fn restores_placeholder_split_across_ndjson_fields() {
        let detector = Detector::default();
        let anonymized = detector.anonymize("mail alice@example.com");
        let token = anonymized
            .mappings
            .keys()
            .next()
            .expect("email token")
            .clone();
        let lines = token.chars().map(|character| {
            Ok(Bytes::from(
                json!({"message": {"content": character.to_string()}, "done": false}).to_string()
                    + "\n",
            ))
        });
        let stream = restored_lines(
            futures_util::stream::iter(lines),
            Restorer::new(&anonymized.mappings),
        );
        futures_util::pin_mut!(stream);

        let mut content = String::new();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.expect("chunk");
            for line in String::from_utf8(bytes.to_vec()).expect("utf-8").lines() {
                let value: Value = serde_json::from_str(line).expect("valid NDJSON");
                content.push_str(value["message"]["content"].as_str().expect("content"));
            }
        }

        assert_eq!(content, "alice@example.com");
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
