use super::*;

pub(super) fn storage_error(error: StorageError) -> Response<Body> {
    tracing::error!(%error, "persistent mapping operation failed");
    json_error(StatusCode::SERVICE_UNAVAILABLE, error.to_string())
}

pub(super) async fn delete_conversation(
    State(state): State<ProxyState>,
    request: Request<Body>,
) -> Response<Body> {
    if !state.authenticate(request.headers()) {
        return json_error(StatusCode::UNAUTHORIZED, "invalid Gatekeeper client token");
    }
    let Some(store) = state.storage.clone() else {
        return json_error(StatusCode::NOT_FOUND, "persistent storage is disabled");
    };
    let conversation = match state.conversation(request.headers()) {
        Ok(Some(conversation)) => conversation,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "missing or invalid conversation ID",
            );
        }
    };
    match tokio::task::spawn_blocking(move || store.delete(&conversation)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(error)) => storage_error(error),
        Err(_) => storage_error(StorageError::Worker),
    }
}

pub(super) async fn persistent_response(
    upstream: reqwest::Response,
    limit: usize,
    restorer: Restorer,
) -> Response<Body> {
    let status = upstream.status();
    let headers = upstream.headers().clone();
    if headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return json_error(
            StatusCode::BAD_GATEWAY,
            "persistent restoration requires an uncompressed upstream response",
        );
    }
    let kind = content_type(&headers).unwrap_or_default();
    if !(kind.is_empty() || kind.starts_with("text/") || is_json(kind) || is_ndjson(kind)) {
        return json_error(
            StatusCode::BAD_GATEWAY,
            "persistent restoration requires a text or JSON upstream response",
        );
    }
    let bytes = match collect_limited(upstream.bytes_stream(), limit).await {
        Ok(bytes) => bytes,
        Err(LimitedBodyError::TooLarge) => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "persistent response exceeds its inspection limit",
            );
        }
        Err(LimitedBodyError::Upstream(_)) => {
            return json_error(
                StatusCode::BAD_GATEWAY,
                "upstream response failed before validation",
            );
        }
    };
    if std::str::from_utf8(&bytes).is_err() {
        return json_error(StatusCode::BAD_GATEWAY, "persistent response is not UTF-8");
    }
    // ponytail: buffer durable responses before releasing executable output; incremental tool-aware validation can restore low latency.
    let source = futures_util::stream::once(async move { Ok::<_, reqwest::Error>(bytes) });
    let body = if kind == "text/event-stream" || is_ndjson(kind) {
        Body::from_stream(restored_lines_limited(source, restorer, limit))
    } else if is_json(kind) {
        let bytes = match to_bytes(Body::from_stream(source), limit).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    "persistent response buffering failed",
                );
            }
        };
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(mut value) => {
                restore_json(&mut value, &restorer);
                match serde_json::to_vec(&value) {
                    Ok(bytes) => Body::from(bytes),
                    Err(_) => {
                        return json_error(
                            StatusCode::BAD_GATEWAY,
                            "persistent response encoding failed",
                        );
                    }
                }
            }
            Err(_) => {
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    "persistent upstream returned malformed JSON",
                );
            }
        }
    } else {
        Body::from_stream(restored_text_stream(source, restorer))
    };
    let restored = match to_bytes(body, limit).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return json_error(
                StatusCode::BAD_GATEWAY,
                "restored response failed or exceeded its inspection limit",
            );
        }
    };
    let Ok(text) = std::str::from_utf8(&restored) else {
        return json_error(StatusCode::BAD_GATEWAY, "restored response is not UTF-8");
    };
    let messages: Vec<String> = if kind == "text/event-stream" {
        sse_payloads(text)
    } else if is_ndjson(kind) {
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect()
    } else {
        vec![text.to_owned()]
    };
    if (kind == "text/event-stream" || is_ndjson(kind))
        && messages
            .iter()
            .any(|message| message != "[DONE]" && serde_json::from_str::<Value>(message).is_err())
    {
        return json_error(
            StatusCode::BAD_GATEWAY,
            "persistent upstream returned malformed stream data",
        );
    }
    if kind == "text/event-stream"
        && !messages
            .last()
            .is_some_and(|message| stream_terminal(message))
    {
        return json_error(
            StatusCode::BAD_GATEWAY,
            "upstream ended before persistent response completion",
        );
    }
    if unresolved_messages(messages.iter().map(String::as_str)) {
        return json_error(
            StatusCode::BAD_GATEWAY,
            "unresolved redaction placeholder; output withheld, reread original data in a fresh conversation",
        );
    }
    let mut response = Response::new(Body::from(restored));
    *response.status_mut() = status;
    let connections = connection_headers(&headers);
    for (name, value) in &headers {
        if !filtered_header(name, &connections) && name != header::CONTENT_ENCODING {
            response.headers_mut().append(name, value.clone());
        }
    }
    response
}

fn sse_payloads(text: &str) -> Vec<String> {
    let mut messages = Vec::new();
    let mut data = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            if !data.is_empty() {
                messages.push(data.join("\n"));
                data.clear();
            }
        } else if let Some(value) = line.strip_prefix("data:") {
            data.push(value.strip_prefix(' ').unwrap_or(value));
        }
    }
    if !data.is_empty() {
        messages.push(data.join("\n"));
    }
    messages
}

fn stream_terminal(message: &str) -> bool {
    message == "[DONE]"
        || serde_json::from_str::<Value>(message)
            .ok()
            .is_some_and(|value| {
                matches!(
                    value["type"].as_str(),
                    Some(
                        "message_stop"
                            | "response.completed"
                            | "response.failed"
                            | "response.incomplete"
                            | "response.cancelled"
                            | "response.done"
                            | "error"
                    )
                )
            })
}

pub(super) fn unresolved_messages<'a>(messages: impl Iterator<Item = &'a str>) -> bool {
    let mut fields = HashMap::new();
    for message in messages {
        if let Ok(value) = serde_json::from_str::<Value>(message) {
            if collect_fields(&value, &mut Vec::new(), &mut fields) {
                return true;
            }
        } else if unresolved_string(message, 0) {
            return true;
        }
    }
    fields.values().any(|text| unresolved_string(text, 0))
}

fn unresolved_string(text: &str, depth: usize) -> bool {
    if crate::detector::contains_placeholder(text) {
        return true;
    }
    if depth >= STRINGIFIED_JSON_DEPTH {
        return serde_json::from_str::<Value>(text).is_ok_and(|value| {
            matches!(value, Value::String(_) | Value::Array(_) | Value::Object(_))
        });
    }
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return unresolved_value(&value, depth + 1);
    }
    false
}

fn unresolved_value(value: &Value, depth: usize) -> bool {
    match value {
        Value::String(text) => unresolved_string(text, depth),
        Value::Array(values) => values.iter().any(|value| unresolved_value(value, depth)),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| unresolved_string(key, depth) || unresolved_value(value, depth)),
        _ => false,
    }
}

fn collect_fields(
    value: &Value,
    path: &mut StreamPath,
    fields: &mut HashMap<StreamPath, String>,
) -> bool {
    match value {
        Value::String(text) => {
            if unresolved_string(text, 0) {
                return true;
            }
            fields.entry(path.clone()).or_default().push_str(text);
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                path.push(PathSegment::ArrayIndex(index));
                if collect_fields(value, path, fields) {
                    return true;
                }
                path.pop();
            }
        }
        Value::Object(values) => {
            let length = path.len();
            path.extend(stream_discriminators(values));
            for (key, value) in values {
                if crate::detector::contains_placeholder(key) {
                    return true;
                }
                path.push(PathSegment::Key(key.clone()));
                if collect_fields(value, path, fields) {
                    return true;
                }
                path.pop();
            }
            path.truncate(length);
        }
        _ => {}
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_encoded_and_split_placeholders_including_opaque_named_fields() {
        let encoded =
            json!({"arguments": "{\"text\":\"\\u005bCUSTOM_000000000000\\u005d\"}"}).to_string();
        assert!(unresolved_messages(std::iter::once(encoded.as_str())));
        let parts = [
            json!({"delta":"[CUSTOM_0000"}).to_string(),
            json!({"delta":"00000000]"}).to_string(),
        ];
        assert!(unresolved_messages(parts.iter().map(String::as_str)));
        let ordinary_data = json!({"data":"[CUSTOM_000000000000]"}).to_string();
        assert!(unresolved_messages(std::iter::once(ordinary_data.as_str())));
        let opaque = json!({"encrypted_content":"[CUSTOM_000000000000]"}).to_string();
        assert!(unresolved_messages(std::iter::once(opaque.as_str())));
        let mut deeply_encoded = "[CUSTOM_000000000000]".to_owned();
        for _ in 0..8 {
            deeply_encoded = serde_json::to_string(&deeply_encoded).unwrap();
        }
        assert!(unresolved_messages(std::iter::once(
            deeply_encoded.as_str()
        )));
        let mut nested = json!("clean");
        for _ in 0..10 {
            nested = json!({"nested":nested});
        }
        let arguments = json!({"arguments":nested.to_string()}).to_string();
        assert!(!unresolved_messages(std::iter::once(arguments.as_str())));
    }

    #[test]
    fn preserves_separate_stream_fields_and_requires_sse_completion() {
        let parts = [
            json!({"index":0,"delta":"[CUSTOM_0000"}).to_string(),
            json!({"index":1,"delta":"00000000]"}).to_string(),
        ];
        assert!(!unresolved_messages(parts.iter().map(String::as_str)));
        let payloads = sse_payloads(
            "event: message\r\ndata: {\"text\":\r\ndata: \"hello\"}\r\n\r\ndata: [DONE]\r\n\r\n",
        );
        assert_eq!(payloads.len(), 2);
        assert!(serde_json::from_str::<Value>(&payloads[0]).is_ok());
        assert!(stream_terminal(&payloads[1]));
        assert!(!stream_terminal(&payloads[0]));
    }
}
