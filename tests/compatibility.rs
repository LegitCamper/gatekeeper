//! Wire contracts against a local upstream; no provider accounts or model downloads.

use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, header};
use axum::routing::any;
use axum::{Json, Router};
use gatekeeper::detector::Detector;
use gatekeeper::proxy::{ProxyState, router, upstream_client};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const CONTACT: &str = "fixture.contact@example.com";
const MEDIA: &str = "AAAA/4155552671/AAAAAAAA";

type Captured = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, task)
}

async fn echo(State(seen): State<Captured>, request: Request<Body>) -> Json<Value> {
    let path = request.uri().to_string();
    let bytes = to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
    seen.lock().unwrap().push((path, bytes.to_vec()));
    Json(serde_json::from_slice(&bytes).unwrap())
}

async fn proxy_to(upstream: &str) -> (String, tokio::task::JoinHandle<()>) {
    serve(router(ProxyState::new(
        upstream.parse().unwrap(),
        upstream_client().unwrap(),
        Arc::new(Detector::default()),
        1024 * 1024,
        None,
    )))
    .await
}

#[tokio::test]
async fn ollama_native_images_survive_while_text_is_redacted() {
    let seen = Captured::default();
    let (upstream, server) = serve(Router::new().fallback(echo).with_state(seen.clone())).await;
    let (gateway, proxy) = proxy_to(&upstream).await;
    let client = upstream_client().unwrap();
    for (path, body, text_path, media_path) in [
        (
            "/api/chat",
            json!({"model": "fixture-model", "messages": [{"role": "user", "content": CONTACT, "images": [MEDIA]}]}),
            "/messages/0/content",
            "/messages/0/images",
        ),
        (
            "/api/generate",
            json!({"model": "fixture-model", "prompt": CONTACT, "images": [MEDIA]}),
            "/prompt",
            "/images",
        ),
    ] {
        let direct: Value = client
            .post(format!("{upstream}{path}"))
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let response = client
            .post(format!("{gateway}{path}"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let actual: Value = response.json().await.unwrap();
        assert_eq!(actual, direct);
        let captured = seen.lock().unwrap();
        let (actual_path, bytes) = captured.last().unwrap();
        let sent: Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(actual_path, path);
        assert_ne!(sent.pointer(text_path), body.pointer(text_path));
        assert_eq!(sent.pointer(media_path), body.pointer(media_path));
    }
    proxy.abort();
    server.abort();
}

#[tokio::test]
async fn binary_audio_response_is_byte_exact_even_with_request_redactions() {
    let expected = Arc::new(Mutex::new(Vec::new()));
    let captured = expected.clone();
    let (upstream, server) = serve(Router::new().fallback(any(move |Json(value): Json<Value>| {
        let captured = captured.clone();
        async move {
            let mut bytes = b"RIFF\xff\x00".to_vec();
            bytes.extend_from_slice(value["input"].as_str().unwrap().as_bytes());
            bytes.extend_from_slice(b"WAVE\x80");
            *captured.lock().unwrap() = bytes.clone();
            Response::builder()
                .header(header::CONTENT_TYPE, "audio/wav")
                .body(Body::from(bytes))
                .unwrap()
        }
    })))
    .await;
    let (gateway, proxy) = proxy_to(&upstream).await;
    let bytes = upstream_client()
        .unwrap()
        .post(format!("{gateway}/v1/audio/speech"))
        .json(&json!({"model": "fixture-speech", "input": CONTACT}))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(bytes.as_ref(), expected.lock().unwrap().as_slice());
    proxy.abort();
    server.abort();
}

#[tokio::test]
async fn multipart_scans_text_without_touching_binary_parts() {
    let seen = Captured::default();
    let captured = seen.clone();
    let (upstream, server) = serve(Router::new().fallback(any(move |request: Request<Body>| {
        let captured = captured.clone();
        async move {
            let kind = request.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .to_owned();
            let bytes = to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
            captured.lock().unwrap().push((kind, bytes.to_vec()));
            Json(json!({"status": "ok"}))
        }
    })))
    .await;
    let (gateway, proxy) = proxy_to(&upstream).await;
    let prefix = format!(
        "--fixture-boundary\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\n{CONTACT}\r\n--fixture-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\nContent-Type: text/plain\r\n\r\n{CONTACT}\r\n--fixture-boundary\r\nContent-Disposition: form-data; name=\"image\"; filename=\"fixture.png\"\r\nContent-Type: image/png\r\n\r\n"
    );
    let binary = b"\x89PNG\x00\xff fixture.contact@example.com --fixture-boundary-inside-binary";
    let mut body = prefix.into_bytes();
    body.extend_from_slice(binary);
    body.extend_from_slice(b"\r\n--fixture-boundary--\r\n");
    let response = upstream_client()
        .unwrap()
        .post(format!("{gateway}/v1/images/edits"))
        .header(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=\"fixture-boundary\"",
        )
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let requests = seen.lock().unwrap();
    let (_, body) = requests.last().unwrap();
    assert!(body.windows(binary.len()).any(|part| part == binary));
    assert_eq!(
        body.windows(CONTACT.len())
            .filter(|part| *part == CONTACT.as_bytes())
            .count(),
        1,
        "only opaque binary media may contain the original"
    );
    drop(requests);
    proxy.abort();
    server.abort();
}

#[tokio::test]
async fn inference_and_tool_contracts_preserve_every_non_text_field() {
    let seen = Captured::default();
    let (upstream, server) = serve(Router::new().fallback(echo).with_state(seen.clone())).await;
    let (gateway, proxy) = proxy_to(&upstream).await;
    let client = upstream_client().unwrap();
    let schema = json!({"type": "object", "properties": {"email": {"type": "string"}}, "required": ["email"], "additionalProperties": false});
    let cases = [
        (
            "/v1/responses",
            json!({"model":"fixture-model", "input":CONTACT, "text":{"format":{"type":"json_schema", "name":"contact_record", "strict":true, "schema":schema}}}),
            "/input",
        ),
        (
            "/v1/responses/compact",
            json!({"model":"fixture-model", "input":[{"role":"user","content":CONTACT},{"type":"reasoning","encrypted_content":"opaque-4155552671","summary":[]}]}),
            "/input/0/content",
        ),
        (
            "/v1/chat/completions",
            json!({"model":"fixture-model", "messages":[{"role":"user", "content":CONTACT}], "response_format":{"type":"json_schema","json_schema":{"name":"contact_record","strict":true,"schema":schema}}}),
            "/messages/0/content",
        ),
        (
            "/v1/embeddings",
            json!({"model":"fixture-embedding","input":CONTACT,"encoding_format":"base64","dimensions":256}),
            "/input",
        ),
        (
            "/api/embed",
            json!({"model":"fixture-embedding","input":[CONTACT],"truncate":false}),
            "/input/0",
        ),
        (
            "/v1/audio/speech",
            json!({"model":"fixture-speech","input":CONTACT,"voice":"fixture-voice","response_format":"wav"}),
            "/input",
        ),
        (
            "/v1/images/generations",
            json!({"model":"fixture-image","prompt":CONTACT,"size":"1024x1024","n":1}),
            "/prompt",
        ),
        (
            "/v1/responses",
            json!({"model":"fixture-model", "input":[{"type":"function_call","call_id":"call_fixture","name":"lookup_contact","arguments":"{}"},{"type":"function_call_output","call_id":"call_fixture","output":CONTACT}], "tools":[{"type":"function","name":"lookup_contact","parameters":schema}],"parallel_tool_calls":true}),
            "/input/1/output",
        ),
        (
            "/v1/responses",
            json!({"model":"fixture-model", "input":[{"type":"custom_tool_call","call_id":"call_fixture","name":"apply_patch","input":CONTACT}],"tools":[{"type":"custom","name":"apply_patch","format":{"type":"text"}}]}),
            "/input/0/input",
        ),
        (
            "/v1/responses",
            json!({"model":"fixture-model", "input":[{"type":"mcp_call","id":"mcp_fixture","server_label":"fixture_server","name":"lookup_contact","arguments":"{}","output":CONTACT}]}),
            "/input/0/output",
        ),
        (
            "/api/chat",
            json!({"model":"fixture-model", "messages":[{"role":"tool","tool_name":"lookup_contact","content":CONTACT}], "tools":[{"type":"function","function":{"name":"lookup_contact","parameters":schema}}],"format":schema}),
            "/messages/0/content",
        ),
    ];
    for (path, body, text_path) in cases {
        let direct: Value = client
            .post(format!("{upstream}{path}"))
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let response = client
            .post(format!("{gateway}{path}"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.json::<Value>().await.unwrap(), direct, "{path}");
        let captured = seen.lock().unwrap();
        let mut sent: Value = serde_json::from_slice(&captured.last().unwrap().1).unwrap();
        assert_ne!(sent.pointer(text_path), body.pointer(text_path), "{path}");
        *sent.pointer_mut(text_path).unwrap() = body.pointer(text_path).unwrap().clone();
        assert_eq!(sent, body, "only intended text may change: {path}");
    }
    proxy.abort();
    server.abort();
}

#[tokio::test]
async fn discovery_errors_queries_and_status_codes_survive() {
    let (upstream, server) = serve(Router::new().fallback(any(
        |request: Request<Body>| async move {
            let status = if request.uri().path().ends_with("missing") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::OK
            };
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-request-id", "fixture-request")
                .body(Body::from(
                    json!({"path":request.uri().to_string(),"method":request.method().as_str()})
                        .to_string(),
                ))
                .unwrap()
        },
    )))
    .await;
    let (gateway, proxy) = proxy_to(&upstream).await;
    let client = upstream_client().unwrap();
    for path in [
        "/v1/models",
        "/v1/models/missing",
        "/v1/responses/resp_fixture?include=output",
        "/v1/files?limit=2",
        "/api/tags",
        "/api/ps",
        "/api/version",
    ] {
        let direct = client
            .get(format!("{upstream}{path}"))
            .send()
            .await
            .unwrap();
        let actual = client
            .get(format!("{gateway}{path}"))
            .header(header::CONTENT_TYPE, "application/json")
            .send()
            .await
            .unwrap();
        assert_eq!(actual.status(), direct.status());
        assert_eq!(actual.headers()["x-request-id"], "fixture-request");
        assert_eq!(actual.bytes().await.unwrap(), direct.bytes().await.unwrap());
    }
    proxy.abort();
    server.abort();
}

#[tokio::test]
async fn protected_reads_remain_withheld_across_responses_tool_shapes() {
    let seen = Captured::default();
    let (upstream, server) = serve(Router::new().fallback(echo).with_state(seen.clone())).await;
    let (gateway, proxy) = proxy_to(&upstream).await;
    let client = upstream_client().unwrap();
    for input in [
        json!([{"type":"function_call","id":"fc_fixture","call_id":"call_fixture","name":"read_file","arguments":"{\"path\":\".env\"}"},{"type":"function_call_output","call_id":"call_fixture","output":"DO_NOT_FORWARD_FIXTURE"}]),
        json!([{"type":"custom_tool_call","id":"ctc_fixture","call_id":"call_fixture","name":"read_file","input":"cat .env"},{"type":"custom_tool_call_output","call_id":"call_fixture","output":"DO_NOT_FORWARD_FIXTURE"}]),
        json!([{"type":"shell_call","id":"sc_fixture","call_id":"call_fixture","action":{"commands":["cat .env"]}},{"type":"shell_call_output","call_id":"call_fixture","output":[{"stdout":"DO_NOT_FORWARD_FIXTURE","stderr":"DO_NOT_FORWARD_FIXTURE","outcome":{"type":"exit","exit_code":0}}]}]),
        json!([{"type":"mcp_call","id":"mcp_fixture","server_label":"local_files","name":"read_file","arguments":"{\"path\":\".env\"}","output":"DO_NOT_FORWARD_FIXTURE"}]),
    ] {
        let response = client
            .post(format!("{gateway}/v1/responses"))
            .json(&json!({"input":input}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let captured = seen.lock().unwrap();
        let body = std::str::from_utf8(&captured.last().unwrap().1).unwrap();
        assert!(!body.contains("DO_NOT_FORWARD_FIXTURE"), "{body}");
        assert!(body.contains("gatekeeper withheld"));
        let value: Value = serde_json::from_str(body).unwrap();
        if input[0]["type"] == "shell_call" {
            assert!(value["input"][1]["output"].is_array());
            assert_eq!(
                value["input"][1]["output"][0]["outcome"],
                input[1]["output"][0]["outcome"]
            );
        }
    }
    proxy.abort();
    server.abort();
}

#[tokio::test]
async fn multipart_jsonl_upload_preserves_media_and_rejects_malformed_parts() {
    let seen = Captured::default();
    let captured = seen.clone();
    let (upstream, server) = serve(Router::new().fallback(any(move |request: Request<Body>| {
        let captured = captured.clone();
        async move {
            let bytes = to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
            captured
                .lock()
                .unwrap()
                .push((String::new(), bytes.to_vec()));
            Json(json!({"id":"file_fixture"}))
        }
    })))
    .await;
    let (gateway, proxy) = proxy_to(&upstream).await;
    let client = upstream_client().unwrap();
    let line =
        json!({"input":CONTACT,"image_url":format!("data:image/png;base64,{MEDIA}")}).to_string();
    let body = format!(
        "--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"batch.jsonl\"\r\nContent-Type: application/octet-stream\r\n\r\n{line}\n{line}\n\r\n--fixture--\r\n"
    );
    let response = client
        .post(format!("{gateway}/v1/files"))
        .header(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=fixture",
        )
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    {
        let captured = seen.lock().unwrap();
        let sent = std::str::from_utf8(&captured.last().unwrap().1).unwrap();
        assert!(!sent.contains(CONTACT));
        assert_eq!(sent.matches(MEDIA).count(), 2);
    }
    for (kind, body) in [
        ("multipart/form-data", "missing boundary".to_owned()),
        ("multipart/form-data; boundary=fixture", "--fixture\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\ntruncated".to_owned()),
        ("multipart/form-data; boundary=fixture", "--fixture\r\nContent-Disposition: form-data; name=\"prompt\"\r\nContent-Transfer-Encoding: base64\r\n\r\nYWJj\r\n--fixture--\r\n".to_owned()),
    ] {
        assert_eq!(client.post(format!("{gateway}/v1/files")).header(header::CONTENT_TYPE,kind).body(body).send().await.unwrap().status(),StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "malformed uploads must never reach upstream"
    );
    proxy.abort();
    server.abort();
}
