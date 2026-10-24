use std::sync::Arc;

use axum::Router;
use axum::extract::WebSocketUpgrade;
use axum::extract::ws::Message;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use gatekeeper::detector::Detector;
use gatekeeper::proxy::{ProxyState, router, upstream_client};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::{Message as Frame, client::IntoClientRequest};

async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, task)
}

#[tokio::test]
async fn websocket_turns_restore_split_tokens_and_keep_auth_protocol_and_binary() {
    let app = Router::new().route("/base/v1/responses", get(|headers: HeaderMap, ws: WebSocketUpgrade| async move {
        assert_eq!(headers["authorization"], "Bearer fixture-upstream");
        assert!(!headers.contains_key("x-api-key"));
        ws.protocols(["fixture-protocol"]).on_upgrade(|mut socket| async move {
            let mut previous = None;
            for _ in 0..2 {
                let Message::Text(text) = socket.recv().await.unwrap().unwrap() else { panic!("JSON frame") };
                let value: Value = serde_json::from_str(&text).unwrap();
                let token = value["input"].as_str().unwrap();
                assert!(!token.contains('@'), "PII reached upstream");
                if let Some(previous) = previous {
                    socket.send(Message::Text(json!({"type": "response.output_text.delta", "delta": previous}).to_string().into())).await.unwrap();
                }
                let split = token.len() / 2;
                for delta in [&token[..split], &token[split..]] {
                    socket.send(Message::Text(json!({"type": "response.output_text.delta", "delta": delta}).to_string().into())).await.unwrap();
                }
                socket.send(Message::Binary(vec![0xff, 0, 42].into())).await.unwrap();
                socket.send(Message::Text(json!({"type": "response.completed", "response": {"output": []}}).to_string().into())).await.unwrap();
                previous = Some(token.to_owned());
            }
        })
    }));
    let (upstream, server) = serve(app).await;
    let (gateway, proxy) = serve(router(ProxyState::new(
        format!("{upstream}/base").parse().unwrap(),
        upstream_client().unwrap(),
        Arc::new(Detector::default()),
        1024 * 1024,
        Some((
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer fixture-upstream"),
        )),
    )))
    .await;
    let mut request = format!("{}/v1/responses", gateway.replace("http:", "ws:"))
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_static("Bearer stale-client"),
    );
    request
        .headers_mut()
        .insert("x-api-key", HeaderValue::from_static("stale-client"));
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static("fixture-protocol"),
    );
    let (mut socket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(
        response.headers()["sec-websocket-protocol"],
        "fixture-protocol"
    );
    for (index, contact) in ["first@example.com", "second@example.com"]
        .iter()
        .enumerate()
    {
        socket
            .send(Frame::Text(
                json!({"type": "response.create", "input": contact})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        let mut output = String::new();
        let mut binary_seen = false;
        loop {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            match frame {
                Frame::Text(text) => {
                    let value: Value = serde_json::from_str(&text).unwrap();
                    if value["type"] == "response.completed" {
                        break;
                    }
                    output.push_str(value["delta"].as_str().unwrap());
                }
                Frame::Binary(bytes) => {
                    assert_eq!(bytes.as_ref(), &[0xff, 0, 42]);
                    binary_seen = true;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(binary_seen);
        assert!(output.ends_with(contact));
        if index == 1 {
            assert!(!output.contains("first@example.com"));
            assert!(output.starts_with("[EMAIL_"));
        }
    }
    proxy.abort();
    server.abort();
}

#[tokio::test]
async fn websocket_parallel_lanes_do_not_share_plaintext_mappings() {
    let (upstream, server) = serve(Router::new().fallback(get(|ws: WebSocketUpgrade| async {
        ws.on_upgrade(|mut socket| async move {
            let mut inputs = Vec::new();
            for _ in 0..2 {
                let Message::Text(text) = socket.recv().await.unwrap().unwrap() else { panic!("text") };
                inputs.push(serde_json::from_str::<Value>(&text).unwrap());
            }
            assert_eq!(inputs[0]["stream_id"], "contact");
            assert_eq!(inputs[1]["stream_id"], "lane-4155552671");
            for i in 0..2 {
                let token = inputs[i]["input"].as_str().unwrap();
                let other = inputs[1-i]["input"].as_str().unwrap();
                assert!(!token.contains('@'));
                socket.send(Message::Text(json!({"type":"response.output_text.delta", "stream_id":inputs[i]["stream_id"], "delta":other}).to_string().into())).await.unwrap();
            }
            for half in 0..2 {
                for input in &inputs {
                    let token = input["input"].as_str().unwrap();
                    let split = token.len()/2;
                    let delta = if half == 0 { &token[..split] } else { &token[split..] };
                    socket.send(Message::Text(json!({"type":"response.output_text.delta", "stream_id":input["stream_id"], "delta":delta}).to_string().into())).await.unwrap();
                }
            }
            for input in inputs {
                socket.send(Message::Text(json!({"type":"response.completed", "stream_id":input["stream_id"]}).to_string().into())).await.unwrap();
            }
        })
    }))).await;
    let (gateway, proxy) = serve(router(ProxyState::new(
        upstream.parse().unwrap(),
        upstream_client().unwrap(),
        Arc::new(Detector::default()),
        4096,
        None,
    )))
    .await;
    let (mut socket, _) = tokio_tungstenite::connect_async(gateway.replace("http:", "ws:"))
        .await
        .unwrap();
    let cases = [
        ("contact", "first@example.com"),
        ("lane-4155552671", "second@example.com"),
    ];
    for (lane, input) in cases {
        socket
            .send(Frame::Text(
                json!({"type":"response.create", "stream_id":lane, "input":input})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
    }
    let mut completed = 0;
    let mut outputs = std::collections::HashMap::<String, String>::new();
    while completed < 2 {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Frame::Text(text) = frame else {
            panic!("text")
        };
        let value: Value = serde_json::from_str(&text).unwrap();
        if value["type"] == "response.completed" {
            completed += 1;
            continue;
        }
        outputs
            .entry(value["stream_id"].as_str().unwrap().to_owned())
            .or_default()
            .push_str(value["delta"].as_str().unwrap());
    }
    for (index, (lane, contact)) in cases.iter().enumerate() {
        assert!(outputs[*lane].ends_with(contact), "{outputs:?}");
        assert!(outputs[*lane].starts_with("[EMAIL_"));
        assert!(!outputs[*lane].contains(cases[1 - index].1));
    }
    proxy.abort();
    server.abort();
}

#[tokio::test]
async fn websocket_rejects_invalid_input_and_flushes_pending_text_on_close() {
    let (upstream, server) = serve(Router::new().fallback(get(|ws: WebSocketUpgrade| async {
        ws.on_upgrade(|mut socket| async move {
            let Message::Binary(bytes) = socket.recv().await.unwrap().unwrap() else {
                panic!("binary JSON")
            };
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert!(!value["input"].as_str().unwrap().contains('@'));
            socket
                .send(Message::Text(
                    json!({"type":"response.output_text.delta","delta":"[EMAIL_"})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
            socket
                .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: 1000,
                    reason: "fixture done".into(),
                })))
                .await
                .unwrap();
        })
    })))
    .await;
    let (gateway, proxy) = serve(router(ProxyState::new(
        upstream.parse().unwrap(),
        upstream_client().unwrap(),
        Arc::new(Detector::default()),
        4096,
        None,
    )))
    .await;
    let (mut socket, _) = tokio_tungstenite::connect_async(gateway.replace("http:", "ws:"))
        .await
        .unwrap();
    socket.send(Frame::Text("not JSON".into())).await.unwrap();
    let error = socket.next().await.unwrap().unwrap();
    let error: Value = serde_json::from_str(error.to_text().unwrap()).unwrap();
    assert_eq!(error["type"], "error");
    socket
        .send(Frame::Ping(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap(),
        Frame::Pong(vec![1, 2, 3].into())
    );
    socket
        .send(Frame::Binary(
            json!({"type":"response.create","input":"fixture@example.com"})
                .to_string()
                .into_bytes()
                .into(),
        ))
        .await
        .unwrap();
    let delta = socket.next().await.unwrap().unwrap();
    let delta: Value = serde_json::from_str(delta.to_text().unwrap()).unwrap();
    assert_eq!(delta["delta"], "[EMAIL_");
    let Frame::Close(Some(close)) = socket.next().await.unwrap().unwrap() else {
        panic!("close")
    };
    assert_eq!(
        close.code,
        tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal
    );
    assert_eq!(close.reason, "fixture done");
    proxy.abort();
    server.abort();
}

#[tokio::test]
async fn websocket_upstream_handshake_errors_are_returned_as_http_errors() {
    let (upstream, server) = serve(Router::new().fallback(|| async {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            [("x-request-id", "fixture-denied")],
            "denied",
        )
    }))
    .await;
    let (gateway, proxy) = serve(router(ProxyState::new(
        upstream.parse().unwrap(),
        upstream_client().unwrap(),
        Arc::new(Detector::default()),
        4096,
        None,
    )))
    .await;
    let error = tokio_tungstenite::connect_async(gateway.replace("http:", "ws:"))
        .await
        .unwrap_err();
    let tokio_tungstenite::tungstenite::Error::Http(response) = error else {
        panic!("HTTP rejection")
    };
    assert_eq!(response.status(), 401);
    assert_eq!(response.headers()["x-request-id"], "fixture-denied");
    proxy.abort();
    server.abort();
}

#[tokio::test]
#[ignore = "requires GATEKEEPER_TEST_UPSTREAM and GATEKEEPER_TEST_MODELS"]
async fn live_websocket_direct_and_proxied() {
    let upstream =
        std::env::var("GATEKEEPER_TEST_UPSTREAM").expect("set generic upstream base URL");
    let models = std::env::var("GATEKEEPER_TEST_MODELS").expect("set comma-separated model IDs");
    let auth = std::env::var("GATEKEEPER_TEST_API_KEY")
        .ok()
        .filter(|key| !key.is_empty())
        .map(|key| {
            let name = std::env::var("GATEKEEPER_TEST_AUTH_HEADER")
                .unwrap_or_else(|_| "authorization".into());
            let value = if name.eq_ignore_ascii_case("authorization") {
                format!("Bearer {key}")
            } else {
                key
            };
            let mut value = HeaderValue::from_str(&value).unwrap();
            value.set_sensitive(true);
            (HeaderName::from_bytes(name.as_bytes()).unwrap(), value)
        });
    let (gateway, proxy) = serve(router(ProxyState::new(
        upstream.parse().unwrap(),
        upstream_client().unwrap(),
        Arc::new(Detector::default()),
        1024 * 1024,
        auth.clone(),
    )))
    .await;
    for model in models.split(',') {
        assert!(!model.is_empty());
        for (label, base) in [("direct", upstream.as_str()), ("proxy", gateway.as_str())] {
            let url =
                format!("{}/v1/responses", base.trim_end_matches('/')).replacen("http", "ws", 1);
            let mut request = url.into_client_request().unwrap();
            if let Some((name, value)) = &auth {
                request.headers_mut().insert(name, value.clone());
            }
            let connected = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio_tungstenite::connect_async(request),
            )
            .await
            .expect("handshake timed out");
            // An HTTP-only gateway answers the upgrade with 404/405/501; that is a
            // missing upstream route, not a proxy defect, so the row is skipped.
            if let Err(tokio_tungstenite::tungstenite::Error::Http(response)) = &connected
                && matches!(response.status().as_u16(), 404 | 405 | 426 | 501)
            {
                eprintln!(
                    "skipping {label} {model}: upstream has no WebSocket route ({})",
                    response.status()
                );
                continue;
            }
            let (mut socket, _) = connected.expect("WebSocket handshake failed");
            socket.send(Frame::Text(json!({"type":"response.create","model":model,"input":[{"role":"user","content":"Reply exactly with fixture.contact@example.com"}]}).to_string().into())).await.unwrap();
            let text = tokio::time::timeout(std::time::Duration::from_secs(90), async {
                let mut text = String::new();
                loop {
                    let frame = socket.next().await.expect("stream ended early").unwrap();
                    if let Frame::Text(raw) = frame {
                        let value: Value = serde_json::from_str(&raw).unwrap();
                        match value["type"].as_str() {
                            Some("response.output_text.delta") => {
                                text.push_str(value["delta"].as_str().unwrap())
                            }
                            Some("response.completed") => break,
                            Some("error" | "response.failed" | "response.incomplete") => {
                                panic!("{label}: provider failed WebSocket turn")
                            }
                            _ => {}
                        }
                    }
                }
                text
            })
            .await
            .expect("response timed out");
            assert!(
                text.contains("fixture.contact@example.com"),
                "{label}: expected original contact"
            );
            socket.close(None).await.unwrap();
            println!("PASS {label} WebSocket {model}");
        }
    }
    proxy.abort();
}
