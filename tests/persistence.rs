use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use gatekeeper::detector::Detector;
use gatekeeper::proxy::{ProxyState, router, upstream_client};
use gatekeeper::storage::MappingStore;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
use tower::ServiceExt;

const ORIGINAL: &str = "SensitiveFixture";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    url: String,
    upstream: tokio::task::JoinHandle<()>,
    seen: Arc<Mutex<String>>,
}

impl Fixture {
    async fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "gatekeeper-persistence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let seen = Arc::new(Mutex::new(String::new()));
        let upstream_app = Router::new()
            .route("/ws", get(websocket_upstream))
            .route("/echo", post(echo))
            .route("/replay", post(replay))
            .route("/stream", post(stream_replay))
            .route("/unknown", post(|| async { Json(json!({"arguments": "[CUSTOM_000000000000]"})) }))
            .route("/unknown-stream", post(|| async {
                ([("content-type", "text/event-stream")], "data: {\"delta\":\"[CUSTOM_0000\"}\n\ndata: {\"delta\":\"00000000]\"}\n\ndata: [DONE]\n\n")
            }))
            .route("/compressed", post(|| async { ([("content-encoding", "gzip")], "uninspectable") }))
            .with_state(Arc::clone(&seen));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let upstream = tokio::spawn(async move {
            axum::serve(listener, upstream_app).await.unwrap();
        });
        Self {
            directory,
            url,
            upstream,
            seen,
        }
    }

    fn app(&self) -> Router {
        self.app_at(&self.directory.join("mappings.sqlite3"))
    }

    fn app_at(&self, path: &Path) -> Router {
        let store = MappingStore::open(path, "owner", &"test".repeat(16), 1_000_000).unwrap();
        router(
            ProxyState::new(
                self.url.parse().unwrap(),
                upstream_client().unwrap(),
                Arc::new(Detector::default().with_redactions(&[ORIGINAL.to_owned()])),
                1_000_000,
                None,
            )
            .with_storage(Arc::new(store)),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.upstream.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

async fn echo(
    State(seen): State<Arc<Mutex<String>>>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Json<Value> {
    assert!(!headers.contains_key("x-gatekeeper-token"));
    assert!(!headers.contains_key("x-gatekeeper-conversation-id"));
    *seen.lock().unwrap() = value["content"].as_str().unwrap().to_owned();
    Json(value)
}

async fn replay(State(seen): State<Arc<Mutex<String>>>) -> Json<Value> {
    Json(json!({"content": seen.lock().unwrap().clone()}))
}

async fn stream_replay(
    State(seen): State<Arc<Mutex<String>>>,
) -> ([(&'static str, &'static str); 1], String) {
    let token = seen.lock().unwrap().clone();
    let middle = token.len() / 2;
    let first = json!({"delta": &token[..middle]});
    let last = json!({"delta": &token[middle..]});
    (
        [("content-type", "text/event-stream")],
        format!("data: {first}\n\ndata: {last}\n\ndata: [DONE]\n\n"),
    )
}

async fn websocket_upstream(
    State(seen): State<Arc<Mutex<String>>>,
    upgrade: WebSocketUpgrade,
) -> axum::response::Response {
    upgrade.on_upgrade(move |mut socket| async move {
        while let Some(Ok(axum::extract::ws::Message::Text(text))) = socket.recv().await {
            let value: Value = serde_json::from_str(&text).unwrap();
            if value["type"] == "session.update" {
                socket
                    .send(axum::extract::ws::Message::Text(
                        json!({"type":"session.updated"}).to_string().into(),
                    ))
                    .await
                    .unwrap();
                continue;
            }
            if let Some(input) = value["input"].as_str() {
                *seen.lock().unwrap() = input.to_owned();
            }
            let token = if value["fixture_unknown"] == true {
                "[CUSTOM_000000000000]".to_owned()
            } else {
                seen.lock().unwrap().clone()
            };
            let middle = token.len() / 2;
            for mut event in [
                json!({"type":"response.output_text.delta", "delta": &token[..middle]}),
                json!({"type":"response.output_text.delta", "delta": &token[middle..]}),
                json!({"type":"response.completed"}),
            ] {
                if let Some(lane) = value.get("stream_id") {
                    event["stream_id"] = lane.clone();
                }
                socket
                    .send(axum::extract::ws::Message::Text(event.to_string().into()))
                    .await
                    .unwrap();
            }
        }
    })
}

async fn websocket_turn(
    fixture: &Fixture,
    conversation: &str,
    input: Value,
    control: bool,
) -> Vec<Value> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut request = format!("ws://{}/ws", listener.local_addr().unwrap())
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("x-gatekeeper-token", "test".repeat(16).parse().unwrap());
    request.headers_mut().insert(
        "x-gatekeeper-conversation-id",
        conversation.parse().unwrap(),
    );
    let app = fixture.app();
    let gateway = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    if control {
        socket
            .send(Message::Text(
                json!({"type":"session.update"}).to_string().into(),
            ))
            .await
            .unwrap();
        let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(message.to_text().unwrap()).unwrap()["type"],
            "session.updated"
        );
    }
    socket
        .send(Message::Text(input.to_string().into()))
        .await
        .unwrap();
    let mut output = Vec::new();
    loop {
        let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let value: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
        let terminal = value["type"] == "error" || value["type"] == "response.completed";
        output.push(value);
        if terminal {
            break;
        }
    }
    let _ = socket.close(None).await;
    gateway.abort();
    output
}

#[tokio::test]
async fn websocket_resume_restores_and_unknown_turns_release_no_deltas() {
    let fixture = Fixture::new().await;
    let first = websocket_turn(
        &fixture,
        "thread",
        json!({"type":"response.create", "input": ORIGINAL}),
        false,
    )
    .await;
    assert!(first.iter().any(|value| value["delta"] == ORIGINAL));
    let resumed = websocket_turn(&fixture, "thread", json!({"type":"response.create"}), true).await;
    assert!(resumed.iter().any(|value| value["delta"] == ORIGINAL));
    let unknown = websocket_turn(
        &fixture,
        "thread",
        json!({"type":"response.create", "fixture_unknown":true}),
        false,
    )
    .await;
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0]["type"], "error");
}

#[tokio::test]
async fn websocket_lanes_keep_separate_restoration_authority() {
    let fixture = Fixture::new().await;
    let first = websocket_turn(
        &fixture,
        "thread",
        json!({"type":"response.create", "stream_id":"first", "input": ORIGINAL}),
        false,
    )
    .await;
    assert!(first.iter().any(|value| value["delta"] == ORIGINAL));
    let resumed = websocket_turn(
        &fixture,
        "thread",
        json!({"type":"response.create", "stream_id":"first"}),
        false,
    )
    .await;
    assert!(resumed.iter().any(|value| value["delta"] == ORIGINAL));
    let other = websocket_turn(
        &fixture,
        "thread",
        json!({"type":"response.create", "stream_id":"second"}),
        false,
    )
    .await;
    assert_eq!(other.len(), 1);
    assert_eq!(other[0]["type"], "error");
    let mut deletion = request("/gatekeeper/conversation", "thread", json!({}));
    *deletion.method_mut() = axum::http::Method::DELETE;
    assert_eq!(
        send(fixture.app(), deletion).await.0,
        StatusCode::NO_CONTENT
    );
    let connection =
        rusqlite::Connection::open(fixture.directory.join("mappings.sqlite3")).unwrap();
    let count: i64 = connection
        .query_row("SELECT count(*) FROM bindings", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

fn request(path: &str, conversation: &str, body: Value) -> Request<Body> {
    Request::post(path)
        .header("content-type", "application/json")
        .header("x-gatekeeper-token", "test".repeat(16))
        .header("x-gatekeeper-conversation-id", conversation)
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn send(app: Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 2_000_000).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn resumed_conversation_restores_after_gateway_restart() {
    let fixture = Fixture::new().await;
    let first = send(
        fixture.app(),
        request("/echo", "yesterday", json!({"content": ORIGINAL})),
    )
    .await;
    assert_eq!(first.0, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&first.1).unwrap()["content"],
        ORIGINAL
    );
    let token = fixture.seen.lock().unwrap().clone();
    assert_ne!(token, ORIGINAL);
    let resumed = send(
        fixture.app(),
        request("/replay", "yesterday", json!({"content": "continue"})),
    )
    .await;
    assert_eq!(resumed.0, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&resumed.1).unwrap()["content"],
        ORIGINAL
    );
    let echoed = send(
        fixture.app(),
        request("/echo", "yesterday", json!({"content": token})),
    )
    .await;
    assert_eq!(echoed.0, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&echoed.1).unwrap()["content"],
        ORIGINAL
    );
}

#[tokio::test]
async fn cross_conversation_replay_is_withheld() {
    let fixture = Fixture::new().await;
    send(
        fixture.app(),
        request("/echo", "first", json!({"content": ORIGINAL})),
    )
    .await;
    let response = send(
        fixture.app(),
        request("/replay", "second", json!({"content": "continue"})),
    )
    .await;
    assert_eq!(response.0, StatusCode::BAD_GATEWAY);
    assert!(!response.1.contains(ORIGINAL));
    assert!(!response.1.contains(&*fixture.seen.lock().unwrap()));
}

#[tokio::test]
async fn authentication_and_conversation_identity_are_required() {
    let fixture = Fixture::new().await;
    let mut missing_auth = request("/echo", "thread", json!({"content": ORIGINAL}));
    missing_auth.headers_mut().remove("x-gatekeeper-token");
    assert_eq!(
        send(fixture.app(), missing_auth).await.0,
        StatusCode::UNAUTHORIZED
    );
    let mut missing_scope = request("/echo", "thread", json!({"content": ORIGINAL}));
    missing_scope
        .headers_mut()
        .remove("x-gatekeeper-conversation-id");
    assert_eq!(
        send(fixture.app(), missing_scope).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut thread_header = request("/echo", "thread", json!({"content": ORIGINAL}));
    thread_header
        .headers_mut()
        .remove("x-gatekeeper-conversation-id");
    thread_header
        .headers_mut()
        .insert("thread-id", "thread".parse().unwrap());
    assert_eq!(send(fixture.app(), thread_header).await.0, StatusCode::OK);
    let mut conflicting = request("/echo", "thread", json!({"content": ORIGINAL}));
    conflicting
        .headers_mut()
        .append("x-gatekeeper-conversation-id", "other".parse().unwrap());
    assert_eq!(
        send(fixture.app(), conflicting).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn conversation_aliases_resume_same_mappings_after_restart() {
    let fixture = Fixture::new().await;
    let mut initial = request("/echo", "Saved.Thread_42", json!({"content": ORIGINAL}));
    initial.headers_mut().remove("x-gatekeeper-conversation-id");
    initial
        .headers_mut()
        .insert("thread-id", "Saved.Thread_42".parse().unwrap());
    initial
        .headers_mut()
        .insert("session_id", "first-session".parse().unwrap());
    assert_eq!(send(fixture.app(), initial).await.0, StatusCode::OK);
    for name in ["thread_id", "x-gatekeeper-conversation-id"] {
        let mut resumed = request("/replay", "Saved.Thread_42", json!({"content": "continue"}));
        resumed.headers_mut().remove("x-gatekeeper-conversation-id");
        resumed
            .headers_mut()
            .insert(name, "Saved.Thread_42".parse().unwrap());
        resumed
            .headers_mut()
            .insert("session_id", "new-session".parse().unwrap());
        let response = send(fixture.app(), resumed).await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<Value>(&response.1).unwrap()["content"],
            ORIGINAL
        );
    }
    let wrong_case = send(
        fixture.app(),
        request("/replay", "saved.thread_42", json!({"content": "continue"})),
    )
    .await;
    assert_eq!(wrong_case.0, StatusCode::BAD_GATEWAY);
    assert!(!wrong_case.1.contains(ORIGINAL));
}

#[tokio::test]
async fn ambiguous_or_transient_identity_never_selects_a_conversation() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    for name in ["thread-id", "thread_id"] {
        let mut conflicting = request("/echo", "first", json!({"content": ORIGINAL}));
        conflicting
            .headers_mut()
            .insert(name, "second".parse().unwrap());
        assert_eq!(
            send(app.clone(), conflicting).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let mut conflicting = request("/echo", "first", json!({"content": ORIGINAL}));
    conflicting
        .headers_mut()
        .remove("x-gatekeeper-conversation-id");
    conflicting
        .headers_mut()
        .insert("thread-id", "first".parse().unwrap());
    conflicting
        .headers_mut()
        .insert("thread_id", "second".parse().unwrap());
    assert_eq!(
        send(app.clone(), conflicting).await.0,
        StatusCode::BAD_REQUEST
    );
    for transient in ["session_id", "session-id", "x-request-id"] {
        let mut missing = request("/echo", "first", json!({"content": ORIGINAL}));
        missing.headers_mut().remove("x-gatekeeper-conversation-id");
        missing
            .headers_mut()
            .insert(transient, "first".parse().unwrap());
        assert_eq!(send(app.clone(), missing).await.0, StatusCode::BAD_REQUEST);
    }
    for invalid in ["", "has spaces", "conversation~lane", &"x".repeat(257)] {
        let malformed = request("/echo", invalid, json!({"content": ORIGINAL}));
        assert_eq!(
            send(app.clone(), malformed).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert!(fixture.seen.lock().unwrap().is_empty());
    let mut matching = request("/echo", "first", json!({"content": ORIGINAL}));
    matching
        .headers_mut()
        .insert("thread-id", "first".parse().unwrap());
    matching
        .headers_mut()
        .insert("thread_id", "first".parse().unwrap());
    assert_eq!(send(app, matching).await.0, StatusCode::OK);
}

#[tokio::test]
async fn old_tokens_restore_across_stream_events() {
    let fixture = Fixture::new().await;
    send(
        fixture.app(),
        request("/echo", "thread", json!({"content": ORIGINAL})),
    )
    .await;
    let response = send(
        fixture.app(),
        request("/stream", "thread", json!({"content": "continue"})),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert!(response.1.contains(ORIGINAL));
    assert!(response.1.contains("[DONE]"));
    assert!(!response.1.contains(&*fixture.seen.lock().unwrap()));
}

#[tokio::test]
async fn unresolved_and_uninspectable_output_is_not_released() {
    let fixture = Fixture::new().await;
    for route in ["/unknown", "/unknown-stream", "/compressed"] {
        let response = send(
            fixture.app(),
            request(route, "thread", json!({"content": "continue"})),
        )
        .await;
        assert_eq!(response.0, StatusCode::BAD_GATEWAY, "{route}");
        assert!(!response.1.contains("[CUSTOM_"));
        assert!(!response.1.contains("data:"));
    }
}

#[tokio::test]
async fn database_write_failure_prevents_upstream_request() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    let connection =
        rusqlite::Connection::open(fixture.directory.join("mappings.sqlite3")).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_mapping BEFORE INSERT ON bindings BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END;").unwrap();
    let response = send(
        app,
        request("/echo", "thread", json!({"content": ORIGINAL})),
    )
    .await;
    assert_eq!(response.0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(fixture.seen.lock().unwrap().is_empty());
    let count: i64 = connection
        .query_row("SELECT count(*) FROM vault_values", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn deleting_one_conversation_preserves_shared_values() {
    let fixture = Fixture::new().await;
    for thread in ["first", "second"] {
        assert_eq!(
            send(
                fixture.app(),
                request("/echo", thread, json!({"content": ORIGINAL}))
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    let mut deletion = request("/gatekeeper/conversation", "first", json!({}));
    *deletion.method_mut() = axum::http::Method::DELETE;
    assert_eq!(
        send(fixture.app(), deletion).await.0,
        StatusCode::NO_CONTENT
    );
    let remaining = send(
        fixture.app(),
        request("/replay", "second", json!({"content": "continue"})),
    )
    .await;
    assert_eq!(remaining.0, StatusCode::OK);
    assert!(remaining.1.contains(ORIGINAL));
    let connection =
        rusqlite::Connection::open(fixture.directory.join("mappings.sqlite3")).unwrap();
    let count: i64 = connection
        .query_row("SELECT count(*) FROM vault_values", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}
