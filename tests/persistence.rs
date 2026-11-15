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
            .route("/unknown", post(|| async { Json(json!({"content": "[NAME_000000000000]"})) }))
            .route("/unknown-stream", post(|| async {
                ([("content-type", "text/event-stream")], "data: {\"delta\":\"[NAME_0000\"}\n\ndata: {\"delta\":\"00000000]\"}\n\ndata: [DONE]\n\n")
            }))
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
        let store = MappingStore::open(path).unwrap();
        router(
            ProxyState::new(
                self.url.parse().unwrap(),
                upstream_client().unwrap(),
                Arc::new(Detector::default().with_redactions(&[ORIGINAL.to_owned()])),
                1_000_000,
                None,
            )
            .with_storage(Arc::new(store))
            .with_client_token(&"test".repeat(16)),
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

async fn websocket_turn(fixture: &Fixture, input: Value, control: bool) -> Vec<Value> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut request = format!("ws://{}/ws", listener.local_addr().unwrap())
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("x-gatekeeper-token", "test".repeat(16).parse().unwrap());
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

fn request(path: &str, body: Value) -> Request<Body> {
    Request::post(path)
        .header("content-type", "application/json")
        .header("x-gatekeeper-token", "test".repeat(16))
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
async fn tokens_restore_across_sessions_restarts_and_streams() {
    let fixture = Fixture::new().await;
    let first = send(
        fixture.app(),
        request("/echo", json!({"content": ORIGINAL})),
    )
    .await;
    assert_eq!(first.0, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&first.1).unwrap()["content"],
        ORIGINAL
    );
    let token = fixture.seen.lock().unwrap().clone();
    assert_ne!(token, ORIGINAL);
    // A fresh app is a restart; no session header links the two requests.
    let replayed = send(
        fixture.app(),
        request("/replay", json!({"content": "continue"})),
    )
    .await;
    assert_eq!(
        serde_json::from_str::<Value>(&replayed.1).unwrap()["content"],
        ORIGINAL
    );
    let streamed = send(
        fixture.app(),
        request("/stream", json!({"content": "continue"})),
    )
    .await;
    assert!(streamed.1.contains(ORIGINAL) && streamed.1.contains("[DONE]"));
    assert!(!streamed.1.contains(&token));
    // The same value maps to the same token every time: one row on disk.
    send(
        fixture.app(),
        request("/echo", json!({"content": ORIGINAL})),
    )
    .await;
    assert_eq!(*fixture.seen.lock().unwrap(), token);
    let connection =
        rusqlite::Connection::open(fixture.directory.join("mappings.sqlite3")).unwrap();
    let rows: i64 = connection
        .query_row("SELECT count(*) FROM mappings", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1);
}

#[tokio::test]
async fn unknown_placeholders_get_stable_decoys_without_disk_writes() {
    let fixture = Fixture::new().await;
    let mut seen = Vec::new();
    for route in ["/unknown", "/unknown", "/unknown-stream"] {
        let response = send(
            fixture.app(),
            request(route, json!({"content": "continue"})),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK, "{route}");
        assert!(!response.1.contains("NAME_"), "{route}: {}", response.1);
        seen.push(response.1);
    }
    assert_eq!(seen[0], seen[1]);
    let decoy = serde_json::from_str::<Value>(&seen[0]).unwrap()["content"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(decoy.contains(' '), "{decoy}");
    assert!(seen[2].contains(&decoy[..decoy.len() / 2]), "{}", seen[2]);
    let connection =
        rusqlite::Connection::open(fixture.directory.join("mappings.sqlite3")).unwrap();
    let rows: i64 = connection
        .query_row("SELECT count(*) FROM mappings", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0);
    // A placeholder-shaped literal the client sent echoes back verbatim.
    let literal = send(
        fixture.app(),
        request("/echo", json!({"content": "fixture [NAME_000000000000]"})),
    )
    .await;
    assert!(literal.1.contains("[NAME_000000000000]"), "{}", literal.1);
}

#[tokio::test]
async fn opt_in_token_is_required_and_stripped() {
    let fixture = Fixture::new().await;
    let mut missing = request("/echo", json!({"content": ORIGINAL}));
    missing.headers_mut().remove("x-gatekeeper-token");
    assert_eq!(
        send(fixture.app(), missing).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert!(fixture.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn database_write_failure_prevents_upstream_request() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    let connection =
        rusqlite::Connection::open(fixture.directory.join("mappings.sqlite3")).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_mapping BEFORE INSERT ON mappings BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END;").unwrap();
    let response = send(app, request("/echo", json!({"content": ORIGINAL}))).await;
    assert_eq!(response.0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(fixture.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn websocket_turns_share_the_global_table() {
    let fixture = Fixture::new().await;
    let first = websocket_turn(
        &fixture,
        json!({"type":"response.create", "stream_id":"first", "input": ORIGINAL}),
        false,
    )
    .await;
    assert!(first.iter().any(|value| value["delta"] == ORIGINAL));
    let other = websocket_turn(
        &fixture,
        json!({"type":"response.create", "stream_id":"second"}),
        true,
    )
    .await;
    assert!(other.iter().any(|value| value["delta"] == ORIGINAL));
}
