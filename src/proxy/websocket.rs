use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use axum::extract::{FromRequestParts, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest, protocol::WebSocketConfig};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::*;

type Upstream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type Frame = tungstenite::Message;
const MAX_QUEUED_TURNS: usize = 64;

pub(super) async fn proxy(state: ProxyState, request: Request<Body>) -> Response<Body> {
    let target = match target_url(&state.target_url, request.uri()) {
        Ok(mut url) => {
            let scheme = match url.scheme() {
                "https" | "wss" => "wss",
                "http" | "ws" => "ws",
                _ => return json_error(StatusCode::BAD_GATEWAY, "invalid WebSocket upstream URL"),
            };
            if url.set_scheme(scheme).is_err() {
                return json_error(StatusCode::BAD_GATEWAY, "invalid WebSocket upstream URL");
            }
            url
        }
        Err(_) => return json_error(StatusCode::BAD_GATEWAY, "invalid WebSocket upstream URL"),
    };
    let (mut parts, _) = request.into_parts();
    let upgrade = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(upgrade) => upgrade,
        Err(error) => return error.into_response(),
    };
    let mut upstream_request = match target.as_str().into_client_request() {
        Ok(request) => request,
        Err(_) => return json_error(StatusCode::BAD_GATEWAY, "invalid WebSocket handshake"),
    };
    let connections = connection_headers(&parts.headers);
    for (name, value) in &parts.headers {
        let websocket_header = name.as_str().starts_with("sec-websocket-")
            && name.as_str() != "sec-websocket-protocol";
        if !filtered_header(name, &connections)
            && !websocket_header
            && name != header::ACCEPT_ENCODING
            && !(state.upstream_auth.is_some() && is_auth_header(name))
        {
            upstream_request.headers_mut().append(name, value.clone());
        }
    }
    if let Some((name, value)) = &state.upstream_auth {
        upstream_request.headers_mut().insert(name, value.clone());
    }
    let config = WebSocketConfig::default()
        .max_message_size(Some(state.max_body_bytes))
        .max_frame_size(Some(state.max_body_bytes));
    let connected = tokio::time::timeout(
        Duration::from_secs(30),
        tokio_tungstenite::connect_async_with_config(upstream_request, Some(config), false),
    )
    .await;
    let (upstream, handshake) = match connected {
        Ok(Ok(connection)) => connection,
        Ok(Err(tungstenite::Error::Http(response))) => {
            let (parts, _) = response.into_parts();
            // The retained handshake body may be partial or still encoded.
            let mut result = json_error(parts.status, "WebSocket upstream rejected handshake");
            let connections = connection_headers(&parts.headers);
            for (name, value) in &parts.headers {
                if !filtered_header(name, &connections)
                    && name != header::CONTENT_TYPE
                    && name != header::CONTENT_ENCODING
                    && name != header::CONTENT_LENGTH
                {
                    result.headers_mut().append(name, value.clone());
                }
            }
            return result;
        }
        _ => {
            return json_error(
                StatusCode::BAD_GATEWAY,
                "WebSocket upstream handshake failed",
            );
        }
    };
    let selected = handshake
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    upgrade
        .protocols(selected)
        .max_message_size(state.max_body_bytes)
        .max_frame_size(state.max_body_bytes)
        .on_upgrade(move |client| bridge(client, upstream, state))
}

struct Turn {
    restorer: Restorer,
    pending: StreamCarry,
    buffered: Vec<(String, String, bool)>,
    bytes: usize,
    request_bytes: usize,
}

impl Turn {
    fn flush(&mut self) -> Vec<(String, bool)> {
        self.pending = StreamCarry::default();
        self.bytes = 0;
        self.buffered
            .drain(..)
            .map(|(raw, _, binary)| (restore_stream_line_complete(&raw, &self.restorer), binary))
            .collect()
    }

    fn restore(
        &mut self,
        raw: &str,
        terminal: bool,
        limit: usize,
        binary: bool,
    ) -> Vec<(String, bool)> {
        let restored = restore_stream_json(raw, &mut self.pending, &self.restorer)
            .unwrap_or_else(|| self.restorer.restore(raw));
        if self.buffered.is_empty() && !self.pending.has_unresolved_fields() {
            return vec![(restored, binary)];
        }
        self.bytes += raw.len();
        self.buffered.push((raw.to_owned(), restored, binary));
        if !self.pending.has_unresolved_fields() {
            self.bytes = 0;
            return self
                .buffered
                .drain(..)
                .map(|(_, restored, binary)| (restored, binary))
                .collect();
        }
        if terminal || self.bytes > limit {
            return self.flush();
        }
        Vec::new()
    }
}

fn lane(value: &Value) -> Result<String, &'static str> {
    match value.get("stream_id") {
        None => Ok(String::new()),
        Some(Value::String(id))
            if !id.is_empty()
                && id.len() <= 256
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)) =>
        {
            Ok(id.clone())
        }
        _ => Err("invalid stream_id"),
    }
}

async fn error(client: &mut WebSocket, message: &str) -> bool {
    client
        .send(Message::Text(
            json!({"type": "error", "error": {
                "type": "gateway_error", "message": message
            }})
            .to_string()
            .into(),
        ))
        .await
        .is_ok()
}

async fn bridge(mut client: WebSocket, mut upstream: Upstream, state: ProxyState) {
    let mut lanes: HashMap<String, VecDeque<Turn>> = HashMap::new();
    let mut closing = Some(CloseFrame {
        code: 1011,
        reason: "WebSocket connection ended".into(),
    });
    loop {
        tokio::select! {
            frame = client.recv() => {
                let Some(Ok(frame)) = frame else { break; };
                // JSON must be inspected even when carried in a binary frame.
                let binary_json = matches!(&frame, Message::Binary(bytes) if serde_json::from_slice::<Value>(bytes).is_ok());
                let frame = match frame {
                    Message::Binary(bytes) if binary_json => Message::Text(String::from_utf8_lossy(&bytes).into_owned().into()),
                    frame => frame,
                };
                let frame = match frame {
                    Message::Text(text) => {
                        let Ok(mut value) = serde_json::from_str::<Value>(&text) else {
                            if !error(&mut client, "WebSocket text messages must contain JSON").await { break; }
                            continue;
                        };
                        let stream_id = match lane(&value) {
                            Ok(id) => id,
                            Err(reason) => { if !error(&mut client, reason).await { break; } continue; }
                        };
                        let starts_turn = value["type"] == "response.create";
                        let mut redactions = state.detector.request_redactions();
                        if let Some(object) = value.as_object_mut() { object.remove("stream_id"); }
                        anonymize_request_value(&mut value, &mut redactions);
                        // Lane names are routing metadata, never model text.
                        if !stream_id.is_empty() { value["stream_id"] = json!(stream_id); }
                        if starts_turn {
                            let turns = lanes.values().map(VecDeque::len).sum::<usize>();
                            let bytes = lanes.values().flatten().map(|turn| turn.request_bytes).sum::<usize>();
                            if turns >= MAX_QUEUED_TURNS || bytes.saturating_add(text.len()) > state.max_body_bytes {
                                if !error(&mut client, "WebSocket pending turn limit exceeded").await { break; }
                                continue;
                            }
                            lanes.entry(stream_id).or_default().push_back(Turn {
                                restorer: redactions.finish(), pending: StreamCarry::default(),
                                buffered: Vec::new(), bytes: 0, request_bytes: text.len(),
                            });
                        } else if redactions.len() > 0 {
                            // No response identity exists for arbitrary control events.
                            if !error(&mut client, "PII-bearing WebSocket input must use response.create").await { break; }
                            continue;
                        }
                        if binary_json { Frame::Binary(value.to_string().into_bytes().into()) }
                        else { Frame::Text(value.to_string().into()) }
                    }
                    Message::Binary(bytes) => Frame::Binary(bytes),
                    Message::Ping(bytes) => { if client.send(Message::Pong(bytes)).await.is_err() { break; } continue; }
                    Message::Pong(_) => continue,
                    Message::Close(frame) => {
                        let frame = frame.map(|frame| tungstenite::protocol::CloseFrame {
                            code: frame.code.into(), reason: frame.reason.to_string().into(),
                        });
                        let _ = upstream.send(Frame::Close(frame)).await;
                        return;
                    }
                };
                if upstream.send(frame).await.is_err() { break; }
            }
            frame = upstream.next() => {
                let Some(Ok(frame)) = frame else { break; };
                let binary_json = matches!(&frame, Frame::Binary(bytes) if serde_json::from_slice::<Value>(bytes).is_ok());
                let frame = match frame {
                    Frame::Binary(bytes) if binary_json => Frame::Text(String::from_utf8_lossy(&bytes).into_owned().into()),
                    frame => frame,
                };
                match frame {
                    Frame::Text(text) => {
                        let value = serde_json::from_str::<Value>(&text).ok();
                        let stream_id = value.as_ref().and_then(|v| lane(v).ok());
                        let terminal = value.as_ref().and_then(|v| v["type"].as_str()).is_some_and(|kind| {
                            matches!(kind, "response.completed" | "response.failed" | "response.incomplete" | "response.cancelled" | "response.done" | "error")
                        });
                        let buffered_bytes = lanes.values().flatten().map(|turn| turn.bytes).sum::<usize>();
                        let messages = if let Some(turn) = stream_id.as_ref()
                            .and_then(|id| lanes.get_mut(id)).and_then(|queue| queue.front_mut()) {
                            turn.restore(&text, terminal, state.max_body_bytes.saturating_sub(buffered_bytes), binary_json)
                        } else { vec![(text.to_string(), binary_json)] };
                        for (message, binary) in messages {
                            let message = if binary { Message::Binary(message.into_bytes().into()) } else { Message::Text(message.into()) };
                            if client.send(message).await.is_err() { return; }
                        }
                        if terminal && let Some(id) = stream_id && let Some(queue) = lanes.get_mut(&id) {
                            queue.pop_front();
                            if queue.is_empty() { lanes.remove(&id); }
                        }
                    }
                    Frame::Binary(bytes) => { if client.send(Message::Binary(bytes)).await.is_err() { break; } }
                    Frame::Ping(bytes) => { if upstream.send(Frame::Pong(bytes)).await.is_err() { break; } }
                    Frame::Pong(_) => {}
                    Frame::Close(frame) => {
                        closing = frame.map(|frame| CloseFrame { code: frame.code.into(), reason: frame.reason.to_string().into() });
                        break;
                    }
                    Frame::Frame(_) => {}
                }
            }
        }
    }
    for turn in lanes.values_mut().flatten() {
        for (message, binary) in turn.flush() {
            let message = if binary {
                Message::Binary(message.into_bytes().into())
            } else {
                Message::Text(message.into())
            };
            if client.send(message).await.is_err() {
                return;
            }
        }
    }
    let _ = client.send(Message::Close(closing)).await;
    let _ = upstream.close(None).await;
}
