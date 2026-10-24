use std::convert::Infallible;

use bytes::{Bytes, BytesMut};
use http::header;

use super::{RequestRedactions, anonymize_request_value, is_json, is_ndjson, protect_string};

pub(super) async fn anonymize(
    body: Bytes,
    content_type: &str,
    redactions: &mut RequestRedactions,
) -> Result<Bytes, &'static str> {
    let boundary =
        multer::parse_boundary(content_type).map_err(|_| "invalid multipart boundary")?;
    let source = futures_util::stream::once(async { Ok::<_, Infallible>(body) });
    let mut multipart = multer::Multipart::new(source, &boundary);
    let mut output = BytesMut::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| "invalid multipart body")?
    {
        let headers = field.headers().clone();
        let mut kind = field
            .content_type()
            .map(|kind| kind.essence_str().to_owned());
        let filename = field.file_name().unwrap_or_default().to_ascii_lowercase();
        let text_file = {
            [
                ".txt", ".md", ".csv", ".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".toml",
                ".env",
            ]
            .iter()
            .any(|suffix| filename.ends_with(suffix))
        };
        if filename.ends_with(".jsonl") || filename.ends_with(".ndjson") {
            kind = Some("application/x-ndjson".into());
        } else if filename.ends_with(".json") {
            kind = Some("application/json".into());
        }
        let text = kind
            .as_deref()
            .is_some_and(|kind| kind.starts_with("text/") || is_json(kind) || is_ndjson(kind))
            || text_file
            || (kind.is_none() && field.file_name().is_none());
        if headers
            .get("content-transfer-encoding")
            .is_some_and(|encoding| {
                !["7bit", "8bit", "binary"]
                    .iter()
                    .any(|allowed| encoding.as_bytes().eq_ignore_ascii_case(allowed.as_bytes()))
            })
        {
            return Err("encoded multipart parts are unsupported; send raw text or binary parts");
        }
        let data = field.bytes().await.map_err(|_| "invalid multipart field")?;
        let data = if text {
            let text = std::str::from_utf8(&data).map_err(|_| "multipart text must be UTF-8")?;
            if kind.as_deref().is_some_and(is_ndjson) {
                let mut lines = String::new();
                for line in text.split_inclusive('\n') {
                    if line.trim().is_empty() {
                        lines.push_str(line);
                        continue;
                    }
                    lines.push_str(&anonymize_json(line, redactions)?);
                    if line.ends_with('\n') {
                        lines.push('\n');
                    }
                }
                Bytes::from(lines)
            } else if kind.as_deref().is_some_and(is_json) {
                Bytes::from(anonymize_json(text, redactions)?)
            } else {
                Bytes::from(protect_string(text.to_owned(), redactions, 0))
            }
        } else {
            data
        };
        output.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        for (name, value) in &headers {
            if name == header::CONTENT_LENGTH {
                continue;
            }
            output.extend_from_slice(name.as_str().as_bytes());
            output.extend_from_slice(b": ");
            output.extend_from_slice(value.as_bytes());
            output.extend_from_slice(b"\r\n");
        }
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(&data);
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(output.freeze())
}

fn anonymize_json(text: &str, redactions: &mut RequestRedactions) -> Result<String, &'static str> {
    let mut value = serde_json::from_str(text).map_err(|_| "invalid JSON multipart field")?;
    anonymize_request_value(&mut value, redactions);
    serde_json::to_string(&value).map_err(|_| "failed to encode multipart JSON")
}
