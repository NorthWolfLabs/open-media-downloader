//! Bounded artwork and event adapters. All fetching still passes through the engine.
use super::*;
pub fn redact(value: &mut Value, secrets: &[String]) {
    match value {
        Value::String(text) => {
            for secret in secrets {
                if !secret.is_empty() {
                    *text = text.replace(secret, "[redacted]");
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact(item, secrets);
            }
        }
        Value::Object(items) => {
            let old = std::mem::take(items);
            for (key, mut item) in old {
                let mut key = Value::String(key);
                redact(&mut key, secrets);
                redact(&mut item, secrets);
                items.insert(key.as_str().unwrap().to_owned(), item);
            }
        }
        _ => {}
    }
}
pub fn input_secrets(operation: &str, args: &Value) -> Vec<String> {
    let mut secrets = Vec::new();
    if operation == "saveSourceAccount" {
        for field in ["headers", "cookies"] {
            if let Some(values) = args["request"]["session"][field].as_array() {
                for value in values {
                    if let Some(value) = value["value"].as_str() {
                        secrets.push(value.to_owned());
                    }
                }
            }
        }
    }
    if operation == "interactWithSignIn" {
        for field in ["text", "value"] {
            if let Some(value) = args["request"]["action"][field].as_str() {
                secrets.push(value.to_owned());
            }
        }
    }
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    secrets
}
pub async fn image_response(mut response: reqwest::Response) -> Result<Value, Value> {
    let mime = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();
    if !matches!(
        mime.as_str(),
        "image/png" | "image/jpeg" | "image/webp" | "image/gif" | "image/avif"
    ) {
        return Err(problem(
            "invalid_response",
            "Engine did not return supported raster artwork",
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| problem("transport", "Artwork response failed"))?
    {
        if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
            return Err(problem("response_too_large", "Artwork exceeds 4 MiB"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(json!({"mime_type": mime, "bytes": bytes.len(), "data": STANDARD.encode(bytes)}))
}
pub async fn event_response(mut response: reqwest::Response, args: &Value) -> Result<Value, Value> {
    if !response
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|s| s.starts_with("text/event-stream"))
    {
        return Err(problem(
            "invalid_response",
            "Engine did not return an event stream",
        ));
    }
    let wait = args["wait_ms"].as_u64().unwrap_or(1000);
    // A zero wait still allows a short round-trip to drain already available journal entries.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(wait.max(25));
    let mut pending = Vec::new();
    let mut total = 0;
    let mut events = Vec::new();
    let mut cursor = args["cursor"].as_i64().unwrap();
    let limit = args["limit"].as_u64().unwrap_or(100) as usize;
    loop {
        let chunk = match tokio::time::timeout_at(deadline, response.chunk()).await {
            Err(_) | Ok(Ok(None)) => break,
            Ok(Err(_)) => {
                return Err(problem(
                    "transport",
                    "Event response failed; retain the previous cursor",
                ));
            }
            Ok(Ok(Some(chunk))) => chunk,
        };
        total += chunk.len();
        if total > LIMIT {
            return Err(problem(
                "response_too_large",
                "Event window exceeds 2 MiB; retain the previous cursor",
            ));
        }
        pending.extend_from_slice(&chunk);
        while let Some((end, delimiter)) = pending
            .windows(2)
            .position(|v| v == b"\n\n")
            .map(|p| (p, 2))
            .or_else(|| {
                pending
                    .windows(4)
                    .position(|v| v == b"\r\n\r\n")
                    .map(|p| (p, 4))
            })
        {
            let frame: Vec<_> = pending.drain(..end + delimiter).collect();
            let frame = std::str::from_utf8(&frame)
                .map_err(|_| problem("invalid_response", "Invalid event encoding"))?;
            let mut data = Vec::new();
            let mut kind = "";
            for line in frame.lines() {
                if let Some(value) = line.strip_prefix("data:") {
                    data.push(value.trim_start_matches(' '));
                }
                if let Some(value) = line.strip_prefix("event:") {
                    kind = value.trim();
                }
            }
            if kind == "resync_required" {
                return Err(problem(
                    "resync_required",
                    "Take a fresh service_status snapshot and query affected resources",
                ));
            }
            if data.is_empty() {
                continue;
            }
            let event: Value = serde_json::from_str(&data.join("\n"))
                .map_err(|_| problem("invalid_response", "Invalid event JSON"))?;
            let id = event["id"]
                .as_i64()
                .filter(|id| *id > cursor)
                .ok_or_else(|| problem("invalid_response", "Event cursor did not advance"))?;
            if sensitive(&event) {
                return Err(problem(
                    "unsafe_response",
                    "Credential-shaped event rejected",
                ));
            }
            cursor = id;
            events.push(event);
            if events.len() >= limit {
                return Ok(json!({"events":events,"next_cursor":cursor,"limit_reached":true}));
            }
        }
    }
    Ok(json!({"events":events,"next_cursor":cursor,"limit_reached":false}))
}
