//! Antigravity (Windsurf/Codeium) session parser
//!
//! Discovers cascade IDs from `.pb` files in `~/.gemini/antigravity/conversations/`,
//! connects to a running language server via HTTP RPC, and extracts token usage
//! from the `GetCascadeTrajectory` response's `generatorMetadata`.

use super::UnifiedMessage;
use crate::pricing::aliases::resolve_alias;
use crate::{provider_identity, TokenBreakdown};
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const CLIENT_NAME: &str = "antigravity";
const RPC_BASE_PATH: &str = "/exa.language_server_pb.LanguageServerService";

// ── Process discovery ────────────────────────────────────────────────

/// Language server connection info.
struct ServerInfo {
    csrf_token: String,
    base_url: String,
}

/// Find a running language server and its HTTP endpoint.
fn discover_server() -> Option<ServerInfo> {
    let (pid, csrf_token) = find_language_server()?;
    let ports = find_listening_ports(&pid);
    if ports.is_empty() {
        return None;
    }
    let base_url = probe_http_port(&ports, &csrf_token)?;
    Some(ServerInfo {
        csrf_token,
        base_url,
    })
}

/// Find a running language server process with a `--csrf_token` argument.
/// Returns `(pid, csrf_token)`.
fn find_language_server() -> Option<(String, String)> {
    if cfg!(target_os = "windows") {
        find_language_server_win()
    } else {
        find_language_server_unix()
    }
}

fn find_language_server_unix() -> Option<(String, String)> {
    let output = Command::new("sh")
        .args(["-c", "ps aux | grep 'antigravity/bin/language_server_'"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.contains("grep") {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let pid = parts[1].to_string();

        // Extract --csrf_token value
        if let Some(csrf_token) = extract_csrf_from_cmdline(trimmed) {
            return Some((pid, csrf_token));
        }
    }
    None
}

fn find_language_server_win() -> Option<(String, String)> {
    let output = Command::new("cmd")
        .args([
            "/C",
            "wmic process where \"CommandLine like '%antigravity%language_server%'\" get ProcessId,CommandLine /format:list",
        ])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut cmd_line = String::new();
    let mut pid = String::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("CommandLine=") {
            if val.to_uppercase().contains("WMIC.EXE") {
                continue;
            }
            cmd_line = val.to_string();
        }
        if let Some(val) = trimmed.strip_prefix("ProcessId=") {
            pid = val.to_string();
        }
    }

    if pid.is_empty() || cmd_line.is_empty() {
        return None;
    }

    let csrf_token = extract_csrf_from_cmdline(&cmd_line)?;
    Some((pid, csrf_token))
}

fn extract_csrf_from_cmdline(line: &str) -> Option<String> {
    let idx = line.find("--csrf_token")?;
    let after = &line[idx + "--csrf_token".len()..];
    let token = after.trim().split_whitespace().next()?;
    // Validate UUID-like format
    if token.len() >= 32 && token.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        Some(token.to_string())
    } else {
        None
    }
}

/// Find TCP ports a process is listening on.
fn find_listening_ports(pid: &str) -> Vec<u16> {
    if cfg!(target_os = "windows") {
        find_listening_ports_win(pid)
    } else {
        find_listening_ports_unix(pid)
    }
}

fn find_listening_ports_unix(pid: &str) -> Vec<u16> {
    let output = Command::new("lsof")
        .args(["-iTCP", "-sTCP:LISTEN", "-nP", "-a", "-p", pid])
        .output()
        .ok();
    let output = match output {
        Some(o) => o,
        None => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ports = Vec::new();

    for line in stdout.lines() {
        // Match lines like ":49327 (LISTEN)"
        if let Some(listen_pos) = line.find("(LISTEN)") {
            let before = &line[..listen_pos];
            if let Some(colon_pos) = before.rfind(':') {
                if let Ok(port) = before[colon_pos + 1..].trim().parse::<u16>() {
                    ports.push(port);
                }
            }
        }
    }
    ports
}

fn find_listening_ports_win(pid: &str) -> Vec<u16> {
    let output = Command::new("netstat").arg("-ano").output().ok();
    let output = match output {
        Some(o) => o,
        None => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ports = Vec::new();

    for line in stdout.lines() {
        if !line.contains("LISTENING") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let line_pid = parts.last().copied().unwrap_or("");
        if line_pid != pid {
            continue;
        }
        // parts[1] is "addr:port"
        if let Some(addr) = parts.get(1) {
            if let Some(colon_pos) = addr.rfind(':') {
                if let Ok(port) = addr[colon_pos + 1..].parse::<u16>() {
                    ports.push(port);
                }
            }
        }
    }
    ports
}

/// Synchronous HTTP POST to a localhost endpoint. Returns the response body
/// on success (2xx status). Uses raw `TcpStream` to avoid async runtime issues.
fn http_post(addr: &str, path: &str, csrf_token: &str, body: &str) -> Option<String> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let mut stream = TcpStream::connect(addr).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok()?;

    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connect-Protocol-Version: 1\r\n\
         X-Codeium-Csrf-Token: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        path,
        addr,
        body.len(),
        csrf_token,
        body
    );

    stream.write_all(request.as_bytes()).ok()?;

    let mut reader = BufReader::new(stream);

    // Parse status line
    let mut status_line = String::new();
    reader.read_line(&mut status_line).ok()?;
    let status_code: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;
    if !(200..300).contains(&status_code) {
        return None;
    }

    // Parse headers to find Content-Length or Transfer-Encoding
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let trimmed = header.trim();
        if trimmed.is_empty() {
            break;
        }
        let lower = trimmed.to_lowercase();
        if let Some(val) = lower.strip_prefix("content-length:") {
            content_length = val.trim().parse().ok();
        }
        if lower.contains("transfer-encoding") && lower.contains("chunked") {
            chunked = true;
        }
    }

    // Read body
    if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).ok()?;
        String::from_utf8(buf).ok()
    } else if chunked {
        let mut body_buf = Vec::new();
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line).ok()?;
            let chunk_size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if chunk_size == 0 {
                break;
            }
            let mut chunk = vec![0u8; chunk_size];
            reader.read_exact(&mut chunk).ok()?;
            body_buf.extend_from_slice(&chunk);
            // Read trailing \r\n
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf);
        }
        String::from_utf8(body_buf).ok()
    } else {
        // Read until EOF
        let mut buf = String::new();
        let _ = reader.read_to_string(&mut buf);
        Some(buf)
    }
}

/// Try each port to find the language server HTTP endpoint.
fn probe_http_port(ports: &[u16], csrf_token: &str) -> Option<String> {
    for &port in ports {
        let addr = format!("127.0.0.1:{}", port);
        let path = format!("{}/GetWorkspaceInfos", RPC_BASE_PATH);

        if http_post(&addr, &path, csrf_token, "{}").is_some() {
            return Some(format!("http://{}", addr));
        }
    }
    None
}

// ── RPC call ─────────────────────────────────────────────────────────

fn rpc_call(server: &ServerInfo, method: &str, body: &str) -> Option<Value> {
    // Extract host:port from base_url (http://127.0.0.1:PORT)
    let addr = server.base_url.strip_prefix("http://")?;
    let path = format!("{}/{}", RPC_BASE_PATH, method);

    let text = http_post(addr, &path, &server.csrf_token, body)?;
    serde_json::from_str(&text).ok()
}

// ── Response parsing ─────────────────────────────────────────────────

fn to_safe_i64(value: Option<&Value>) -> i64 {
    value
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_u64().map(|n| n as i64))
                .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
        })
        .unwrap_or(0)
        .max(0)
}

fn parse_rfc3339_to_millis(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp_millis())
}

/// Get provider from model name (e.g. "gemini-2.5-pro" → "google").
fn get_provider(model: &str) -> &'static str {
    provider_identity::inferred_provider_from_model(model).unwrap_or("google")
}

/// Map internal placeholder model IDs to canonical names.
fn resolve_placeholder(model: &str) -> Option<&'static str> {
    match model {
        "MODEL_PLACEHOLDER_M37" | "MODEL_PLACEHOLDER_M36" => Some("gemini-3.1-pro"),
        "MODEL_PLACEHOLDER_M47" => Some("gemini-3-flash"),
        "MODEL_PLACEHOLDER_M35" => Some("claude-sonnet-4-6"),
        "MODEL_PLACEHOLDER_M26" => Some("claude-opus-4-6"),
        "MODEL_OPENAI_GPT_OSS_120B_MEDIUM" => Some("gpt-oss-120b"),
        _ => None,
    }
}

/// Resolve model name with full resolution chain:
/// responseModel → alias resolve → if empty, chatModel.model placeholder map → "unknown"
fn resolve_model(chat_model: &Value) -> String {
    let response_model = chat_model
        .get("responseModel")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if !response_model.is_empty() {
        // Try alias resolution first, fall back to raw name
        return resolve_alias(response_model)
            .unwrap_or(response_model)
            .to_string();
    }

    // Fallback: check chatModel.model against placeholder map
    let model_field = chat_model
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if let Some(resolved) = resolve_placeholder(model_field) {
        return resolved.to_string();
    }

    "unknown".to_string()
}

/// Parse a single `GetCascadeTrajectory` response and extract `UnifiedMessage`s.
/// Also takes a mutable `seen_response_ids` set for global deduplication.
pub(crate) fn parse_trajectory_response(
    resp: &Value,
    cascade_id: &str,
    seen_response_ids: &mut HashSet<String>,
) -> Vec<UnifiedMessage> {
    let trajectory = match resp.get("trajectory") {
        Some(t) => t,
        None => return Vec::new(),
    };

    let metadata_list = trajectory
        .get("generatorMetadata")
        .and_then(|v| v.as_array());

    let metadata_list = match metadata_list {
        Some(list) => list,
        None => return Vec::new(),
    };

    let mut messages = Vec::new();

    for meta in metadata_list {
        let chat_model = match meta.get("chatModel") {
            Some(cm) => cm,
            None => continue,
        };

        let model = resolve_model(chat_model);

        let created_at = chat_model
            .get("chatStartMetadata")
            .and_then(|m| m.get("createdAt"))
            .and_then(|v| v.as_str());

        let timestamp = match created_at.and_then(parse_rfc3339_to_millis) {
            Some(ts) => ts,
            None => continue,
        };

        let retry_infos = chat_model.get("retryInfos").and_then(|v| v.as_array());

        let retry_infos = match retry_infos {
            Some(ri) => ri,
            None => continue,
        };

        for retry in retry_infos {
            let usage = match retry.get("usage") {
                Some(u) => u,
                None => continue,
            };

            // Dedup by responseId
            let response_id = usage
                .get("responseId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !response_id.is_empty() {
                if seen_response_ids.contains(response_id) {
                    continue;
                }
                seen_response_ids.insert(response_id.to_string());
            }

            let input_tokens = to_safe_i64(usage.get("inputTokens"));
            let output_tokens = to_safe_i64(usage.get("outputTokens"));
            let cache_read_tokens = to_safe_i64(usage.get("cacheReadTokens"));
            let thinking_tokens = to_safe_i64(usage.get("thinkingOutputTokens"));

            if input_tokens == 0
                && output_tokens == 0
                && cache_read_tokens == 0
                && thinking_tokens == 0
            {
                continue;
            }

            messages.push(UnifiedMessage::new(
                CLIENT_NAME,
                &model,
                get_provider(&model),
                cascade_id,
                timestamp,
                TokenBreakdown {
                    input: input_tokens,
                    output: output_tokens,
                    cache_read: cache_read_tokens,
                    cache_write: 0,
                    reasoning: thinking_tokens,
                },
                0.0,
            ));
        }
    }

    messages
}

// ── Public entry point ───────────────────────────────────────────────

/// Parse all Antigravity cascade files by discovering a running language server
/// and making RPC calls for each cascade ID.
///
/// Unlike other per-file parsers, this takes all paths at once to:
/// 1. Discover the language server only once
/// 2. Deduplicate `responseId` across all cascades
pub fn parse_antigravity_files(paths: &[PathBuf]) -> Vec<UnifiedMessage> {
    if paths.is_empty() {
        return Vec::new();
    }

    let server = match discover_server() {
        Some(s) => s,
        None => return Vec::new(),
    };

    let mut all_messages = Vec::new();
    let mut seen_response_ids = HashSet::new();

    for path in paths {
        let cascade_id = match cascade_id_from_path(path) {
            Some(id) => id,
            None => continue,
        };

        let body = format!(r#"{{"cascadeId":"{}"}}"#, cascade_id);
        let resp = match rpc_call(&server, "GetCascadeTrajectory", &body) {
            Some(r) => r,
            None => continue,
        };

        let messages = parse_trajectory_response(&resp, &cascade_id, &mut seen_response_ids);
        all_messages.extend(messages);
    }

    all_messages
}

/// Extract cascade ID from a `.pb` file path (the file stem).
fn cascade_id_from_path(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_trajectory_response(
        model: &str,
        created_at: &str,
        input: i64,
        output: i64,
        cache_read: i64,
        thinking: i64,
        response_id: &str,
    ) -> Value {
        serde_json::json!({
            "trajectory": {
                "generatorMetadata": [{
                    "chatModel": {
                        "responseModel": model,
                        "chatStartMetadata": {
                            "createdAt": created_at
                        },
                        "retryInfos": [{
                            "usage": {
                                "inputTokens": input,
                                "outputTokens": output,
                                "cacheReadTokens": cache_read,
                                "thinkingOutputTokens": thinking,
                                "responseId": response_id
                            }
                        }]
                    }
                }]
            }
        })
    }

    #[test]
    fn test_parse_trajectory_response_basic() {
        let resp = mock_trajectory_response(
            "gemini-2.5-pro",
            "2026-03-15T10:00:00Z",
            1000,
            500,
            200,
            50,
            "resp-001",
        );

        let mut seen = HashSet::new();
        let msgs = parse_trajectory_response(&resp, "cascade-abc", &mut seen);

        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].client, "antigravity");
        assert_eq!(msgs[0].model_id, "gemini-2.5-pro");
        assert_eq!(msgs[0].provider_id, "google");
        assert_eq!(msgs[0].session_id, "cascade-abc");
        assert_eq!(msgs[0].tokens.input, 1000);
        assert_eq!(msgs[0].tokens.output, 500);
        assert_eq!(msgs[0].tokens.cache_read, 200);
        assert_eq!(msgs[0].tokens.reasoning, 50);
    }

    #[test]
    fn test_dedup_response_ids() {
        let resp = mock_trajectory_response(
            "gemini-2.5-pro",
            "2026-03-15T10:00:00Z",
            100,
            50,
            0,
            0,
            "resp-dup",
        );

        let mut seen = HashSet::new();
        seen.insert("resp-dup".to_string());

        let msgs = parse_trajectory_response(&resp, "cascade-1", &mut seen);
        assert_eq!(msgs.len(), 0, "Duplicate responseId should be skipped");
    }

    #[test]
    fn test_empty_trajectory() {
        let resp = serde_json::json!({"trajectory": null});
        let mut seen = HashSet::new();
        let msgs = parse_trajectory_response(&resp, "cascade-1", &mut seen);
        assert_eq!(msgs.len(), 0);
    }

    #[test]
    fn test_no_trajectory_field() {
        let resp = serde_json::json!({"status": "ok"});
        let mut seen = HashSet::new();
        let msgs = parse_trajectory_response(&resp, "cascade-1", &mut seen);
        assert_eq!(msgs.len(), 0);
    }

    #[test]
    fn test_provider_inference() {
        let test_cases = vec![
            ("gemini-2.5-pro", "google"),
            ("claude-sonnet-4", "anthropic"),
            ("gpt-4o", "openai"),
            ("deepseek-v3", "deepseek"),
        ];

        for (model, expected_provider) in test_cases {
            let resp = mock_trajectory_response(
                model,
                "2026-03-15T10:00:00Z",
                100,
                50,
                0,
                0,
                &format!("resp-{}", model),
            );

            let mut seen = HashSet::new();
            let msgs = parse_trajectory_response(&resp, "cascade-1", &mut seen);

            assert_eq!(msgs.len(), 1);
            assert_eq!(
                msgs[0].provider_id, expected_provider,
                "Model '{}' should map to provider '{}'",
                model, expected_provider
            );
        }
    }

    #[test]
    fn test_zero_token_usage_skipped() {
        let resp = mock_trajectory_response(
            "gemini-2.5-pro",
            "2026-03-15T10:00:00Z",
            0,
            0,
            0,
            0,
            "resp-zero",
        );

        let mut seen = HashSet::new();
        let msgs = parse_trajectory_response(&resp, "cascade-1", &mut seen);
        assert_eq!(msgs.len(), 0, "Zero-token entries should be skipped");
    }

    #[test]
    fn test_multiple_generator_metadata() {
        let resp = serde_json::json!({
            "trajectory": {
                "generatorMetadata": [
                    {
                        "chatModel": {
                            "responseModel": "gemini-2.5-pro",
                            "chatStartMetadata": { "createdAt": "2026-03-15T10:00:00Z" },
                            "retryInfos": [{
                                "usage": {
                                    "inputTokens": 100,
                                    "outputTokens": 50,
                                    "responseId": "resp-1"
                                }
                            }]
                        }
                    },
                    {
                        "chatModel": {
                            "responseModel": "claude-sonnet-4",
                            "chatStartMetadata": { "createdAt": "2026-03-15T10:01:00Z" },
                            "retryInfos": [{
                                "usage": {
                                    "inputTokens": 200,
                                    "outputTokens": 100,
                                    "responseId": "resp-2"
                                }
                            }]
                        }
                    }
                ]
            }
        });

        let mut seen = HashSet::new();
        let msgs = parse_trajectory_response(&resp, "cascade-1", &mut seen);

        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].model_id, "gemini-2.5-pro");
        assert_eq!(msgs[1].model_id, "claude-sonnet-4");
    }

    #[test]
    fn test_string_token_values() {
        // Some JSON responses may have token counts as strings
        let resp = serde_json::json!({
            "trajectory": {
                "generatorMetadata": [{
                    "chatModel": {
                        "responseModel": "gemini-2.5-pro",
                        "chatStartMetadata": { "createdAt": "2026-03-15T10:00:00Z" },
                        "retryInfos": [{
                            "usage": {
                                "inputTokens": "1000",
                                "outputTokens": "500",
                                "cacheReadTokens": "200",
                                "thinkingOutputTokens": "50",
                                "responseId": "resp-str"
                            }
                        }]
                    }
                }]
            }
        });

        let mut seen = HashSet::new();
        let msgs = parse_trajectory_response(&resp, "cascade-1", &mut seen);

        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].tokens.input, 1000);
        assert_eq!(msgs[0].tokens.output, 500);
        assert_eq!(msgs[0].tokens.cache_read, 200);
        assert_eq!(msgs[0].tokens.reasoning, 50);
    }

    #[test]
    fn test_cascade_id_from_path() {
        let path = PathBuf::from("/home/user/.gemini/antigravity/conversations/abc-123.pb");
        assert_eq!(cascade_id_from_path(&path), Some("abc-123".to_string()));

        let path = PathBuf::from("/tmp/test.pb");
        assert_eq!(cascade_id_from_path(&path), Some("test".to_string()));
    }
}
