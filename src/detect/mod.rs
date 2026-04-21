use crate::config::MonitorConfig;
use crate::logtail::json_line::{parse_line, ParsedLine};
use chrono::Utc;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct MiningCandidate {
    pub worker_id: u64,
    pub height: u64,
    pub nonce: String,
    pub raw: String,
    pub combined: String,
    pub log_timestamp: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MiningVerificationResult {
    pub candidate: MiningCandidate,
    pub matched_contract: String,
    pub tx_hash: Option<String>,
    pub matched_block: u64,
    pub confidence: String,
    pub evidence: String,
    pub source_path: Option<String>,
    pub node_addr: Option<String>,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MiningVerificationFailure {
    pub candidate: MiningCandidate,
    pub reason: String,
    pub source_path: Option<String>,
    pub node_addr: Option<String>,
    pub client_id: Option<String>,
}

#[derive(Debug)]
pub enum InputEvent {
    LogLine {
        path: PathBuf,
        line: String,
        node_addr: Option<String>,
        client_id: Option<String>,
    },
    MiningCandidateVerified(MiningVerificationResult),
    MiningCandidateUnverified(MiningVerificationFailure),
    NodeDown {
        addr: String,
        error: String,
        client_id: Option<String>,
        source: Option<String>,
    },
    NodeUp {
        addr: String,
        latency_ms: u128,
        client_id: Option<String>,
        source: Option<String>,
    },
    RpcUnavailable {
        endpoints: Vec<String>,
        error: String,
        client_id: Option<String>,
    },
    RpcRecovered {
        endpoint: String,
        height: u64,
        latency_ms: u128,
        client_id: Option<String>,
    },
    ChainStalled {
        endpoint: String,
        height: u64,
        stall_secs: u64,
        block_age_secs: u64,
        client_id: Option<String>,
    },
    ChainRecovered {
        endpoint: String,
        height: u64,
        latency_ms: u128,
        client_id: Option<String>,
    },
    RemoteHostDown {
        host: String,
        error: String,
    },
    RemoteHostUp {
        host: String,
    },
    ScreenMissing {
        host: String,
        screen_name: String,
        client_id: Option<String>,
    },
    ScreenRecovered {
        host: String,
        screen_name: String,
        client_id: Option<String>,
    },
    ProcessMissing {
        host: String,
        keyword: String,
        client_id: Option<String>,
    },
    ProcessRecovered {
        host: String,
        keyword: String,
        client_id: Option<String>,
    },
    ProcessRestartTriggered {
        host: String,
        keyword: String,
        command: String,
        client_id: Option<String>,
    },
    ProcessRestartFailed {
        host: String,
        keyword: String,
        error: String,
        client_id: Option<String>,
    },
    ProcessRestartSkippedCooldown {
        host: String,
        keyword: String,
        cooldown_secs: u64,
        remaining_secs: u64,
        client_id: Option<String>,
    },
    LogStale {
        host: String,
        stale_threshold_secs: u64,
        stale_secs: u64,
        latest_log_timestamp: String,
        client_id: Option<String>,
    },
    LogRecovered {
        host: String,
        latest_log_timestamp: String,
        client_id: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertEvent {
    pub event_type: String,
    pub rule_id: String,
    pub severity: String,
    pub node_addr: Option<String>,
    pub client_id: Option<String>,
    pub source_path: Option<String>,
    pub timestamp: String,
    pub log_timestamp: Option<String>,
    pub summary: String,
    pub matched: Option<String>,
    pub raw: String,

    #[serde(skip_serializing)]
    pub fingerprint_key: String,
}

pub fn parse_mining_candidate(raw: &str) -> Option<MiningCandidate> {
    let parsed = parse_line(raw);
    let (_, log_timestamp, combined) = split_line_parts(&parsed);
    parse_candidate_from_combined(raw, combined, log_timestamp)
}

pub fn detect_event(cfg: &MonitorConfig, ev: InputEvent) -> Option<AlertEvent> {
    match ev {
        InputEvent::LogLine {
            path,
            line,
            node_addr,
            client_id,
        } => detect_log(cfg, path, line, node_addr, client_id),
        InputEvent::MiningCandidateVerified(result) => Some(AlertEvent {
            event_type: "candidate_verified".to_string(),
            rule_id: "candidate_verified".to_string(),
            severity: "info".to_string(),
            node_addr: result.node_addr,
            client_id: result.client_id.or_else(|| cfg.node.client_id.clone()),
            source_path: result.source_path,
            timestamp: now_rfc3339(),
            log_timestamp: result.candidate.log_timestamp,
            summary: format!(
                "爆块候选已链上确认: height={}, workerID={}, nonce={}, contract={}, block={}, confidence={}",
                result.candidate.height,
                result.candidate.worker_id,
                result.candidate.nonce,
                result.matched_contract,
                result.matched_block,
                result.confidence
            ),
            matched: result.tx_hash,
            raw: truncate(
                format!(
                    "evidence={} | combined={} | raw={}",
                    result.evidence, result.candidate.combined, result.candidate.raw
                ),
                cfg.alert.max_raw_bytes,
            ),
            fingerprint_key: format!(
                "candidate_verified|{}|{}|{}",
                result.candidate.height, result.candidate.worker_id, result.candidate.nonce
            ),
        }),
        InputEvent::MiningCandidateUnverified(result) => Some(AlertEvent {
            event_type: "candidate_unverified".to_string(),
            rule_id: "candidate_unverified".to_string(),
            severity: "warning".to_string(),
            node_addr: result.node_addr,
            client_id: result.client_id.or_else(|| cfg.node.client_id.clone()),
            source_path: result.source_path,
            timestamp: now_rfc3339(),
            log_timestamp: result.candidate.log_timestamp,
            summary: format!(
                "爆块候选未确认: height={}, workerID={}, nonce={} ({})",
                result.candidate.height, result.candidate.worker_id, result.candidate.nonce, result.reason
            ),
            matched: None,
            raw: truncate(
                format!("combined={} | raw={}", result.candidate.combined, result.candidate.raw),
                cfg.alert.max_raw_bytes,
            ),
            fingerprint_key: format!(
                "candidate_unverified|{}|{}|{}",
                result.candidate.height, result.candidate.worker_id, result.candidate.nonce
            ),
        }),
        InputEvent::NodeDown {
            addr,
            error,
            client_id,
            source,
        } => Some(AlertEvent {
            event_type: "node_down".to_string(),
            rule_id: "node_down".to_string(),
            severity: "critical".to_string(),
            node_addr: Some(addr.clone()),
            client_id: client_id.or_else(|| cfg.node.client_id.clone()),
            source_path: source.clone(),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: match source {
                Some(source) => format!("节点不可达: {addr} ({error}) 来源: {source}"),
                None => format!("节点不可达: {addr} ({error})"),
            },
            matched: None,
            raw: truncate(error, cfg.alert.max_raw_bytes),
            fingerprint_key: format!("node_down|{addr}"),
        }),
        InputEvent::NodeUp {
            addr,
            latency_ms,
            client_id,
            source,
        } => Some(AlertEvent {
            event_type: "node_up".to_string(),
            rule_id: "node_up".to_string(),
            severity: "info".to_string(),
            node_addr: Some(addr.clone()),
            client_id: client_id.or_else(|| cfg.node.client_id.clone()),
            source_path: source.clone(),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: match source {
                Some(source) => format!("节点恢复: {addr} (latency {latency_ms}ms) 来源: {source}"),
                None => format!("节点恢复: {addr} (latency {latency_ms}ms)"),
            },
            matched: None,
            raw: String::new(),
            fingerprint_key: format!("node_up|{addr}"),
        }),
        InputEvent::RpcUnavailable {
            endpoints,
            error,
            client_id,
        } => Some(AlertEvent {
            event_type: "rpc_unavailable".to_string(),
            rule_id: "rpc_unavailable".to_string(),
            severity: "critical".to_string(),
            node_addr: None,
            client_id: client_id.or_else(|| cfg.node.client_id.clone()),
            source_path: None,
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!("RPC 不可用: {}", endpoints.join(", ")),
            matched: None,
            raw: truncate(error, cfg.alert.max_raw_bytes),
            fingerprint_key: format!("rpc_unavailable|{}", endpoints.join("|")),
        }),
        InputEvent::RpcRecovered {
            endpoint,
            height,
            latency_ms,
            client_id,
        } => Some(AlertEvent {
            event_type: "rpc_recovered".to_string(),
            rule_id: "rpc_recovered".to_string(),
            severity: "info".to_string(),
            node_addr: None,
            client_id: client_id.or_else(|| cfg.node.client_id.clone()),
            source_path: Some(endpoint.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!("RPC 恢复: {endpoint}, latest={height}, latency={latency_ms}ms"),
            matched: None,
            raw: String::new(),
            fingerprint_key: format!("rpc_recovered|{endpoint}"),
        }),
        InputEvent::ChainStalled {
            endpoint,
            height,
            stall_secs,
            block_age_secs,
            client_id,
        } => Some(AlertEvent {
            event_type: "chain_stalled".to_string(),
            rule_id: "chain_stalled".to_string(),
            severity: "critical".to_string(),
            node_addr: None,
            client_id: client_id.or_else(|| cfg.node.client_id.clone()),
            source_path: Some(endpoint.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!(
                "链停滞: {endpoint}, latest={height}, stall={stall_secs}s, block_age={block_age_secs}s"
            ),
            matched: None,
            raw: String::new(),
            fingerprint_key: format!("chain_stalled|{endpoint}"),
        }),
        InputEvent::ChainRecovered {
            endpoint,
            height,
            latency_ms,
            client_id,
        } => Some(AlertEvent {
            event_type: "chain_recovered".to_string(),
            rule_id: "chain_recovered".to_string(),
            severity: "info".to_string(),
            node_addr: None,
            client_id: client_id.or_else(|| cfg.node.client_id.clone()),
            source_path: Some(endpoint.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!("链恢复: {endpoint}, latest={height}, latency={latency_ms}ms"),
            matched: None,
            raw: String::new(),
            fingerprint_key: format!("chain_recovered|{endpoint}"),
        }),
        InputEvent::RemoteHostDown { host, error } => Some(AlertEvent {
            event_type: "remote_host_down".to_string(),
            rule_id: "remote_host_down".to_string(),
            severity: "critical".to_string(),
            node_addr: None,
            client_id: None,
            source_path: Some(host.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!("SSH 远端机器不可达: {host}"),
            matched: None,
            raw: truncate(error, cfg.alert.max_raw_bytes),
            fingerprint_key: format!("remote_host_down|{host}"),
        }),
        InputEvent::RemoteHostUp { host } => Some(AlertEvent {
            event_type: "remote_host_up".to_string(),
            rule_id: "remote_host_up".to_string(),
            severity: "info".to_string(),
            node_addr: None,
            client_id: None,
            source_path: Some(host.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!("SSH 远端机器恢复: {host}"),
            matched: None,
            raw: String::new(),
            fingerprint_key: format!("remote_host_up|{host}"),
        }),
        InputEvent::ScreenMissing {
            host,
            screen_name,
            client_id,
        } => Some(AlertEvent {
            event_type: "screen_missing".to_string(),
            rule_id: "screen_missing".to_string(),
            severity: "critical".to_string(),
            node_addr: None,
            client_id,
            source_path: Some(host.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!("screen 缺失: {host} -> {screen_name}"),
            matched: Some(screen_name.clone()),
            raw: screen_name.clone(),
            fingerprint_key: format!("screen_missing|{host}|{screen_name}"),
        }),
        InputEvent::ScreenRecovered {
            host,
            screen_name,
            client_id,
        } => Some(AlertEvent {
            event_type: "screen_recovered".to_string(),
            rule_id: "screen_recovered".to_string(),
            severity: "info".to_string(),
            node_addr: None,
            client_id,
            source_path: Some(host.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!("screen 恢复: {host} -> {screen_name}"),
            matched: Some(screen_name.clone()),
            raw: String::new(),
            fingerprint_key: format!("screen_recovered|{host}|{screen_name}"),
        }),
        InputEvent::ProcessMissing {
            host,
            keyword,
            client_id,
        } => Some(AlertEvent {
            event_type: "process_missing".to_string(),
            rule_id: "process_missing".to_string(),
            severity: "critical".to_string(),
            node_addr: None,
            client_id,
            source_path: Some(host.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!("进程缺失: {host} -> {keyword}"),
            matched: Some(keyword.clone()),
            raw: keyword.clone(),
            fingerprint_key: format!("process_missing|{host}|{keyword}"),
        }),
        InputEvent::ProcessRecovered {
            host,
            keyword,
            client_id,
        } => Some(AlertEvent {
            event_type: "process_recovered".to_string(),
            rule_id: "process_recovered".to_string(),
            severity: "info".to_string(),
            node_addr: None,
            client_id,
            source_path: Some(host.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!("进程恢复: {host} -> {keyword}"),
            matched: Some(keyword.clone()),
            raw: String::new(),
            fingerprint_key: format!("process_recovered|{host}|{keyword}"),
        }),
        InputEvent::ProcessRestartTriggered {
            host,
            keyword,
            command,
            client_id,
        } => Some(AlertEvent {
            event_type: "process_restart_triggered".to_string(),
            rule_id: "process_restart_triggered".to_string(),
            severity: "info".to_string(),
            node_addr: None,
            client_id,
            source_path: Some(host.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!("进程重启已触发: {host} -> {keyword}"),
            matched: Some(keyword.clone()),
            raw: truncate(command, cfg.alert.max_raw_bytes),
            fingerprint_key: format!("process_restart_triggered|{host}|{keyword}"),
        }),
        InputEvent::ProcessRestartFailed {
            host,
            keyword,
            error,
            client_id,
        } => Some(AlertEvent {
            event_type: "process_restart_failed".to_string(),
            rule_id: "process_restart_failed".to_string(),
            severity: "critical".to_string(),
            node_addr: None,
            client_id,
            source_path: Some(host.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!("进程重启失败: {host} -> {keyword}"),
            matched: Some(keyword.clone()),
            raw: truncate(error, cfg.alert.max_raw_bytes),
            fingerprint_key: format!("process_restart_failed|{host}|{keyword}"),
        }),
        InputEvent::ProcessRestartSkippedCooldown {
            host,
            keyword,
            cooldown_secs,
            remaining_secs,
            client_id,
        } => Some(AlertEvent {
            event_type: "process_restart_skipped_cooldown".to_string(),
            rule_id: "process_restart_skipped_cooldown".to_string(),
            severity: "info".to_string(),
            node_addr: None,
            client_id,
            source_path: Some(host.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: None,
            summary: format!(
                "进程重启冷却中跳过: {host} -> {keyword} (cooldown={cooldown_secs}s, remaining={remaining_secs}s)"
            ),
            matched: Some(keyword.clone()),
            raw: String::new(),
            fingerprint_key: format!("process_restart_skipped_cooldown|{host}|{keyword}"),
        }),
        InputEvent::LogStale {
            host,
            stale_threshold_secs,
            stale_secs,
            latest_log_timestamp,
            client_id,
        } => Some(AlertEvent {
            event_type: "log_stale".to_string(),
            rule_id: "log_stale".to_string(),
            severity: "critical".to_string(),
            node_addr: None,
            client_id,
            source_path: Some(host.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: Some(latest_log_timestamp),
            summary: format!(
                "日志时间停滞: {host} (threshold={stale_threshold_secs}s, stale={stale_secs}s)"
            ),
            matched: None,
            raw: String::new(),
            fingerprint_key: format!("log_stale|{host}"),
        }),
        InputEvent::LogRecovered {
            host,
            latest_log_timestamp,
            client_id,
        } => Some(AlertEvent {
            event_type: "log_recovered".to_string(),
            rule_id: "log_recovered".to_string(),
            severity: "info".to_string(),
            node_addr: None,
            client_id,
            source_path: Some(host.clone()),
            timestamp: now_rfc3339(),
            log_timestamp: Some(latest_log_timestamp),
            summary: format!("日志时间恢复推进: {host}"),
            matched: None,
            raw: String::new(),
            fingerprint_key: format!("log_recovered|{host}"),
        }),
    }
}

fn detect_log(
    cfg: &MonitorConfig,
    path: PathBuf,
    raw: String,
    node_addr: Option<String>,
    client_id: Option<String>,
) -> Option<AlertEvent> {
    let parsed = parse_line(&raw);
    let (level, log_ts, combined) = split_line_parts(&parsed);

    for pat in &cfg.detect.suppress_patterns {
        if !pat.is_empty() && combined.contains(pat) {
            return None;
        }
    }

    if let Some(candidate) = parse_candidate_from_combined(&raw, combined.clone(), log_ts.clone()) {
        return Some(AlertEvent {
            event_type: "candidate_detected".to_string(),
            rule_id: "candidate_detected".to_string(),
            severity: "info".to_string(),
            node_addr: node_addr.or_else(|| cfg.node.server_addr.clone()),
            client_id: client_id.or_else(|| cfg.node.client_id.clone()),
            source_path: Some(path.to_string_lossy().to_string()),
            timestamp: now_rfc3339(),
            log_timestamp: log_ts,
            summary: format!(
                "发现爆块候选: height={}, workerID={}, nonce={}",
                candidate.height, candidate.worker_id, candidate.nonce
            ),
            matched: Some(format!(
                "height={}, workerID={}, nonce={}",
                candidate.height, candidate.worker_id, candidate.nonce
            )),
            raw: truncate(raw, cfg.alert.max_raw_bytes),
            fingerprint_key: format!(
                "candidate_detected|{}|{}|{}",
                candidate.height, candidate.worker_id, candidate.nonce
            ),
        });
    }

    if let Some(matched) = find_match(&combined, &cfg.detect.block_fail_keywords) {
        return Some(AlertEvent {
            event_type: "mining_error".to_string(),
            rule_id: "block_fail".to_string(),
            severity: "critical".to_string(),
            node_addr: node_addr.or_else(|| cfg.node.server_addr.clone()),
            client_id: client_id.or_else(|| cfg.node.client_id.clone()),
            source_path: Some(path.to_string_lossy().to_string()),
            timestamp: now_rfc3339(),
            log_timestamp: log_ts,
            summary: format!("命中出块/提交失败日志关键字: {matched}"),
            matched: Some(matched.clone()),
            raw: truncate(raw, cfg.alert.max_raw_bytes),
            fingerprint_key: format!("block_fail|{}|{matched}", path.to_string_lossy()),
        });
    }

    let level_lc = level.to_ascii_lowercase();
    if (level_lc == "fatal" || level_lc == "error")
        && find_match(&combined, &cfg.detect.secondary_keywords).is_some()
    {
        let matched = find_match(&combined, &cfg.detect.secondary_keywords).cloned();
        return Some(AlertEvent {
            event_type: "mining_error".to_string(),
            rule_id: "mining_related_error".to_string(),
            severity: "critical".to_string(),
            node_addr: node_addr.or_else(|| cfg.node.server_addr.clone()),
            client_id: client_id.or_else(|| cfg.node.client_id.clone()),
            source_path: Some(path.to_string_lossy().to_string()),
            timestamp: now_rfc3339(),
            log_timestamp: log_ts,
            summary: "命中挖矿相关 error/fatal 日志".to_string(),
            matched,
            raw: truncate(raw, cfg.alert.max_raw_bytes),
            fingerprint_key: format!(
                "mining_related_error|{}|{}",
                path.to_string_lossy(),
                combined_fingerprint(&combined)
            ),
        });
    }

    None
}

fn split_line_parts(parsed: &ParsedLine) -> (String, Option<String>, String) {
    match parsed {
        ParsedLine::Json(j) => {
            let lvl = j.level.clone().unwrap_or_default();
            let ts = j.timestamp.clone();
            let mut parts: Vec<String> = Vec::new();
            if let Some(m) = &j.msg {
                parts.push(m.clone());
            }
            if let Some(e) = &j.error {
                parts.push(e.clone());
            }
            if let Some(s) = &j.stacktrace {
                parts.push(s.clone());
            }
            (lvl, ts, parts.join(" | "))
        }
        ParsedLine::Text(t) => (String::new(), None, t.clone()),
    }
}

fn parse_candidate_from_combined(
    raw: &str,
    combined: String,
    log_timestamp: Option<String>,
) -> Option<MiningCandidate> {
    if !contains_candidate_markers(&combined) {
        return None;
    }

    let worker_id = extract_numeric_field(&combined, &["workerid", "worker_id"])?;
    let height = extract_numeric_field(&combined, &["height"])?;
    let nonce = extract_string_field(&combined, &["nonce"])?;

    Some(MiningCandidate {
        worker_id,
        height,
        nonce,
        raw: raw.to_string(),
        combined,
        log_timestamp,
    })
}

fn contains_candidate_markers(input: &str) -> bool {
    let input_lc = input.to_ascii_lowercase();
    (input_lc.contains("valid nonce")
        || input.contains("有效Nonce")
        || input.contains("有效 nonce"))
        && input_lc.contains("worker")
        && input_lc.contains("height")
        && input_lc.contains("nonce")
}

fn extract_numeric_field(input: &str, keys: &[&str]) -> Option<u64> {
    extract_string_field(input, keys)?.parse().ok()
}

fn extract_string_field(input: &str, keys: &[&str]) -> Option<String> {
    let input_lc = input.to_ascii_lowercase();
    for key in keys {
        let key_lc = key.to_ascii_lowercase();
        let mut search_from = 0usize;
        while let Some(relative_idx) = input_lc[search_from..].find(&key_lc) {
            let idx = search_from + relative_idx;
            let after_key = &input[idx + key.len()..];
            if let Some(value) = trim_field_value(after_key) {
                return Some(value);
            }
            search_from = idx + key.len();
        }
    }
    None
}

fn trim_field_value(remainder: &str) -> Option<String> {
    let start = remainder
        .char_indices()
        .find(|(_, ch)| !matches!(ch, ' ' | '\t' | '"' | '\\'))
        .map(|(idx, _)| idx)?;
    let tail = &remainder[start..];
    let tail = tail.strip_prefix(':').or_else(|| tail.strip_prefix('='))?;
    let value_start = tail
        .char_indices()
        .find(|(_, ch)| !matches!(ch, ' ' | '\t' | '"' | '\\'))
        .map(|(idx, _)| idx)?;
    let value_tail = &tail[value_start..];
    let end = value_tail
        .char_indices()
        .find(|(_, ch)| matches!(ch, ',' | '}' | ' ' | '|' | '"'))
        .map(|(idx, _)| idx)
        .unwrap_or(value_tail.len());
    let value = value_tail[..end].trim().trim_matches('"');
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn find_match<'a>(haystack: &'a str, needles: &'a [String]) -> Option<&'a String> {
    let haystack_lc = haystack.to_ascii_lowercase();
    needles
        .iter()
        .find(|n| !n.is_empty() && haystack_lc.contains(&n.to_ascii_lowercase()))
}

fn truncate(s: String, max: usize) -> String {
    if s.len() <= max {
        s
    } else {
        s.chars().take(max).collect()
    }
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn combined_fingerprint(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().take(128) {
        if c.is_ascii_whitespace() {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::parse_mining_candidate;

    #[test]
    fn parses_candidate_from_plain_text_log() {
        let raw = r#"找到有效Nonce\",\"workerID\":13, \"height\":70203821,\"nonce\":10422410401645896667"#;
        let parsed = parse_mining_candidate(raw).expect("candidate should parse");
        assert_eq!(parsed.worker_id, 13);
        assert_eq!(parsed.height, 70203821);
        assert_eq!(parsed.nonce, "10422410401645896667");
    }

    #[test]
    fn parses_candidate_from_json_log_message() {
        let raw = r#"{"timestamp":"2026-04-21T00:00:00Z","msg":"found valid nonce workerID=9, height=88, nonce=12345"}"#;
        let parsed = parse_mining_candidate(raw).expect("candidate should parse");
        assert_eq!(parsed.worker_id, 9);
        assert_eq!(parsed.height, 88);
        assert_eq!(parsed.nonce, "12345");
        assert_eq!(
            parsed.log_timestamp.as_deref(),
            Some("2026-04-21T00:00:00Z")
        );
    }

    #[test]
    fn ignores_non_candidate_logs() {
        assert!(parse_mining_candidate("submit failed height=88 nonce=123").is_none());
    }
}
