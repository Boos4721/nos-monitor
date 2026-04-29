use crate::config::RemoteHostConfig;
use crate::detect::InputEvent;
use crate::logtail::json_line::{parse_line, ParsedLine};
use anyhow::Context;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::sync::mpsc;

const PROCESS_MISSING_THRESHOLD: u32 = 2;
const SEEN_LOGS_CAP: usize = 10_000;

pub async fn run_ssh_loop(
    host_cfg: RemoteHostConfig,
    interval_secs: u64,
    timeout_secs: u64,
    tail_lines: usize,
    log_stale_threshold_secs: u64,
    tx: mpsc::Sender<InputEvent>,
) -> anyhow::Result<()> {
    let mut state = HostState::new();

    loop {
        match fetch_remote_snapshot(&host_cfg, timeout_secs, tail_lines).await {
            Ok(snapshot) => {
                if state.host_alerting {
                    if !try_send(
                        &tx,
                        InputEvent::RemoteHostUp {
                            host: host_cfg.name.clone(),
                        },
                    )
                    .await
                    {
                        return Ok(());
                    }
                    state.host_alerting = false;
                }

                if !emit_screen_events(&host_cfg, &snapshot.screens, &mut state, &tx).await {
                    return Ok(());
                }
                if !emit_process_events(
                    &host_cfg,
                    &snapshot.process_hits,
                    &mut state,
                    timeout_secs,
                    &tx,
                )
                .await
                {
                    return Ok(());
                }
                if !emit_log_stale_events(
                    &host_cfg,
                    &snapshot.logs,
                    &mut state,
                    timeout_secs,
                    log_stale_threshold_secs,
                    &tx,
                )
                .await
                {
                    return Ok(());
                }
                if !emit_log_events(&host_cfg, &snapshot.logs, &mut state, &tx).await {
                    return Ok(());
                }
            }
            Err(err) => {
                if !state.host_alerting {
                    if !try_send(
                        &tx,
                        InputEvent::RemoteHostDown {
                            host: host_cfg.name.clone(),
                            error: err.to_string(),
                        },
                    )
                    .await
                    {
                        return Ok(());
                    }
                    state.host_alerting = true;
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}

struct HostState {
    host_alerting: bool,
    missing_screens: HashSet<String>,
    missing_processes: HashSet<String>,
    missing_process_counts: HashMap<String, u32>,
    seen_logs: HashSet<String>,
    seen_log_fifo: VecDeque<String>,
    last_restart_at: HashMap<String, Instant>,
    last_log_timestamp: Option<DateTime<Utc>>,
    log_stale_alerting: bool,
}

impl HostState {
    fn new() -> Self {
        Self {
            host_alerting: false,
            missing_screens: HashSet::new(),
            missing_processes: HashSet::new(),
            missing_process_counts: HashMap::new(),
            seen_logs: HashSet::new(),
            seen_log_fifo: VecDeque::new(),
            last_restart_at: HashMap::new(),
            last_log_timestamp: None,
            log_stale_alerting: false,
        }
    }

    fn remember_seen_log(&mut self, fingerprint: String) -> bool {
        if !self.seen_logs.insert(fingerprint.clone()) {
            return false;
        }

        self.seen_log_fifo.push_back(fingerprint);
        while self.seen_log_fifo.len() > SEEN_LOGS_CAP {
            if let Some(oldest) = self.seen_log_fifo.pop_front() {
                self.seen_logs.remove(&oldest);
            }
        }
        true
    }
}

struct RemoteSnapshot {
    screens: HashSet<String>,
    process_hits: HashSet<String>,
    logs: HashMap<PathBuf, Vec<String>>,
}

async fn emit_screen_events(
    host_cfg: &RemoteHostConfig,
    found: &HashSet<String>,
    state: &mut HostState,
    tx: &mpsc::Sender<InputEvent>,
) -> bool {
    for expected in &host_cfg.screen_names {
        if found.contains(expected) {
            if state.missing_screens.remove(expected)
                && !try_send(
                    tx,
                    InputEvent::ScreenRecovered {
                        host: host_cfg.name.clone(),
                        screen_name: expected.clone(),
                        client_id: host_cfg.client_id.clone(),
                    },
                )
                .await
            {
                return false;
            }
        } else if state.missing_screens.insert(expected.clone())
            && !try_send(
                tx,
                InputEvent::ScreenMissing {
                    host: host_cfg.name.clone(),
                    screen_name: expected.clone(),
                    client_id: host_cfg.client_id.clone(),
                },
            )
            .await
        {
            return false;
        }
    }

    true
}

async fn emit_process_events(
    host_cfg: &RemoteHostConfig,
    found: &HashSet<String>,
    state: &mut HostState,
    timeout_secs: u64,
    tx: &mpsc::Sender<InputEvent>,
) -> bool {
    for expected in &host_cfg.process_keywords {
        if found.contains(expected) {
            state.missing_process_counts.remove(expected);
            if state.missing_processes.remove(expected)
                && !try_send(
                    tx,
                    InputEvent::ProcessRecovered {
                        host: host_cfg.name.clone(),
                        keyword: expected.clone(),
                        client_id: host_cfg.client_id.clone(),
                    },
                )
                .await
            {
                return false;
            }
            continue;
        }

        let missing_count = state
            .missing_process_counts
            .entry(expected.clone())
            .and_modify(|v| *v += 1)
            .or_insert(1);

        if state.missing_processes.insert(expected.clone())
            && !try_send(
                tx,
                InputEvent::ProcessMissing {
                    host: host_cfg.name.clone(),
                    keyword: expected.clone(),
                    client_id: host_cfg.client_id.clone(),
                },
            )
            .await
        {
            return false;
        }

        if *missing_count >= PROCESS_MISSING_THRESHOLD
            && !maybe_restart_miner(host_cfg, expected, expected, state, timeout_secs, tx).await
        {
            return false;
        }
    }

    true
}

async fn maybe_restart_miner(
    host_cfg: &RemoteHostConfig,
    cooldown_key: &str,
    event_keyword: &str,
    state: &mut HostState,
    timeout_secs: u64,
    tx: &mpsc::Sender<InputEvent>,
) -> bool {
    let Some(command) = host_cfg.restart_command.clone() else {
        return true;
    };

    let cooldown_secs = host_cfg.restart_cooldown_secs.unwrap_or(300);
    let now = Instant::now();

    if let Some(last_at) = state.last_restart_at.get(cooldown_key) {
        if let Some(remaining_secs) = restart_cooldown_remaining_secs(*last_at, now, cooldown_secs)
        {
            return try_send(
                tx,
                InputEvent::ProcessRestartSkippedCooldown {
                    host: host_cfg.name.clone(),
                    keyword: event_keyword.to_string(),
                    cooldown_secs,
                    remaining_secs,
                    client_id: host_cfg.client_id.clone(),
                },
            )
            .await;
        }
    }

    state.last_restart_at.insert(cooldown_key.to_string(), now);

    match run_remote_command(host_cfg, timeout_secs, &command).await {
        Ok(()) => {
            try_send(
                tx,
                InputEvent::ProcessRestartTriggered {
                    host: host_cfg.name.clone(),
                    keyword: event_keyword.to_string(),
                    command,
                    client_id: host_cfg.client_id.clone(),
                },
            )
            .await
        }
        Err(err) => {
            try_send(
                tx,
                InputEvent::ProcessRestartFailed {
                    host: host_cfg.name.clone(),
                    keyword: event_keyword.to_string(),
                    error: err.to_string(),
                    client_id: host_cfg.client_id.clone(),
                },
            )
            .await
        }
    }
}

async fn emit_log_stale_events(
    host_cfg: &RemoteHostConfig,
    logs: &HashMap<PathBuf, Vec<String>>,
    state: &mut HostState,
    timeout_secs: u64,
    stale_threshold_secs: u64,
    tx: &mpsc::Sender<InputEvent>,
) -> bool {
    let Some(latest_ts) = latest_log_timestamp(logs) else {
        return true;
    };

    let mut log_advanced = false;
    match state.last_log_timestamp {
        Some(prev) if latest_ts > prev => {
            state.last_log_timestamp = Some(latest_ts);
            log_advanced = true;
        }
        None => {
            state.last_log_timestamp = Some(latest_ts);
            log_advanced = true;
        }
        _ => {}
    }

    if log_advanced {
        if state.log_stale_alerting {
            if !try_send(
                tx,
                InputEvent::LogRecovered {
                    host: host_cfg.name.clone(),
                    latest_log_timestamp: latest_ts.to_rfc3339(),
                    client_id: host_cfg.client_id.clone(),
                },
            )
            .await
            {
                return false;
            }
            state.log_stale_alerting = false;
        }
        return true;
    }

    let stale_secs = stale_duration_secs(latest_ts, Utc::now());
    if stale_secs < stale_threshold_secs {
        return true;
    }

    if !state.log_stale_alerting {
        if !try_send(
            tx,
            InputEvent::LogStale {
                host: host_cfg.name.clone(),
                stale_threshold_secs,
                stale_secs,
                latest_log_timestamp: latest_ts.to_rfc3339(),
                client_id: host_cfg.client_id.clone(),
            },
        )
        .await
        {
            return false;
        }
        state.log_stale_alerting = true;
    }

    for keyword in &host_cfg.process_keywords {
        let restart_key = format!("log_stale:{keyword}");
        if !maybe_restart_miner(host_cfg, &restart_key, keyword, state, timeout_secs, tx).await {
            return false;
        }
    }

    true
}

fn latest_log_timestamp(logs: &HashMap<PathBuf, Vec<String>>) -> Option<DateTime<Utc>> {
    let mut latest: Option<DateTime<Utc>> = None;

    for lines in logs.values() {
        for line in lines {
            let Some(ts) = extract_log_timestamp(line) else {
                continue;
            };
            match latest {
                Some(current) if ts <= current => {}
                _ => latest = Some(ts),
            }
        }
    }

    latest
}

fn extract_log_timestamp(line: &str) -> Option<DateTime<Utc>> {
    let ParsedLine::Json(json) = parse_line(line) else {
        return None;
    };
    let ts = json.timestamp?;
    chrono::DateTime::parse_from_rfc3339(&ts)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn stale_duration_secs(last_log_ts: DateTime<Utc>, now: DateTime<Utc>) -> u64 {
    now.signed_duration_since(last_log_ts)
        .to_std()
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

async fn emit_log_events(
    host_cfg: &RemoteHostConfig,
    logs: &HashMap<PathBuf, Vec<String>>,
    state: &mut HostState,
    tx: &mpsc::Sender<InputEvent>,
) -> bool {
    for (path, lines) in logs {
        for line in lines {
            let fingerprint = format!("{}|{}|{}", host_cfg.name, path.display(), line);
            if state.remember_seen_log(fingerprint) {
                let remote_path = PathBuf::from(format!("{}:{}", host_cfg.name, path.display()));
                if !try_send(
                    tx,
                    InputEvent::LogLine {
                        path: remote_path,
                        line: line.clone(),
                        node_addr: host_cfg.node_addr.clone(),
                        client_id: host_cfg.client_id.clone(),
                    },
                )
                .await
                {
                    return false;
                }
            }
        }
    }

    true
}

async fn fetch_remote_snapshot(
    host_cfg: &RemoteHostConfig,
    timeout_secs: u64,
    tail_lines: usize,
) -> anyhow::Result<RemoteSnapshot> {
    let marker = format!(
        "__NOSMON_{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );

    let mut script = String::new();
    script.push_str("set -e\n");
    script.push_str(&format!("echo '{}_SCREENS'\n", marker));
    script.push_str("screen -ls 2>/dev/null || true\n");
    script.push_str(&format!("echo '{}_PROCESSES'\n", marker));
    script.push_str("ps -ef 2>/dev/null || true\n");
    for path in &host_cfg.log_paths {
        let escaped = shell_escape(path.to_string_lossy().as_ref());
        script.push_str(&format!("echo '{}_LOG:{}'\n", marker, path.display()));
        script.push_str(&format!(
            "tail -n {} {} 2>/dev/null || true\n",
            tail_lines, escaped
        ));
    }

    let mut cmd = build_ssh_command(host_cfg, timeout_secs);
    cmd.arg("sh").arg("-lc").arg(script);

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs + 2),
        cmd.output(),
    )
    .await
    .context("ssh command timed out")??;

    if !output.status.success() {
        let stderr = truncate_for_error(String::from_utf8_lossy(&output.stderr).trim());
        anyhow::bail!("ssh failed: {}", stderr);
    }

    parse_remote_snapshot(host_cfg, &String::from_utf8_lossy(&output.stdout), &marker)
}

fn parse_remote_snapshot(
    host_cfg: &RemoteHostConfig,
    stdout: &str,
    marker: &str,
) -> anyhow::Result<RemoteSnapshot> {
    let screens_marker = format!("{marker}_SCREENS");
    let processes_marker = format!("{marker}_PROCESSES");
    let log_prefix = format!("{marker}_LOG:");

    let mut section = "";
    let mut current_log: Option<PathBuf> = None;
    let mut screens = HashSet::new();
    let mut process_hits = HashSet::new();
    let mut logs: HashMap<PathBuf, Vec<String>> = HashMap::new();

    for line in stdout.lines() {
        if line == screens_marker {
            section = "screens";
            current_log = None;
            continue;
        }
        if line == processes_marker {
            section = "processes";
            current_log = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix(&log_prefix) {
            section = "log";
            current_log = Some(PathBuf::from(rest));
            continue;
        }

        match section {
            "screens" => {
                for screen_name in &host_cfg.screen_names {
                    if line.contains(screen_name) {
                        screens.insert(screen_name.clone());
                    }
                }
            }
            "processes" => {
                for keyword in &host_cfg.process_keywords {
                    if line.contains(keyword) {
                        process_hits.insert(keyword.clone());
                    }
                }
            }
            "log" => {
                if let Some(path) = &current_log {
                    logs.entry(path.clone()).or_default().push(line.to_string());
                }
            }
            _ => {}
        }
    }

    Ok(RemoteSnapshot {
        screens,
        process_hits,
        logs,
    })
}

fn build_ssh_command(host_cfg: &RemoteHostConfig, timeout_secs: u64) -> Command {
    let mut cmd = if host_cfg.uses_password_auth() {
        let mut cmd = Command::new("sshpass");
        cmd.arg("-e").arg("ssh");
        cmd.env("SSHPASS", host_cfg.password.as_deref().unwrap_or_default());
        cmd
    } else {
        Command::new("ssh")
    };

    cmd.arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg(format!("ConnectTimeout={timeout_secs}"))
        .arg("-p")
        .arg(host_cfg.port.to_string())
        .arg(remote_target(host_cfg));

    cmd
}

fn remote_target(host_cfg: &RemoteHostConfig) -> String {
    match &host_cfg.user {
        Some(user) if !user.is_empty() => format!("{user}@{}", host_cfg.host),
        _ => host_cfg.host.clone(),
    }
}

fn shell_escape(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\\''"))
}

async fn run_remote_command(
    host_cfg: &RemoteHostConfig,
    timeout_secs: u64,
    command: &str,
) -> anyhow::Result<()> {
    let mut cmd = build_ssh_command(host_cfg, timeout_secs);
    cmd.arg("sh").arg("-lc").arg(command);

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs + 2),
        cmd.output(),
    )
    .await
    .context("restart command timed out")??;

    if !output.status.success() {
        let stdout = truncate_for_error(String::from_utf8_lossy(&output.stdout).trim());
        let stderr = truncate_for_error(String::from_utf8_lossy(&output.stderr).trim());
        anyhow::bail!(
            "restart command failed: status={:?}, stdout='{}', stderr='{}'",
            output.status.code(),
            stdout,
            stderr
        );
    }

    Ok(())
}

async fn try_send(tx: &mpsc::Sender<InputEvent>, event: InputEvent) -> bool {
    tx.send(event).await.is_ok()
}

fn restart_cooldown_remaining_secs(
    last_at: Instant,
    now: Instant,
    cooldown_secs: u64,
) -> Option<u64> {
    let elapsed = now.duration_since(last_at).as_secs();
    if elapsed >= cooldown_secs {
        None
    } else {
        Some(cooldown_secs - elapsed)
    }
}

fn truncate_for_error(s: &str) -> String {
    const MAX: usize = 256;
    let mut chars = s.chars();
    let prefix: String = chars.by_ref().take(MAX).collect();
    if chars.next().is_some() {
        format!("{prefix}...")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_log_timestamp, restart_cooldown_remaining_secs, stale_duration_secs};
    use chrono::{Duration as ChronoDuration, Utc};
    use std::time::{Duration, Instant};

    #[test]
    fn cooldown_remaining_is_none_after_cooldown_elapsed() {
        let now = Instant::now();
        let last = now - Duration::from_secs(10);
        assert_eq!(restart_cooldown_remaining_secs(last, now, 5), None);
    }

    #[test]
    fn cooldown_remaining_reports_remaining_seconds() {
        let now = Instant::now();
        let last = now - Duration::from_secs(3);
        assert_eq!(restart_cooldown_remaining_secs(last, now, 10), Some(7));
    }

    #[test]
    fn extracts_json_rfc3339_timestamp() {
        let line = r#"{"level":"info","timestamp":"2026-04-20T16:34:47.964+08:00","msg":"ok"}"#;
        let ts = extract_log_timestamp(line).expect("timestamp should parse");
        assert_eq!(ts.to_rfc3339(), "2026-04-20T08:34:47.964+00:00");
    }

    #[test]
    fn ignores_non_json_timestamp() {
        let line = "plain text without json timestamp";
        assert!(extract_log_timestamp(line).is_none());
    }

    #[test]
    fn stale_duration_boundary() {
        let now = Utc::now();
        let almost_stale = now - ChronoDuration::seconds(119);
        let stale = now - ChronoDuration::seconds(120);

        assert!(stale_duration_secs(almost_stale, now) < 120);
        assert!(stale_duration_secs(stale, now) >= 120);
    }
}
