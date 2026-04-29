use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct CliArgs {
    pub config: Option<PathBuf>,
    pub base_config: Option<PathBuf>,
}

impl CliArgs {
    pub fn from_env() -> Self {
        let mut args = std::env::args().skip(1);
        let mut config = None;
        let mut base_config = None;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--config" | "-c" => config = args.next().map(PathBuf::from),
                "--base-config" | "-f" => base_config = args.next().map(PathBuf::from),
                "-h" | "--help" => print_help_and_exit(),
                _ => {
                    eprintln!("unknown argument: {arg}");
                    print_help_and_exit();
                }
            }
        }

        Self {
            config,
            base_config,
        }
    }
}

fn print_help_and_exit() -> ! {
    eprintln!(
        "Usage: nos-monitor [-c|--config <monitor.yaml>] [-f|--base-config <config.yaml>]\n\n\
         If --base-config is not provided, defaults to $PWD/config.yaml when present.\n"
    );
    std::process::exit(2)
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NosConfigFile {
    #[serde(default)]
    pub config: BaseConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BaseConfig {
    pub server_addr: Option<String>,
    pub client_id: Option<String>,
    pub metrics_port: Option<u16>,
    pub retry_times: Option<u32>,
    pub retry_delay: Option<u64>,
    pub log_level: Option<String>,
}

impl BaseConfig {
    fn is_empty(&self) -> bool {
        self.server_addr.is_none()
            && self.client_id.is_none()
            && self.metrics_port.is_none()
            && self.retry_times.is_none()
            && self.retry_delay.is_none()
            && self.log_level.is_none()
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MonitorConfig {
    #[serde(default)]
    pub node: NodeConfig,
    #[serde(default)]
    pub rpc: RpcConfig,
    #[serde(default)]
    pub logs: LogsConfig,
    #[serde(default)]
    pub detect: DetectConfig,
    #[serde(default)]
    pub alert: AlertConfig,
    #[serde(default)]
    pub liveness: LivenessConfig,
    #[serde(default)]
    pub ssh: SshConfig,
    #[serde(default)]
    pub verify: VerifyConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NodeConfig {
    pub server_addr: Option<String>,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RpcConfig {
    #[serde(default = "default_rpc_endpoints")]
    pub endpoints: Vec<String>,
    #[serde(default = "default_rpc_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_rpc_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_stall_threshold_secs")]
    pub stall_threshold_secs: u64,
    #[serde(default = "default_rpc_failures_before_alert")]
    pub failures_before_alert: u32,
    #[serde(default = "default_rpc_successes_before_recovery")]
    pub successes_before_recovery: u32,
}

fn default_rpc_endpoints() -> Vec<String> {
    vec![
        "https://www.kortho-chain.com".to_string(),
        "https://www.kortho-chain.cc".to_string(),
        "https://www.kortho-chain.pro".to_string(),
        "https://rpc.noschain.org".to_string(),
    ]
}

fn default_rpc_interval_secs() -> u64 {
    15
}

fn default_rpc_timeout_ms() -> u64 {
    5_000
}

fn default_stall_threshold_secs() -> u64 {
    180
}

fn default_rpc_failures_before_alert() -> u32 {
    3
}

fn default_rpc_successes_before_recovery() -> u32 {
    2
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            endpoints: default_rpc_endpoints(),
            interval_secs: default_rpc_interval_secs(),
            timeout_ms: default_rpc_timeout_ms(),
            stall_threshold_secs: default_stall_threshold_secs(),
            failures_before_alert: default_rpc_failures_before_alert(),
            successes_before_recovery: default_rpc_successes_before_recovery(),
        }
    }
}

#[derive(Debug, Copy, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartPosition {
    #[default]
    End,
    Beginning,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogsConfig {
    #[serde(default = "default_log_paths")]
    pub paths: Vec<PathBuf>,
    #[serde(default)]
    pub start_position: StartPosition,
}

fn default_log_paths() -> Vec<PathBuf> {
    vec![PathBuf::from("/root/nos/logs/miner-client.log")]
}

impl Default for LogsConfig {
    fn default() -> Self {
        Self {
            paths: default_log_paths(),
            start_position: StartPosition::End,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DetectConfig {
    #[serde(default = "default_block_fail")]
    pub block_fail_keywords: Vec<String>,
    #[serde(default = "default_secondary_keywords")]
    pub secondary_keywords: Vec<String>,
    #[serde(default = "default_suppress_patterns")]
    pub suppress_patterns: Vec<String>,
}

fn default_block_fail() -> Vec<String> {
    vec![
        "出块失败".to_string(),
        "爆块失败".to_string(),
        "submit failed".to_string(),
        "send result failed".to_string(),
        "invalid block".to_string(),
        "reject".to_string(),
        "share rejected".to_string(),
        "mining error".to_string(),
        "task failed".to_string(),
    ]
}

fn default_secondary_keywords() -> Vec<String> {
    vec![
        "mine".to_string(),
        "block".to_string(),
        "result".to_string(),
        "share".to_string(),
        "submit".to_string(),
        "爆块".to_string(),
        "出块".to_string(),
    ]
}

fn default_suppress_patterns() -> Vec<String> {
    vec![
        "Config File \"config\" Not Found".to_string(),
        "bind: address already in use".to_string(),
        "启动metrics服务器失败".to_string(),
    ]
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            block_fail_keywords: default_block_fail(),
            secondary_keywords: default_secondary_keywords(),
            suppress_patterns: default_suppress_patterns(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_verify_confirmations")]
    pub confirmations: u64,
    #[serde(default = "default_verify_backtrack_blocks")]
    pub backtrack_blocks: u64,
    #[serde(default = "default_verify_forward_blocks")]
    pub forward_blocks: u64,
    #[serde(default = "default_verify_pending_ttl_secs")]
    pub pending_ttl_secs: u64,
    #[serde(default = "default_verify_poll_interval_secs")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_primary_contracts")]
    pub primary_contracts: Vec<String>,
    #[serde(default = "default_auxiliary_contracts")]
    pub auxiliary_contracts: Vec<String>,
}

fn default_verify_confirmations() -> u64 {
    2
}

fn default_verify_backtrack_blocks() -> u64 {
    2
}

fn default_verify_forward_blocks() -> u64 {
    12
}

fn default_verify_pending_ttl_secs() -> u64 {
    1800
}

fn default_verify_poll_interval_secs() -> u64 {
    15
}

fn default_primary_contracts() -> Vec<String> {
    vec![
        "0x79cCCa31e6F352913A7EBeC89d3e416F0D543378".to_string(),
        "0xbDe68c62E7De38C55d5675D6D2237a17cE285B3E".to_string(),
    ]
}

fn default_auxiliary_contracts() -> Vec<String> {
    vec![
        "0x52Adcc498489C9994B806aE7BB75b28d760848aD".to_string(),
        "0xf8d9f519255885a9d856ee1c6537ef01323cf970".to_string(),
    ]
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            confirmations: default_verify_confirmations(),
            backtrack_blocks: default_verify_backtrack_blocks(),
            forward_blocks: default_verify_forward_blocks(),
            pending_ttl_secs: default_verify_pending_ttl_secs(),
            poll_interval_secs: default_verify_poll_interval_secs(),
            primary_contracts: default_primary_contracts(),
            auxiliary_contracts: default_auxiliary_contracts(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlertConfig {
    #[serde(
        default = "default_feishu_webhook_url",
        alias = "webhook_url",
        alias = "bark_url"
    )]
    pub feishu_webhook_url: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_retry_max")]
    pub retry_max_attempts: u32,
    #[serde(default = "default_retry_base_delay_ms")]
    pub retry_base_delay_ms: u64,
    #[serde(default = "default_retry_max_delay_ms")]
    pub retry_max_delay_ms: u64,
    #[serde(default = "default_dedup_window")]
    pub dedup_window_secs: u64,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_max_raw")]
    pub max_raw_bytes: usize,
}

fn default_feishu_webhook_url() -> String {
    String::new()
}

fn default_timeout_ms() -> u64 {
    5_000
}

fn default_retry_max() -> u32 {
    5
}

fn default_retry_base_delay_ms() -> u64 {
    500
}

fn default_retry_max_delay_ms() -> u64 {
    10_000
}

fn default_dedup_window() -> u64 {
    900
}

fn default_cooldown() -> u64 {
    300
}

fn default_max_raw() -> usize {
    8 * 1024
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            feishu_webhook_url: default_feishu_webhook_url(),
            timeout_ms: default_timeout_ms(),
            retry_max_attempts: default_retry_max(),
            retry_base_delay_ms: default_retry_base_delay_ms(),
            retry_max_delay_ms: default_retry_max_delay_ms(),
            dedup_window_secs: default_dedup_window(),
            cooldown_secs: default_cooldown(),
            dry_run: false,
            max_raw_bytes: default_max_raw(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LivenessConfig {
    #[serde(default = "default_liveness_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_liveness_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_failures_before_alert")]
    pub failures_before_alert: u32,
    #[serde(default = "default_successes_before_recovery")]
    pub successes_before_recovery: u32,
}

fn default_liveness_interval() -> u64 {
    15
}

fn default_liveness_timeout() -> u64 {
    1_500
}

fn default_failures_before_alert() -> u32 {
    3
}

fn default_successes_before_recovery() -> u32 {
    2
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_liveness_interval(),
            timeout_ms: default_liveness_timeout(),
            failures_before_alert: default_failures_before_alert(),
            successes_before_recovery: default_successes_before_recovery(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SshConfig {
    #[serde(default = "default_ssh_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_ssh_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_ssh_tail_lines")]
    pub tail_lines: usize,
    #[serde(default = "default_restart_cooldown_secs")]
    pub restart_cooldown_secs: u64,
    #[serde(default = "default_log_stale_threshold_secs")]
    pub log_stale_threshold_secs: u64,
    #[serde(default)]
    pub defaults: SshHostDefaults,
    #[serde(default)]
    pub ranges: Vec<RemoteHostRangeConfig>,
    #[serde(default)]
    pub hosts: Vec<RemoteHostConfig>,
}

fn default_ssh_interval_secs() -> u64 {
    15
}

fn default_ssh_timeout_secs() -> u64 {
    8
}

fn default_ssh_tail_lines() -> usize {
    20
}

fn default_restart_cooldown_secs() -> u64 {
    300
}

fn default_log_stale_threshold_secs() -> u64 {
    120
}
impl Default for SshConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_ssh_interval_secs(),
            timeout_secs: default_ssh_timeout_secs(),
            tail_lines: default_ssh_tail_lines(),
            restart_cooldown_secs: default_restart_cooldown_secs(),
            log_stale_threshold_secs: default_log_stale_threshold_secs(),
            defaults: SshHostDefaults::default(),
            ranges: Vec::new(),
            hosts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct SshHostDefaults {
    pub user: Option<String>,
    pub password: Option<String>,
    pub restart_command: Option<String>,
    pub restart_cooldown_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteHostConfig {
    pub name: String,
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub log_paths: Vec<PathBuf>,
    #[serde(default)]
    pub screen_names: Vec<String>,
    #[serde(default)]
    pub process_keywords: Vec<String>,
    pub restart_command: Option<String>,
    pub restart_cooldown_secs: Option<u64>,
    pub node_addr: Option<String>,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RemoteHostRangeConfig {
    pub name_prefix: Option<String>,
    pub ips: Option<String>,
    #[serde(default)]
    pub start: String,
    #[serde(default)]
    pub end: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub restart_command: Option<String>,
    pub restart_cooldown_secs: Option<u64>,
    pub node_addr: Option<String>,
}

impl RemoteHostConfig {
    pub fn uses_password_auth(&self) -> bool {
        self.password
            .as_ref()
            .map(|password| !password.trim().is_empty())
            .unwrap_or(false)
    }
}

fn default_ssh_port() -> u16 {
    22
}

fn fixed_remote_log_paths() -> Vec<PathBuf> {
    vec![PathBuf::from("~/logs/miner-client.log")]
}

fn fixed_screen_names() -> Vec<String> {
    vec!["nos".to_string()]
}

fn fixed_process_keywords() -> Vec<String> {
    vec!["nospowcli".to_string()]
}

#[derive(Debug, Clone)]
pub struct ResolvedConfigSources {
    pub monitor_config: Option<PathBuf>,
    pub base_config: Option<PathBuf>,
}

pub async fn load_configs(
    monitor_path: Option<PathBuf>,
    base_path: Option<PathBuf>,
) -> anyhow::Result<(MonitorConfig, ResolvedConfigSources)> {
    let base_cfg = match base_path.as_deref() {
        Some(p) if p.exists() => Some(load_nos_base_config(p)?),
        _ => None,
    };

    let mut mon_cfg = match monitor_path.as_deref() {
        Some(p) => load_monitor_yaml(p)?,
        None => MonitorConfig::default(),
    };

    if mon_cfg.node.server_addr.is_none() {
        mon_cfg.node.server_addr = base_cfg.as_ref().and_then(|b| b.server_addr.clone());
    }

    if mon_cfg.alert.feishu_webhook_url.trim().is_empty() {
        mon_cfg.alert.feishu_webhook_url = std::env::var("FEISHU_WEBHOOK_URL")
            .or_else(|_| std::env::var("BARK_URL"))
            .unwrap_or_default();
    }

    let shared_ssh_defaults = resolve_shared_ssh_defaults(&mon_cfg.ssh.defaults);
    let expanded_range_hosts = expand_ssh_host_ranges(&mon_cfg.ssh.ranges)?;
    mon_cfg.ssh.hosts.extend(expanded_range_hosts);

    for host in &mut mon_cfg.ssh.hosts {
        host.log_paths = fixed_remote_log_paths();
        host.screen_names = fixed_screen_names();
        host.process_keywords = fixed_process_keywords();
        host.client_id = None;

        host.user = first_non_empty(host.user.take(), shared_ssh_defaults.user.clone());
        host.password = first_non_empty(host.password.take(), shared_ssh_defaults.password.clone());
        host.restart_command = first_non_empty(
            host.restart_command.take(),
            shared_ssh_defaults.restart_command.clone(),
        );

        if host.node_addr.is_none() {
            host.node_addr = mon_cfg.node.server_addr.clone();
        }
        if host.restart_cooldown_secs.is_none() {
            host.restart_cooldown_secs = shared_ssh_defaults
                .restart_cooldown_secs
                .or(Some(mon_cfg.ssh.restart_cooldown_secs));
        }
    }

    Ok((
        mon_cfg,
        ResolvedConfigSources {
            monitor_config: monitor_path,
            base_config: base_path,
        },
    ))
}

fn load_nos_base_config(path: &Path) -> anyhow::Result<BaseConfig> {
    let bytes = std::fs::read(path)?;

    if let Ok(val) = serde_yaml::from_slice::<NosConfigFile>(&bytes) {
        if !val.config.is_empty() {
            return Ok(val.config);
        }
    }

    let val = serde_yaml::from_slice::<BaseConfig>(&bytes)?;
    Ok(val)
}

fn load_monitor_yaml(path: &Path) -> anyhow::Result<MonitorConfig> {
    let bytes = std::fs::read(path)?;
    let val = serde_yaml::from_slice::<serde_yaml::Value>(&bytes)?;

    if let Some(m) = val.get("monitor") {
        Ok(serde_yaml::from_value::<MonitorConfig>(m.clone())?)
    } else {
        Ok(serde_yaml::from_value::<MonitorConfig>(val)?)
    }
}

fn resolve_shared_ssh_defaults(defaults: &SshHostDefaults) -> SshHostDefaults {
    SshHostDefaults {
        user: env_ssh_value("NOS_MONITOR_SSH_USER").or_else(|| defaults.user.clone()),
        password: env_ssh_value("NOS_MONITOR_SSH_PASSWORD").or_else(|| defaults.password.clone()),
        restart_command: normalize_optional_string(defaults.restart_command.clone()),
        restart_cooldown_secs: defaults.restart_cooldown_secs,
    }
}

fn expand_ssh_host_ranges(
    ranges: &[RemoteHostRangeConfig],
) -> anyhow::Result<Vec<RemoteHostConfig>> {
    let mut hosts = Vec::new();

    for range in ranges {
        hosts.extend(expand_ssh_host_range(range)?);
    }

    Ok(hosts)
}

fn expand_ssh_host_range(range: &RemoteHostRangeConfig) -> anyhow::Result<Vec<RemoteHostConfig>> {
    let (start, end) = resolve_range_bounds(range)?;

    anyhow::ensure!(
        start <= end,
        "ssh range start must be <= end: {} > {}",
        format_ipv4_addr(start),
        format_ipv4_addr(end)
    );

    let prefix = normalize_optional_string(range.name_prefix.clone())
        .unwrap_or_else(|| default_range_name_prefix(start, end));

    let mut hosts = Vec::new();
    for current in start..=end {
        let ip = format_ipv4_addr(current);
        let suffix = current & 0xff;
        hosts.push(RemoteHostConfig {
            name: format!("{}-{}", prefix, suffix),
            host: ip,
            port: range.port,
            user: range.user.clone(),
            password: range.password.clone(),
            log_paths: Vec::new(),
            screen_names: Vec::new(),
            process_keywords: Vec::new(),
            restart_command: range.restart_command.clone(),
            restart_cooldown_secs: range.restart_cooldown_secs,
            node_addr: range.node_addr.clone(),
            client_id: None,
        });
    }

    Ok(hosts)
}

fn resolve_range_bounds(range: &RemoteHostRangeConfig) -> anyhow::Result<(u32, u32)> {
    if let Some(ips) = normalize_optional_string(range.ips.clone()) {
        return parse_ipv4_range_expr(&ips);
    }

    anyhow::ensure!(
        !range.start.trim().is_empty() && !range.end.trim().is_empty(),
        "ssh range requires either ips or both start/end"
    );

    Ok((parse_ipv4_addr(&range.start)?, parse_ipv4_addr(&range.end)?))
}

fn parse_ipv4_range_expr(value: &str) -> anyhow::Result<(u32, u32)> {
    let (start_raw, end_raw) = value
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("invalid ssh ips range: {value}"))?;

    let start_raw = start_raw.trim();
    let end_raw = end_raw.trim();
    let start = parse_ipv4_addr(start_raw)?;

    let end = if end_raw.contains('.') {
        parse_ipv4_addr(end_raw)?
    } else {
        let octet = end_raw
            .parse::<u8>()
            .map_err(|_| anyhow::anyhow!("invalid ssh ips range end octet: {value}"))?;
        let start_octets = std::net::Ipv4Addr::from(start).octets();
        u32::from(std::net::Ipv4Addr::new(
            start_octets[0],
            start_octets[1],
            start_octets[2],
            octet,
        ))
    };

    Ok((start, end))
}

fn parse_ipv4_addr(value: &str) -> anyhow::Result<u32> {
    let addr: std::net::Ipv4Addr = value
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IPv4 address in ssh range: {value}"))?;
    Ok(u32::from(addr))
}

fn format_ipv4_addr(value: u32) -> String {
    std::net::Ipv4Addr::from(value).to_string()
}

fn default_range_name_prefix(start: u32, end: u32) -> String {
    let start_octets = std::net::Ipv4Addr::from(start).octets();
    let end_octets = std::net::Ipv4Addr::from(end).octets();

    if start_octets[..3] == end_octets[..3] {
        format!(
            "{}-{}-{}",
            start_octets[0], start_octets[1], start_octets[2]
        )
    } else {
        format!(
            "{}-{}-{}-{}",
            start_octets[0], start_octets[1], start_octets[2], start_octets[3]
        )
    }
}

fn env_ssh_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .and_then(|value| normalize_optional_string(Some(value)))
}

fn first_non_empty(primary: Option<String>, fallback: Option<String>) -> Option<String> {
    normalize_optional_string(primary).or_else(|| normalize_optional_string(fallback))
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            // SAFETY: Tests are short-lived and this helper restores the original value on drop.
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            // SAFETY: Tests are short-lived and this helper restores the original env state on drop.
            unsafe { std::env::remove_var(key) };
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.as_ref() {
                Some(value) => {
                    // SAFETY: Restores the exact prior process environment value captured by the guard.
                    unsafe { std::env::set_var(self.key, value) };
                }
                None => {
                    // SAFETY: Restores the absence of the env var captured by the guard.
                    unsafe { std::env::remove_var(self.key) };
                }
            }
        }
    }

    #[test]
    fn load_nos_base_config_supports_nested_config_shape() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        fs::write(
            &path,
            "config:\n  server_addr: 1.2.3.4:5678\n  client_id: miner-01\n  metrics_port: 9200\n",
        )
        .unwrap();

        let cfg = load_nos_base_config(&path).unwrap();
        assert_eq!(cfg.server_addr.as_deref(), Some("1.2.3.4:5678"));
        assert_eq!(cfg.client_id.as_deref(), Some("miner-01"));
        assert_eq!(cfg.metrics_port, Some(9200));
    }

    #[test]
    fn load_nos_base_config_falls_back_to_flat_shape() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        fs::write(
            &path,
            "server_addr: 127.0.0.1:7000\nclient_id: flat-client\nlog_level: debug\n",
        )
        .unwrap();

        let cfg = load_nos_base_config(&path).unwrap();
        assert_eq!(cfg.server_addr.as_deref(), Some("127.0.0.1:7000"));
        assert_eq!(cfg.client_id.as_deref(), Some("flat-client"));
        assert_eq!(cfg.log_level.as_deref(), Some("debug"));
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn load_configs_applies_base_env_and_ssh_defaults() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("config.yaml");
        let monitor_path = dir.path().join("monitor.yaml");

        fs::write(
            &base_path,
            "config:\n  server_addr: 10.0.0.1:1234\n  client_id: base-client\n",
        )
        .unwrap();
        fs::write(
            &monitor_path,
            "monitor:\n  ssh:\n    restart_cooldown_secs: 77\n    hosts:\n      - name: worker-a\n        host: 192.168.1.10\n",
        )
        .unwrap();

        let guard = EnvVarGuard::set("FEISHU_WEBHOOK_URL", "https://example.invalid/webhook");

        let (cfg, sources) = load_configs(Some(monitor_path.clone()), Some(base_path.clone()))
            .await
            .unwrap();

        drop(guard);

        assert_eq!(sources.monitor_config, Some(monitor_path));
        assert_eq!(sources.base_config, Some(base_path));
        assert_eq!(cfg.node.server_addr.as_deref(), Some("10.0.0.1:1234"));
        assert_eq!(
            cfg.alert.feishu_webhook_url,
            "https://example.invalid/webhook"
        );
        assert_eq!(cfg.ssh.hosts.len(), 1);
        let host = &cfg.ssh.hosts[0];
        assert_eq!(host.node_addr.as_deref(), Some("10.0.0.1:1234"));
        assert_eq!(host.restart_cooldown_secs, Some(77));
        assert_eq!(host.client_id, None);
        assert_eq!(host.log_paths, fixed_remote_log_paths());
        assert_eq!(host.screen_names, fixed_screen_names());
        assert_eq!(host.process_keywords, fixed_process_keywords());
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn load_configs_applies_ssh_defaults_and_env_overrides() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let monitor_path = dir.path().join("monitor.yaml");

        fs::write(
            &monitor_path,
            "monitor:\n  ssh:\n    defaults:\n      user: shared-user\n      password: shared-pass\n      restart_command: \"cd ~ && ./restart-nos.sh\"\n      restart_cooldown_secs: 123\n    hosts:\n      - name: worker-a\n        host: 192.168.1.10\n      - name: worker-b\n        host: 192.168.1.11\n        user: explicit-user\n        password: explicit-pass\n        restart_command: \"systemctl restart nos\"\n        restart_cooldown_secs: 456\n",
        )
        .unwrap();

        let env_user = EnvVarGuard::set("NOS_MONITOR_SSH_USER", "env-user");
        let env_password = EnvVarGuard::set("NOS_MONITOR_SSH_PASSWORD", "env-pass");

        let (cfg, _) = load_configs(Some(monitor_path), None).await.unwrap();

        drop(env_user);
        drop(env_password);

        assert_eq!(cfg.ssh.hosts.len(), 2);
        assert_eq!(cfg.ssh.hosts[0].user.as_deref(), Some("env-user"));
        assert_eq!(cfg.ssh.hosts[0].password.as_deref(), Some("env-pass"));
        assert_eq!(
            cfg.ssh.hosts[0].restart_command.as_deref(),
            Some("cd ~ && ./restart-nos.sh")
        );
        assert_eq!(cfg.ssh.hosts[0].restart_cooldown_secs, Some(123));
        assert_eq!(cfg.ssh.hosts[1].user.as_deref(), Some("explicit-user"));
        assert_eq!(cfg.ssh.hosts[1].password.as_deref(), Some("explicit-pass"));
        assert_eq!(
            cfg.ssh.hosts[1].restart_command.as_deref(),
            Some("systemctl restart nos")
        );
        assert_eq!(cfg.ssh.hosts[1].restart_cooldown_secs, Some(456));
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn load_configs_treats_blank_ssh_credentials_as_missing() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let monitor_path = dir.path().join("monitor.yaml");

        fs::write(
            &monitor_path,
            "monitor:\n  ssh:\n    defaults:\n      user: \"   \"\n      password: \"\"\n    hosts:\n      - name: worker-a\n        host: 192.168.1.10\n        user: \" \"\n        password: \"   \"\n",
        )
        .unwrap();

        let env_user = EnvVarGuard::remove("NOS_MONITOR_SSH_USER");
        let env_password = EnvVarGuard::remove("NOS_MONITOR_SSH_PASSWORD");

        let (cfg, _) = load_configs(Some(monitor_path), None).await.unwrap();

        drop(env_user);
        drop(env_password);

        assert_eq!(cfg.ssh.hosts[0].user, None);
        assert_eq!(cfg.ssh.hosts[0].password, None);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn load_configs_applies_shared_restart_defaults() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let monitor_path = dir.path().join("monitor.yaml");

        fs::write(
            &monitor_path,
            "monitor:\n  ssh:\n    restart_cooldown_secs: 300\n    defaults:\n      restart_command: \"screen -S nos -X quit; cd ~ && screen -dmS nos ./nospowcli\"\n      restart_cooldown_secs: 222\n    hosts:\n      - name: worker-a\n        host: 192.168.1.10\n      - name: worker-b\n        host: 192.168.1.11\n        restart_command: \"systemctl restart nos\"\n      - name: worker-c\n        host: 192.168.1.12\n        restart_cooldown_secs: 444\n",
        )
        .unwrap();

        let (cfg, _) = load_configs(Some(monitor_path), None).await.unwrap();

        assert_eq!(
            cfg.ssh.hosts[0].restart_command.as_deref(),
            Some("screen -S nos -X quit; cd ~ && screen -dmS nos ./nospowcli")
        );
        assert_eq!(cfg.ssh.hosts[0].restart_cooldown_secs, Some(222));
        assert_eq!(
            cfg.ssh.hosts[1].restart_command.as_deref(),
            Some("systemctl restart nos")
        );
        assert_eq!(cfg.ssh.hosts[1].restart_cooldown_secs, Some(222));
        assert_eq!(
            cfg.ssh.hosts[2].restart_command.as_deref(),
            Some("screen -S nos -X quit; cd ~ && screen -dmS nos ./nospowcli")
        );
        assert_eq!(cfg.ssh.hosts[2].restart_cooldown_secs, Some(444));
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn load_configs_expands_ssh_ranges_with_defaults_and_overrides() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let monitor_path = dir.path().join("monitor.yaml");

        fs::write(
            &monitor_path,
            "monitor:\n  node:\n    server_addr: 10.0.0.1:1234\n  ssh:\n    restart_cooldown_secs: 300\n    defaults:\n      user: shared-user\n      password: shared-pass\n      restart_command: \"shared-restart\"\n      restart_cooldown_secs: 222\n    ranges:\n      - name_prefix: rack-a\n        ips: 192.168.10.20-22\n      - ips: 192.168.20.5-192.168.20.6\n        user: range-user\n        restart_command: \"range-restart\"\n        restart_cooldown_secs: 444\n    hosts:\n      - name: worker-a\n        host: 192.168.30.10\n",
        )
        .unwrap();

        let (cfg, _) = load_configs(Some(monitor_path), None).await.unwrap();

        assert_eq!(cfg.ssh.hosts.len(), 6);

        assert_eq!(cfg.ssh.hosts[0].name, "worker-a");

        assert_eq!(cfg.ssh.hosts[1].name, "rack-a-20");
        assert_eq!(cfg.ssh.hosts[1].host, "192.168.10.20");
        assert_eq!(cfg.ssh.hosts[1].user.as_deref(), Some("shared-user"));
        assert_eq!(cfg.ssh.hosts[1].password.as_deref(), Some("shared-pass"));
        assert_eq!(
            cfg.ssh.hosts[1].restart_command.as_deref(),
            Some("shared-restart")
        );
        assert_eq!(cfg.ssh.hosts[1].restart_cooldown_secs, Some(222));
        assert_eq!(cfg.ssh.hosts[1].node_addr.as_deref(), Some("10.0.0.1:1234"));

        assert_eq!(cfg.ssh.hosts[4].name, "192-168-20-5");
        assert_eq!(cfg.ssh.hosts[4].user.as_deref(), Some("range-user"));
        assert_eq!(cfg.ssh.hosts[4].password.as_deref(), Some("shared-pass"));
        assert_eq!(
            cfg.ssh.hosts[4].restart_command.as_deref(),
            Some("range-restart")
        );
        assert_eq!(cfg.ssh.hosts[4].restart_cooldown_secs, Some(444));
    }

    #[test]
    fn expand_ssh_host_range_rejects_descending_ranges() {
        let range = RemoteHostRangeConfig {
            ips: Some("192.168.1.10-9".to_string()),
            ..Default::default()
        };

        let err = expand_ssh_host_range(&range).unwrap_err();
        assert!(err.to_string().contains("start must be <= end"));
    }

    #[test]
    fn expand_ssh_host_range_supports_start_end_fields() {
        let range = RemoteHostRangeConfig {
            start: "192.168.1.10".to_string(),
            end: "192.168.1.11".to_string(),
            ..Default::default()
        };

        let hosts = expand_ssh_host_range(&range).unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].host, "192.168.1.10");
        assert_eq!(hosts[1].host, "192.168.1.11");
    }

    #[test]
    fn expand_ssh_host_range_supports_single_host_ranges() {
        let range = RemoteHostRangeConfig {
            ips: Some("192.168.5.9-9".to_string()),
            ..Default::default()
        };

        let hosts = expand_ssh_host_range(&range).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].name, "192-168-5-9");
        assert_eq!(hosts[0].host, "192.168.5.9");
    }

    #[test]
    fn expand_ssh_host_range_uses_stable_names_across_subnets() {
        let range = RemoteHostRangeConfig {
            ips: Some("192.168.5.254-192.168.6.1".to_string()),
            ..Default::default()
        };

        let hosts = expand_ssh_host_range(&range).unwrap();
        assert_eq!(hosts.len(), 4);
        assert_eq!(hosts[0].name, "192-168-5-254-254");
        assert_eq!(hosts[1].name, "192-168-5-254-255");
        assert_eq!(hosts[2].name, "192-168-5-254-0");
        assert_eq!(hosts[3].name, "192-168-5-254-1");
    }

    #[test]
    fn expand_ssh_host_range_rejects_invalid_ipv4_addresses() {
        let range = RemoteHostRangeConfig {
            ips: Some("192.168.1.999-192.168.2.1".to_string()),
            ..Default::default()
        };

        let err = expand_ssh_host_range(&range).unwrap_err();
        assert!(err.to_string().contains("invalid IPv4 address"));
    }

    #[test]
    fn load_monitor_yaml_supports_nested_monitor_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("monitor.yaml");
        fs::write(
            &path,
            "monitor:\n  liveness:\n    failures_before_alert: 5\n  alert:\n    webhook_url: https://example.invalid/alias\n",
        )
        .unwrap();

        let cfg = load_monitor_yaml(&path).unwrap();
        assert_eq!(cfg.liveness.failures_before_alert, 5);
        assert_eq!(
            cfg.alert.feishu_webhook_url,
            "https://example.invalid/alias"
        );
    }
}
