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

#[derive(Debug, Clone, Deserialize)]
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

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            node: NodeConfig::default(),
            rpc: RpcConfig::default(),
            logs: LogsConfig::default(),
            detect: DetectConfig::default(),
            alert: AlertConfig::default(),
            liveness: LivenessConfig::default(),
            ssh: SshConfig::default(),
            verify: VerifyConfig::default(),
        }
    }
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

#[derive(Debug, Copy, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartPosition {
    End,
    Beginning,
}

impl Default for StartPosition {
    fn default() -> Self {
        StartPosition::End
    }
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
    #[serde(default = "default_bark_url", alias = "webhook_url")]
    pub bark_url: String,
    #[serde(default, alias = "group")]
    pub bark_group: Option<String>,
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

fn default_bark_url() -> String {
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
            bark_url: default_bark_url(),
            bark_group: None,
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
            hosts: Vec::new(),
        }
    }
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

    if mon_cfg.alert.bark_url.trim().is_empty() {
        mon_cfg.alert.bark_url = std::env::var("BARK_URL").unwrap_or_default();
    }

    for host in &mut mon_cfg.ssh.hosts {
        host.log_paths = fixed_remote_log_paths();
        host.screen_names = fixed_screen_names();
        host.process_keywords = fixed_process_keywords();
        host.client_id = None;

        if host.node_addr.is_none() {
            host.node_addr = mon_cfg.node.server_addr.clone();
        }
        if host.restart_cooldown_secs.is_none() {
            host.restart_cooldown_secs = Some(mon_cfg.ssh.restart_cooldown_secs);
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
