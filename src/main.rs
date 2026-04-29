mod alert;
mod config;
mod dedup;
mod detect;
mod liveness;
mod logtail;
mod metrics;
mod rpc;
mod ssh;
mod util;

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

struct TeeWriter {
    file: Arc<Mutex<std::fs::File>>,
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        {
            let mut file = self
                .file
                .lock()
                .map_err(|_| io::Error::other("log file mutex poisoned"))?;
            file.write_all(buf)?;
        }
        io::stdout().write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        {
            let mut file = self
                .file
                .lock()
                .map_err(|_| io::Error::other("log file mutex poisoned"))?;
            file.flush()?;
        }
        io::stdout().flush()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let log_dir = std::env::current_dir()?.join("log");
    fs::create_dir_all(&log_dir)?;
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("nos.log"))?;
    let shared_log_file = Arc::new(Mutex::new(log_file));

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(move || TeeWriter {
            file: Arc::clone(&shared_log_file),
        })
        .init();

    let args = config::CliArgs::from_env();
    let base_config_path = args.base_config.clone().or_else(|| {
        std::env::current_dir()
            .ok()
            .map(|cwd| cwd.join("config.yaml"))
    });

    let (cfg, cfg_sources) = config::load_configs(args.config.clone(), base_config_path).await?;
    info!(
        monitor_config = ?cfg_sources.monitor_config,
        base_config = ?cfg_sources.base_config,
        client_id = ?cfg.node.client_id,
        ssh_hosts = cfg.ssh.hosts.len(),
        ssh_password_hosts = cfg
            .ssh
            .hosts
            .iter()
            .filter(|host| host.uses_password_auth())
            .count(),
        "loaded configuration"
    );

    if !cfg.ssh.hosts.is_empty() {
        for host in &cfg.ssh.hosts {
            let restart_enabled = host
                .restart_command
                .as_ref()
                .map(|cmd| !cmd.trim().is_empty())
                .unwrap_or(false);
            info!(
                host = %host.name,
                restart_enabled,
                restart_cooldown_secs = host.restart_cooldown_secs.unwrap_or(cfg.ssh.restart_cooldown_secs),
                restart_command_configured = host.restart_command.is_some(),
                log_stale_threshold_secs = cfg.ssh.log_stale_threshold_secs,
                "ssh host restart self-check"
            );
        }
    }

    let (tx, mut rx) = mpsc::channel::<detect::InputEvent>(1024);
    let (candidate_tx, candidate_rx) = mpsc::channel::<rpc::PendingCandidate>(256);

    {
        let tx = tx.clone();
        let rpc_cfg = cfg.rpc.clone();
        let client_id = cfg.node.client_id.clone();
        tokio::spawn(async move {
            if let Err(e) = rpc::run_rpc_loop(client_id, rpc_cfg, tx).await {
                error!(error = ?e, "rpc loop exited");
            }
        });
    }

    if cfg.verify.enabled {
        let tx = tx.clone();
        let rpc_cfg = cfg.rpc.clone();
        let verify_cfg = cfg.verify.clone();
        tokio::spawn(async move {
            if let Err(e) = rpc::run_verification_loop(rpc_cfg, verify_cfg, candidate_rx, tx).await
            {
                error!(error = ?e, "verification loop exited");
            }
        });
    } else {
        drop(candidate_rx);
    }

    if cfg.ssh.hosts.is_empty() {
        for path in cfg.logs.paths.iter().cloned() {
            let tx = tx.clone();
            let start_pos = cfg.logs.start_position;
            let node_addr = cfg.node.server_addr.clone();
            let client_id = cfg.node.client_id.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = logtail::follow_file(path, start_pos, node_addr, client_id, tx) {
                    eprintln!("log tailer exited: {e:?}");
                }
            });
        }

        if let Some(addr) = cfg.node.server_addr.clone() {
            let tx = tx.clone();
            let live_cfg = cfg.liveness.clone();
            let client_id = cfg.node.client_id.clone();
            tokio::spawn(async move {
                if let Err(e) = liveness::run_liveness_loop(
                    addr,
                    client_id,
                    Some("local".to_string()),
                    live_cfg,
                    tx,
                )
                .await
                {
                    error!(error = ?e, "liveness loop exited");
                }
            });
        } else {
            warn!("node.server_addr not set; liveness probe disabled");
        }
    } else {
        info!("ssh centralized monitoring enabled");
        for host_cfg in cfg.ssh.hosts.iter().cloned() {
            let tx = tx.clone();
            let interval_secs = cfg.ssh.interval_secs;
            let timeout_secs = cfg.ssh.timeout_secs;
            let tail_lines = cfg.ssh.tail_lines;

            let log_stale_threshold_secs = cfg.ssh.log_stale_threshold_secs;

            if let Some(addr) = host_cfg.node_addr.clone() {
                let tx = tx.clone();
                let live_cfg = cfg.liveness.clone();
                let source = Some(format!("ssh:{}", host_cfg.name));
                let client_id = host_cfg.client_id.clone();
                let host_name = host_cfg.name.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        liveness::run_liveness_loop(addr, client_id, source, live_cfg, tx).await
                    {
                        error!(error = ?e, host = %host_name, "remote node liveness loop exited");
                    }
                });
            }

            tokio::spawn(async move {
                if let Err(e) = ssh::run_ssh_loop(
                    host_cfg,
                    interval_secs,
                    timeout_secs,
                    tail_lines,
                    log_stale_threshold_secs,
                    tx,
                )
                .await
                {
                    error!(error = ?e, "ssh loop exited");
                }
            });
        }
    }

    drop(tx);

    let mut deduper = dedup::Deduper::new(cfg.alert.dedup_window_secs, cfg.alert.cooldown_secs);
    let webhook = if cfg.alert.feishu_webhook_url.is_empty() {
        None
    } else {
        Some(alert::WebhookClient::new(
            cfg.alert.feishu_webhook_url.clone(),
            cfg.alert.clone(),
        )?)
    };

    if webhook.is_none() && !cfg.alert.dry_run {
        warn!("alert.feishu_webhook_url not set; running in print-only mode");
    }

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received");
                break;
            }
            maybe_ev = rx.recv() => {
                let Some(ev) = maybe_ev else { break; };

                if cfg.verify.enabled {
                    if let detect::InputEvent::LogLine { path, line, node_addr, client_id } = &ev {
                        if let Some(candidate) = detect::parse_mining_candidate(line) {
                            let pending = rpc::PendingCandidate {
                                candidate,
                                source_path: Some(path.to_string_lossy().to_string()),
                                node_addr: node_addr.clone(),
                                client_id: client_id.clone().or_else(|| cfg.node.client_id.clone()),
                                first_seen_at: std::time::Instant::now(),
                                attempts: 0,
                            };
                            if candidate_tx.send(pending).await.is_err() {
                                warn!("candidate verification channel closed");
                            }
                        }
                    }
                }

                let Some(alert_ev) = detect::detect_event(&cfg, ev) else { continue; };
                if !deduper.should_send(&alert_ev.fingerprint_key) {
                    continue;
                }

                if cfg.alert.dry_run || webhook.is_none() {
                    info!(event_type = %alert_ev.event_type, rule_id = %alert_ev.rule_id, summary = %alert_ev.summary, "ALERT (dry-run/print-only)");
                    continue;
                }

                if let Some(webhook) = webhook.as_ref() {
                    if let Err(e) = webhook.send(&alert_ev).await {
                        error!(error = ?e, "failed to send feishu notification");
                    } else {
                        info!(event_type = %alert_ev.event_type, rule_id = %alert_ev.rule_id, "notification sent");
                    }
                }
            }
        }
    }

    Ok(())
}
