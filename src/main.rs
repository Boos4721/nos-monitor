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
use std::path::PathBuf;
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
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "log file mutex poisoned"))?;
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
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "log file mutex poisoned"))?;
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
    let base_config_path = args
        .base_config
        .clone()
        .or_else(|| Some(PathBuf::from("/root/nos/config.yaml")));

    let (cfg, cfg_sources) = config::load_configs(args.config.clone(), base_config_path).await?;
    info!(
        monitor_config = ?cfg_sources.monitor_config,
        base_config = ?cfg_sources.base_config,
        client_id = ?cfg.node.client_id,
        ssh_hosts = cfg.ssh.hosts.len(),
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
                    if let Err(e) = liveness::run_liveness_loop(addr, client_id, source, live_cfg, tx).await {
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
    let webhook = if cfg.alert.bark_url.is_empty() {
        None
    } else {
        Some(alert::WebhookClient::new(
            cfg.alert.bark_url.clone(),
            cfg.alert.clone(),
        )?)
    };

    if webhook.is_none() && !cfg.alert.dry_run {
        warn!("alert.bark_url not set; running in print-only mode");
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
                let Some(alert_ev) = detect::detect_event(&cfg, ev) else { continue; };
                if !deduper.should_send(&alert_ev.rule_id, &alert_ev.fingerprint_key) {
                    continue;
                }

                if cfg.alert.dry_run || webhook.is_none() {
                    info!(event_type = %alert_ev.event_type, rule_id = %alert_ev.rule_id, summary = %alert_ev.summary, "ALERT (dry-run/print-only)");
                    continue;
                }

                if let Some(webhook) = webhook.as_ref() {
                    if let Err(e) = webhook.send(&alert_ev).await {
                        error!(error = ?e, "failed to send bark notification");
                    } else {
                        info!(event_type = %alert_ev.event_type, rule_id = %alert_ev.rule_id, "notification sent");
                    }
                }
            }
        }
    }

    Ok(())
}
