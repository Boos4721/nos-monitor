use crate::config::LivenessConfig;
use crate::detect::InputEvent;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;

pub async fn run_liveness_loop(
    addr: String,
    client_id: Option<String>,
    source: Option<String>,
    cfg: LivenessConfig,
    tx: mpsc::Sender<InputEvent>,
) -> anyhow::Result<()> {
    let mut consecutive_failures = 0u32;
    let mut consecutive_successes = 0u32;
    let mut alerting = false;

    loop {
        let start = Instant::now();
        let res = tokio::time::timeout(
            Duration::from_millis(cfg.timeout_ms),
            TcpStream::connect(&addr),
        )
        .await;

        match res {
            Ok(Ok(_stream)) => {
                let latency_ms = start.elapsed().as_millis();
                consecutive_failures = 0;
                consecutive_successes += 1;

                if !alerting {
                    consecutive_successes = 0;
                } else if consecutive_successes >= cfg.successes_before_recovery {
                    if tx
                        .send(InputEvent::NodeUp {
                            addr: addr.clone(),
                            latency_ms,
                            client_id: client_id.clone(),
                            source: source.clone(),
                        })
                        .await
                        .is_err()
                    {
                        return Ok(());
                    }
                    alerting = false;
                    consecutive_successes = 0;
                }
            }
            Ok(Err(e)) => {
                if !handle_connect_failure(
                    &e.to_string(),
                    &addr,
                    &client_id,
                    &source,
                    &mut consecutive_successes,
                    &mut consecutive_failures,
                    &mut alerting,
                    &cfg,
                    &tx,
                )
                .await
                {
                    return Ok(());
                }
            }
            Err(_) => {
                if !handle_connect_failure(
                    "connect timeout",
                    &addr,
                    &client_id,
                    &source,
                    &mut consecutive_successes,
                    &mut consecutive_failures,
                    &mut alerting,
                    &cfg,
                    &tx,
                )
                .await
                {
                    return Ok(());
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(cfg.interval_secs)).await;
    }
}

/// Returns `false` if the channel is closed and the caller should exit.
async fn handle_connect_failure(
    error: &str,
    addr: &str,
    client_id: &Option<String>,
    source: &Option<String>,
    consecutive_successes: &mut u32,
    consecutive_failures: &mut u32,
    alerting: &mut bool,
    cfg: &LivenessConfig,
    tx: &mpsc::Sender<InputEvent>,
) -> bool {
    *consecutive_successes = 0;
    *consecutive_failures += 1;
    if !*alerting && *consecutive_failures >= cfg.failures_before_alert {
        if tx
            .send(InputEvent::NodeDown {
                addr: addr.to_string(),
                error: error.to_string(),
                client_id: client_id.clone(),
                source: source.clone(),
            })
            .await
            .is_err()
        {
            return false;
        }
        *alerting = true;
        *consecutive_failures = 0;
    }
    true
}
