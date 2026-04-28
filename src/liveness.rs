use crate::config::LivenessConfig;
use crate::detect::InputEvent;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;

#[derive(Default)]
struct LivenessState {
    consecutive_failures: u32,
    consecutive_successes: u32,
    alerting: bool,
}

pub async fn run_liveness_loop(
    addr: String,
    client_id: Option<String>,
    source: Option<String>,
    cfg: LivenessConfig,
    tx: mpsc::Sender<InputEvent>,
) -> anyhow::Result<()> {
    let mut state = LivenessState::default();

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
                state.consecutive_failures = 0;
                state.consecutive_successes += 1;

                if !state.alerting {
                    state.consecutive_successes = 0;
                } else if state.consecutive_successes >= cfg.successes_before_recovery {
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
                    state.alerting = false;
                    state.consecutive_successes = 0;
                }
            }
            Ok(Err(e)) => {
                if !handle_connect_failure(
                    &e.to_string(),
                    &addr,
                    &client_id,
                    &source,
                    &mut state,
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
                    &mut state,
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
    state: &mut LivenessState,
    cfg: &LivenessConfig,
    tx: &mpsc::Sender<InputEvent>,
) -> bool {
    state.consecutive_successes = 0;
    state.consecutive_failures += 1;
    if !state.alerting && state.consecutive_failures >= cfg.failures_before_alert {
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
        state.alerting = true;
        state.consecutive_failures = 0;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> LivenessConfig {
        LivenessConfig {
            interval_secs: 60,
            timeout_ms: 50,
            failures_before_alert: 2,
            successes_before_recovery: 2,
        }
    }

    #[tokio::test]
    async fn emits_node_down_after_threshold_and_resets_failures() {
        let (tx, mut rx) = mpsc::channel(4);
        let mut state = LivenessState::default();
        let cfg = test_cfg();
        let client_id = Some("client-a".to_string());
        let source = Some("ssh://worker-a".to_string());

        assert!(
            handle_connect_failure(
                "connection refused",
                "127.0.0.1:1234",
                &client_id,
                &source,
                &mut state,
                &cfg,
                &tx,
            )
            .await
        );
        assert_eq!(state.consecutive_failures, 1);
        assert!(!state.alerting);
        assert!(rx.try_recv().is_err());

        assert!(
            handle_connect_failure(
                "connection refused",
                "127.0.0.1:1234",
                &client_id,
                &source,
                &mut state,
                &cfg,
                &tx,
            )
            .await
        );

        match rx.recv().await {
            Some(InputEvent::NodeDown {
                addr,
                error,
                client_id,
                source,
            }) => {
                assert_eq!(addr, "127.0.0.1:1234");
                assert_eq!(error, "connection refused");
                assert_eq!(client_id.as_deref(), Some("client-a"));
                assert_eq!(source.as_deref(), Some("ssh://worker-a"));
            }
            other => panic!("unexpected event: {other:?}"),
        }

        assert!(state.alerting);
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.consecutive_successes, 0);
    }

    #[tokio::test]
    async fn closed_channel_returns_false_once_alert_should_fire() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);

        let mut state = LivenessState {
            consecutive_failures: 1,
            ..Default::default()
        };

        let should_continue = handle_connect_failure(
            "connect timeout",
            "10.0.0.2:9000",
            &None,
            &None,
            &mut state,
            &test_cfg(),
            &tx,
        )
        .await;

        assert!(!should_continue);
        assert_eq!(state.consecutive_failures, 2);
        assert!(!state.alerting);
    }
}
