use crate::config::RpcConfig;
use crate::detect::InputEvent;
use crate::util::{duration_since_block, parse_block_timestamp_secs, parse_hex_u64, BlockHeader, RpcEnvelope};
use anyhow::Context;
use chrono::Utc;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use tokio::sync::mpsc;

pub async fn run_rpc_loop(
    client_id: Option<String>,
    cfg: RpcConfig,
    tx: mpsc::Sender<InputEvent>,
) -> anyhow::Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_millis(cfg.timeout_ms))
        .build()?;

    let mut last_height: Option<u64> = None;
    let mut last_change_at = Utc::now();
    let mut stall_alerting = false;
    let mut rpc_alerting = false;
    let mut consecutive_rpc_failures = 0u32;
    let mut consecutive_rpc_successes = 0u32;

    loop {
        let mut success = false;
        let mut last_error = None;

        for endpoint in &cfg.endpoints {
            match fetch_latest_block(&client, endpoint).await {
                Ok((height, block_ts_secs, latency_ms)) => {
                    let now = Utc::now();
                    let block_age_secs = duration_since_block(now, block_ts_secs)
                        .map(|d| d.as_secs())
                        .unwrap_or_default();

                    if last_height != Some(height) {
                        last_height = Some(height);
                        last_change_at = now;
                    }

                    let stall_secs = now
                        .signed_duration_since(last_change_at)
                        .to_std()
                        .map(|d| d.as_secs())
                        .unwrap_or_default();

                    if !stall_alerting && stall_secs >= cfg.stall_threshold_secs {
                        if tx
                            .send(InputEvent::ChainStalled {
                                endpoint: endpoint.clone(),
                                height,
                                stall_secs,
                                block_age_secs,
                                client_id: client_id.clone(),
                            })
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                        stall_alerting = true;
                    } else if stall_alerting && stall_secs < cfg.stall_threshold_secs {
                        if tx
                            .send(InputEvent::ChainRecovered {
                                endpoint: endpoint.clone(),
                                height,
                                latency_ms,
                                client_id: client_id.clone(),
                            })
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                        stall_alerting = false;
                    }

                    if rpc_alerting && consecutive_rpc_successes + 1 >= cfg.successes_before_recovery {
                        if tx
                            .send(InputEvent::RpcRecovered {
                                endpoint: endpoint.clone(),
                                height,
                                latency_ms,
                                client_id: client_id.clone(),
                            })
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                        rpc_alerting = false;
                    }

                    consecutive_rpc_failures = 0;
                    consecutive_rpc_successes += 1;
                    success = true;
                    break;
                }
                Err(err) => {
                    last_error = Some(format!("{endpoint}: {err:#}"));
                }
            }
        }

        if !success {
            consecutive_rpc_successes = 0;
            consecutive_rpc_failures += 1;
            if !rpc_alerting && consecutive_rpc_failures >= cfg.failures_before_alert {
                if tx
                    .send(InputEvent::RpcUnavailable {
                        endpoints: cfg.endpoints.clone(),
                        error: last_error.unwrap_or_else(|| "unknown rpc error".to_string()),
                        client_id: client_id.clone(),
                    })
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                rpc_alerting = true;
            }
        }

        tokio::time::sleep(Duration::from_secs(cfg.interval_secs)).await;
    }
}

async fn fetch_latest_block(client: &Client, endpoint: &str) -> anyhow::Result<(u64, u64, u128)> {
    let start = std::time::Instant::now();
    let height_hex = rpc_call::<String>(client, endpoint, "eth_blockNumber", json!([])).await?;
    let height = parse_hex_u64(&height_hex).context("invalid block height hex")?;

    let block = rpc_call::<BlockHeader>(
        client,
        endpoint,
        "eth_getBlockByNumber",
        json!(["latest", false]),
    )
    .await?;
    let block_ts_secs = parse_block_timestamp_secs(&block.timestamp).context("invalid block timestamp hex")?;

    Ok((height, block_ts_secs, start.elapsed().as_millis()))
}

async fn rpc_call<T: for<'de> serde::Deserialize<'de>>(
    client: &Client,
    endpoint: &str,
    method: &str,
    params: serde_json::Value,
) -> anyhow::Result<T> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    let resp = client.post(endpoint).json(&body).send().await?;
    let resp = resp.error_for_status()?;
    let parsed = resp.json::<RpcEnvelope<T>>().await?;
    if let Some(err) = parsed.error {
        anyhow::bail!("rpc error {}: {}", err.code, err.message);
    }
    parsed.result.context("missing rpc result")
}
