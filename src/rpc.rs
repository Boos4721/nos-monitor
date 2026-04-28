use crate::config::RpcConfig;
use crate::config::VerifyConfig;
use crate::detect::{
    InputEvent, MiningCandidate, MiningVerificationFailure, MiningVerificationResult,
};
use crate::util::{
    duration_since_block, encode_decimal_string_as_hex32, encode_u64_as_hex32, parse_hex_u64,
    BlockHeader, RpcBlock, RpcEnvelope, RpcLog,
};
use anyhow::Context;
use chrono::Utc;
use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};
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

                    if rpc_alerting
                        && consecutive_rpc_successes + 1 >= cfg.successes_before_recovery
                    {
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

#[derive(Debug, Clone)]
pub struct PendingCandidate {
    pub candidate: MiningCandidate,
    pub source_path: Option<String>,
    pub node_addr: Option<String>,
    pub client_id: Option<String>,
    pub first_seen_at: Instant,
    pub attempts: u32,
}

impl PendingCandidate {
    fn make_failure(&self, reason: String) -> MiningVerificationFailure {
        MiningVerificationFailure {
            candidate: self.candidate.clone(),
            reason,
            source_path: self.source_path.clone(),
            node_addr: self.node_addr.clone(),
            client_id: self.client_id.clone(),
        }
    }
}

pub async fn run_verification_loop(
    rpc_cfg: RpcConfig,
    verify_cfg: VerifyConfig,
    mut candidate_rx: mpsc::Receiver<PendingCandidate>,
    tx: mpsc::Sender<InputEvent>,
) -> anyhow::Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_millis(rpc_cfg.timeout_ms))
        .build()?;
    let mut pending: HashMap<String, PendingCandidate> = HashMap::new();

    loop {
        tokio::select! {
            maybe_candidate = candidate_rx.recv() => {
                match maybe_candidate {
                    Some(candidate) => {
                        let key = candidate_key(&candidate.candidate, candidate.source_path.as_deref());
                        pending.entry(key).or_insert(candidate);
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(verify_cfg.poll_interval_secs.max(1))) => {
                if pending.is_empty() {
                    continue;
                }

                let latest_height = match fetch_latest_height(&client, &rpc_cfg.endpoints).await {
                    Ok(height) => height,
                    Err(_) => continue,
                };

                let mut resolved = Vec::new();
                for (key, item) in pending.iter_mut() {
                    if item.first_seen_at.elapsed() > Duration::from_secs(verify_cfg.pending_ttl_secs) {
                        let _ = tx.send(InputEvent::MiningCandidateUnverified(
                            item.make_failure("窗口内未发现链上证据".to_string()),
                        )).await;
                        resolved.push(key.clone());
                        continue;
                    }

                    if latest_height < item.candidate.height.saturating_add(verify_cfg.confirmations) {
                        continue;
                    }

                    item.attempts += 1;
                    match verify_candidate(&client, &rpc_cfg.endpoints, &verify_cfg, item, latest_height).await {
                        Ok(Some(result)) => {
                            let _ = tx.send(InputEvent::MiningCandidateVerified(result)).await;
                            resolved.push(key.clone());
                        }
                        Ok(None) => {}
                        Err(err) => {
                            if item.first_seen_at.elapsed() > Duration::from_secs(verify_cfg.pending_ttl_secs) {
                                let _ = tx.send(InputEvent::MiningCandidateUnverified(
                                    item.make_failure(format!("RPC 查询失败: {err:#}")),
                                )).await;
                                resolved.push(key.clone());
                            }
                        }
                    }
                }

                for key in resolved {
                    pending.remove(&key);
                }
            }
        }
    }

    Ok(())
}

async fn verify_candidate(
    client: &Client,
    endpoints: &[String],
    cfg: &VerifyConfig,
    pending: &PendingCandidate,
    latest_height: u64,
) -> anyhow::Result<Option<MiningVerificationResult>> {
    if let Some(block) = fetch_block_by_height(client, endpoints, pending.candidate.height).await? {
        let matched_block = parse_hex_u64(&block.number).unwrap_or(pending.candidate.height);
        let mut evidence_parts = vec![format!(
            "confirmed block exists at height {}",
            pending.candidate.height
        )];
        if let Some(hash) = &block.hash {
            evidence_parts.push(format!("block_hash={hash}"));
        }
        if let Some(miner) = &block.miner {
            evidence_parts.push(format!("miner={miner}"));
        }
        if let Some(nonce) = &block.nonce {
            evidence_parts.push(format!("block_nonce={nonce}"));
        }

        return Ok(Some(MiningVerificationResult {
            candidate: pending.candidate.clone(),
            matched_contract: "block_header".to_string(),
            tx_hash: block.hash.clone(),
            matched_block,
            confidence: "high".to_string(),
            evidence: evidence_parts.join(" | "),
            source_path: pending.source_path.clone(),
            node_addr: pending.node_addr.clone(),
            client_id: pending.client_id.clone(),
        }));
    }

    let from_block = pending
        .candidate
        .height
        .saturating_sub(cfg.backtrack_blocks);
    let to_block = latest_height.min(pending.candidate.height.saturating_add(cfg.forward_blocks));
    let height_hex = encode_u64_as_hex32(pending.candidate.height);
    let nonce_hex = encode_decimal_string_as_hex32(&pending.candidate.nonce)
        .with_context(|| format!("invalid nonce {}", pending.candidate.nonce))?;

    let primary = fetch_logs_for_addresses(
        client,
        endpoints,
        &cfg.primary_contracts,
        from_block,
        to_block,
    )
    .await?;
    if let Some(result) = match_logs(
        &primary,
        &pending.candidate,
        &height_hex,
        &nonce_hex,
        "high",
        pending,
    ) {
        return Ok(Some(result));
    }

    let auxiliary = fetch_logs_for_addresses(
        client,
        endpoints,
        &cfg.auxiliary_contracts,
        from_block,
        to_block,
    )
    .await?;
    Ok(match_logs(
        &auxiliary,
        &pending.candidate,
        &height_hex,
        &nonce_hex,
        "medium",
        pending,
    ))
}

fn match_logs(
    logs: &[RpcLog],
    candidate: &MiningCandidate,
    height_hex: &str,
    nonce_hex: &str,
    confidence: &str,
    pending: &PendingCandidate,
) -> Option<MiningVerificationResult> {
    let nonce_compact = nonce_hex.trim_start_matches('0');
    let height_compact = height_hex.trim_start_matches('0');

    logs.iter().find_map(|log| {
        let data_lc = log.data.to_ascii_lowercase();
        let topics_lc: Vec<String> = log
            .topics
            .iter()
            .map(|topic| topic.to_ascii_lowercase())
            .collect();
        let haystacks =
            std::iter::once(data_lc.as_str()).chain(topics_lc.iter().map(String::as_str));
        let matched = haystacks.clone().any(|value| {
            value.contains(height_hex)
                || (!height_compact.is_empty() && value.contains(height_compact))
                || value.contains(nonce_hex)
                || (!nonce_compact.is_empty() && value.contains(nonce_compact))
        });

        if !matched {
            return None;
        }

        Some(MiningVerificationResult {
            candidate: candidate.clone(),
            matched_contract: log.address.clone(),
            tx_hash: log.transaction_hash.clone(),
            matched_block: log
                .block_number
                .as_deref()
                .and_then(parse_hex_u64)
                .unwrap_or(candidate.height),
            confidence: confidence.to_string(),
            evidence: format!(
                "matched candidate height/nonce in log topics/data after {} attempts",
                pending.attempts
            ),
            source_path: pending.source_path.clone(),
            node_addr: pending.node_addr.clone(),
            client_id: pending.client_id.clone(),
        })
    })
}

async fn fetch_latest_height(client: &Client, endpoints: &[String]) -> anyhow::Result<u64> {
    let mut last_err = None;
    for endpoint in endpoints {
        match rpc_call::<String>(client, endpoint, "eth_blockNumber", json!([])).await {
            Ok(height_hex) => {
                return parse_hex_u64(&height_hex).context("invalid block height hex")
            }
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no rpc endpoints configured")))
}

async fn fetch_block_by_height(
    client: &Client,
    endpoints: &[String],
    height: u64,
) -> anyhow::Result<Option<RpcBlock>> {
    let block_hex = format!("0x{:x}", height);
    let mut last_err = None;
    for endpoint in endpoints {
        match rpc_call::<Option<RpcBlock>>(
            client,
            endpoint,
            "eth_getBlockByNumber",
            json!([block_hex, false]),
        )
        .await
        {
            Ok(block) => return Ok(block),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("failed to fetch block by height")))
}

async fn fetch_logs_for_addresses(
    client: &Client,
    endpoints: &[String],
    addresses: &[String],
    from_block: u64,
    to_block: u64,
) -> anyhow::Result<Vec<RpcLog>> {
    if addresses.is_empty() {
        return Ok(Vec::new());
    }

    let mut last_err = None;
    for endpoint in endpoints {
        let mut all_logs = Vec::new();
        let mut endpoint_succeeded = false;

        for address in addresses {
            let filter = json!({
                "fromBlock": format!("0x{:x}", from_block),
                "toBlock": format!("0x{:x}", to_block),
                "address": address,
            });
            match rpc_call::<Option<Vec<RpcLog>>>(client, endpoint, "eth_getLogs", json!([filter]))
                .await
            {
                Ok(Some(mut logs)) => {
                    endpoint_succeeded = true;
                    all_logs.append(&mut logs);
                }
                Ok(None) => {
                    endpoint_succeeded = true;
                }
                Err(err) => {
                    last_err = Some(err);
                    endpoint_succeeded = false;
                    break;
                }
            }
        }

        if endpoint_succeeded {
            return Ok(all_logs);
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("failed to fetch logs")))
}

fn candidate_key(candidate: &MiningCandidate, source_path: Option<&str>) -> String {
    format!(
        "{}|{}|{}|{}",
        candidate.height,
        candidate.worker_id,
        candidate.nonce,
        source_path.unwrap_or_default()
    )
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
    let block_ts_secs = parse_hex_u64(&block.timestamp).context("invalid block timestamp hex")?;

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

#[cfg(test)]
mod tests {
    use super::{candidate_key, match_logs, PendingCandidate};
    use crate::detect::MiningCandidate;
    use crate::util::RpcLog;
    use std::time::Instant;

    #[test]
    fn candidate_key_includes_source_path() {
        let candidate = MiningCandidate {
            worker_id: 13,
            height: 100,
            nonce: "999".to_string(),
            raw: String::new(),
            combined: String::new(),
            log_timestamp: None,
        };
        assert_eq!(candidate_key(&candidate, Some("a")), "100|13|999|a");
    }

    #[test]
    fn matches_log_by_height_and_nonce() {
        let candidate = MiningCandidate {
            worker_id: 13,
            height: 100,
            nonce: "255".to_string(),
            raw: "raw".to_string(),
            combined: "combined".to_string(),
            log_timestamp: None,
        };
        let pending = PendingCandidate {
            candidate: candidate.clone(),
            source_path: Some("/tmp/log".to_string()),
            node_addr: None,
            client_id: None,
            first_seen_at: Instant::now(),
            attempts: 1,
        };
        let log = RpcLog {
            address: "0xabc".to_string(),
            topics: vec![
                "0x0000000000000000000000000000000000000000000000000000000000000064".to_string(),
            ],
            data: "0x00000000000000000000000000000000000000000000000000000000000000ff".to_string(),
            block_number: Some("0x64".to_string()),
            transaction_hash: Some("0xtx".to_string()),
        };

        let matched = match_logs(
            &[log],
            &candidate,
            "0000000000000000000000000000000000000000000000000000000000000064",
            "00000000000000000000000000000000000000000000000000000000000000ff",
            "high",
            &pending,
        )
        .expect("expected log match");
        assert_eq!(matched.matched_contract, "0xabc");
        assert_eq!(matched.tx_hash.as_deref(), Some("0xtx"));
        assert_eq!(matched.matched_block, 100);
    }
}
