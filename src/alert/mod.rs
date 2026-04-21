use crate::config::AlertConfig;
use crate::detect::AlertEvent;
use anyhow::Context;
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;

#[derive(Clone)]
pub struct WebhookClient {
    client: Client,
    url: String,
    cfg: AlertConfig,
}

#[derive(Debug, Serialize)]
struct BarkPayload<'a> {
    title: &'a str,
    body: String,
    level: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<&'a str>,
}

impl WebhookClient {
    pub fn new(url: String, cfg: AlertConfig) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .build()?;

        Ok(Self { client, url, cfg })
    }

    pub async fn send(&self, ev: &AlertEvent) -> anyhow::Result<()> {
        let mut attempt = 0u32;
        let mut delay_ms = self.cfg.retry_base_delay_ms;
        let payload = bark_payload(ev, &self.cfg);
        let request_url = bark_request_url(&self.url, &self.cfg);

        loop {
            attempt += 1;
            let res = self.client.post(&request_url).json(&payload).send().await;

            match res {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    let err = anyhow::anyhow!("bark http {status}: {body}");
                    if attempt >= self.cfg.retry_max_attempts {
                        return Err(err);
                    }
                }
                Err(err) => {
                    if attempt >= self.cfg.retry_max_attempts {
                        return Err(err).context("send bark request failed");
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            delay_ms = (delay_ms.saturating_mul(2)).min(self.cfg.retry_max_delay_ms);
        }
    }
}

fn bark_payload<'a>(ev: &'a AlertEvent, cfg: &'a AlertConfig) -> BarkPayload<'a> {
    let title = match ev.event_type.as_str() {
        "candidate_detected" => "【爆块候选】NOS 监控",
        "candidate_verified" => "【链上确认】NOS 监控",
        "candidate_unverified" => "【待复核】NOS 监控",
        _ => match ev.severity.as_str() {
            "critical" => "NOS 监控告警",
            "warning" => "NOS 监控提醒",
            _ => "NOS 监控恢复",
        },
    };

    let mut lines = Vec::new();
    lines.push(format!("类型: {}", ev.event_type));
    lines.push(format!("规则: {}", ev.rule_id));
    lines.push(format!("摘要: {}", ev.summary));
    if let Some(node_addr) = &ev.node_addr {
        lines.push(format!("节点: {node_addr}"));
    }
    if let Some(client_id) = &ev.client_id {
        lines.push(format!("client_id: {client_id}"));
    }
    if let Some(source_path) = &ev.source_path {
        lines.push(format!("来源: {source_path}"));
    }
    if let Some(log_ts) = &ev.log_timestamp {
        lines.push(format!("日志时间: {log_ts}"));
    }
    if let Some(matched) = &ev.matched {
        lines.push(format!("命中: {matched}"));
    }
    if !ev.raw.is_empty() {
        lines.push(format!("原始: {}", ev.raw));
    }

    let group = bark_group(cfg);

    BarkPayload {
        title,
        body: lines.join("\n"),
        level: match ev.severity.as_str() {
            "critical" => "critical",
            "warning" => "active",
            _ => "passive",
        },
        group: Some(group),
    }
}

fn bark_group(cfg: &AlertConfig) -> &str {
    cfg.bark_group
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("nos-monitor")
}

fn bark_request_url(url: &str, cfg: &AlertConfig) -> String {
    let group = bark_group(cfg);
    if url.contains("group=") {
        return url.to_string();
    }

    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}group={group}")
}
