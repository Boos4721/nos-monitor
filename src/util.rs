use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct RpcEnvelope<T> {
    pub result: Option<T>,
    pub error: Option<RpcError>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeader {
    pub timestamp: String,
}

pub fn parse_hex_u64(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .and_then(|v| u64::from_str_radix(v, 16).ok())
}

pub fn parse_block_timestamp_secs(value: &str) -> Option<u64> {
    parse_hex_u64(value)
}

pub fn duration_since_block(now: DateTime<Utc>, block_ts_secs: u64) -> Option<Duration> {
    let block_time = DateTime::<Utc>::from_timestamp(block_ts_secs as i64, 0)?;
    now.signed_duration_since(block_time).to_std().ok()
}
