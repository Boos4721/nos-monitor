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

#[derive(Debug, Clone, Deserialize)]
pub struct RpcBlock {
    pub number: String,
    pub hash: Option<String>,
    #[serde(rename = "parentHash")]
    pub parent_hash: Option<String>,
    pub nonce: Option<String>,
    pub miner: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RpcLog {
    pub address: String,
    #[serde(default)]
    pub topics: Vec<String>,
    pub data: String,
    #[serde(rename = "blockNumber")]
    pub block_number: Option<String>,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<String>,
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

pub fn encode_u64_as_hex32(value: u64) -> String {
    format!("{:064x}", value)
}

pub fn encode_decimal_string_as_hex32(value: &str) -> Option<String> {
    let digits = value.trim();
    if digits.is_empty() || !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }

    let mut bytes = vec![0u8];
    for ch in digits.chars() {
        let digit = ch.to_digit(10)? as u8;
        let mut carry = digit as u16;
        for byte in bytes.iter_mut().rev() {
            let v = (*byte as u16) * 10 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    if bytes.len() > 32 {
        return None;
    }

    let mut hex = String::with_capacity(64);
    for _ in 0..(32 - bytes.len()) {
        hex.push_str("00");
    }
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    Some(hex)
}

#[cfg(test)]
mod tests {
    use super::{encode_decimal_string_as_hex32, encode_u64_as_hex32};

    #[test]
    fn encodes_u64_into_32_byte_hex() {
        assert_eq!(
            encode_u64_as_hex32(15),
            "000000000000000000000000000000000000000000000000000000000000000f"
        );
    }

    #[test]
    fn encodes_decimal_string_into_32_byte_hex() {
        assert_eq!(
            encode_decimal_string_as_hex32("255").as_deref(),
            Some("00000000000000000000000000000000000000000000000000000000000000ff")
        );
    }
}
