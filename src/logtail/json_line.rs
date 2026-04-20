use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct JsonLogLine {
    pub level: Option<String>,
    pub timestamp: Option<String>,
    pub msg: Option<String>,
    pub error: Option<String>,
    pub stacktrace: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ParsedLine {
    Json(JsonLogLine),
    Text(String),
}

pub fn parse_line(raw: &str) -> ParsedLine {
    match serde_json::from_str::<JsonLogLine>(raw) {
        Ok(v) => ParsedLine::Json(v),
        Err(_) => ParsedLine::Text(raw.to_string()),
    }
}
