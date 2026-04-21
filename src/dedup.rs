use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct Deduper {
    window: Duration,
    cooldown_default: Duration,
    last_sent: HashMap<String, Instant>,
    last_cleanup: Instant,
}

impl Deduper {
    pub fn new(dedup_window_secs: u64, cooldown_secs: u64) -> Self {
        Self {
            window: Duration::from_secs(dedup_window_secs),
            cooldown_default: Duration::from_secs(cooldown_secs),
            last_sent: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    pub fn should_send(&mut self, _rule_id: &str, fingerprint_key: &str) -> bool {
        let now = Instant::now();

        if let Some(prev) = self.last_sent.get(fingerprint_key) {
            if now.duration_since(*prev) < self.cooldown_default {
                return false;
            }
        }

        self.last_sent.insert(fingerprint_key.to_string(), now);

        if now.duration_since(self.last_cleanup) > Duration::from_secs(30) {
            self.cleanup(now);
            self.last_cleanup = now;
        }

        true
    }

    fn cleanup(&mut self, now: Instant) {
        let window = self.window;
        self.last_sent
            .retain(|_, t| now.duration_since(*t) <= window);
    }
}

#[cfg(test)]
mod tests {
    use super::Deduper;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn blocks_repeated_fingerprint_within_cooldown() {
        let mut deduper = Deduper::new(60, 1);
        assert!(deduper.should_send("rule", "a"));
        assert!(!deduper.should_send("rule", "a"));
    }

    #[test]
    fn allows_repeated_fingerprint_after_cooldown() {
        let mut deduper = Deduper::new(60, 1);
        assert!(deduper.should_send("rule", "a"));
        thread::sleep(Duration::from_millis(1100));
        assert!(deduper.should_send("rule", "a"));
    }

    #[test]
    fn different_fingerprints_do_not_block_each_other() {
        let mut deduper = Deduper::new(60, 5);
        assert!(deduper.should_send("rule", "a"));
        assert!(deduper.should_send("rule", "b"));
    }
}
