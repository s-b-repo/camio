//! Shared request rate limiting (plan §4.3, §16: "shared rates … across
//! simultaneous native and external jobs").
//!
//! A per-host token-bucket limiter every send path can consult so Camio never
//! hammers a target faster than the operator allows — whether the traffic comes
//! from the proxy, a campaign, the crawler, or the active scanner. The bucket
//! logic is pure and clock-injectable so it is tested deterministically; a
//! blocking [`RateLimiter::acquire`] convenience paces synchronous callers.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A token bucket: `capacity` tokens, refilling at `refill_per_sec`.
#[derive(Clone, Copy, Debug)]
struct Rate {
    capacity: f64,
    refill_per_sec: f64,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// A per-host (and optional global) token-bucket rate limiter.
pub struct RateLimiter {
    per_host: Option<Rate>,
    global: Option<Rate>,
    buckets: Mutex<HashMap<String, Bucket>>,
    global_bucket: Mutex<Option<Bucket>>,
}

impl RateLimiter {
    /// A limiter with an optional per-host and global requests-per-second cap.
    /// `None` on either disables that dimension. Burst capacity equals one
    /// second's worth of tokens (minimum 1).
    pub fn new(per_host_rps: Option<f64>, global_rps: Option<f64>) -> Self {
        let mk = |rps: f64| Rate {
            capacity: rps.max(1.0),
            refill_per_sec: rps.max(0.0),
        };
        RateLimiter {
            per_host: per_host_rps.filter(|r| *r > 0.0).map(mk),
            global: global_rps.filter(|r| *r > 0.0).map(mk),
            buckets: Mutex::new(HashMap::new()),
            global_bucket: Mutex::new(None),
        }
    }

    /// An unlimited limiter (both dimensions off) — a convenient no-op default.
    pub fn unlimited() -> Self {
        RateLimiter::new(None, None)
    }

    /// Whether this limiter imposes any cap.
    pub fn is_limited(&self) -> bool {
        self.per_host.is_some() || self.global.is_some()
    }

    /// Try to take one token for `host` at `now`. Returns `true` if allowed.
    /// Both the per-host and global buckets (when configured) must have a token;
    /// a token is consumed from each only when both can be satisfied.
    pub fn try_acquire_at(&self, host: &str, now: Instant) -> bool {
        // Check availability without consuming, then consume atomically.
        // Poison recovery rather than `expect`: the limiter is shared by every send
        // path, so one panicking caller used to poison both locks and make every
        // later request panic too.
        let mut host_guard = crate::sync::recovered_lock(&self.buckets);
        let mut global_guard = crate::sync::recovered_lock(&self.global_bucket);

        let host_ok = match self.per_host {
            Some(rate) => {
                let b = host_guard.entry(host.to_string()).or_insert(Bucket {
                    tokens: rate.capacity,
                    last: now,
                });
                refill(b, rate, now);
                b.tokens >= 1.0
            }
            None => true,
        };
        let global_ok = match self.global {
            Some(rate) => {
                let b = global_guard.get_or_insert(Bucket {
                    tokens: rate.capacity,
                    last: now,
                });
                refill(b, rate, now);
                b.tokens >= 1.0
            }
            None => true,
        };

        if host_ok && global_ok {
            if self.per_host.is_some() {
                if let Some(b) = host_guard.get_mut(host) {
                    b.tokens -= 1.0;
                }
            }
            if self.global.is_some() {
                if let Some(b) = global_guard.as_mut() {
                    b.tokens -= 1.0;
                }
            }
            true
        } else {
            false
        }
    }

    /// Try to take one token for `host` now (non-blocking).
    pub fn try_acquire(&self, host: &str) -> bool {
        self.try_acquire_at(host, Instant::now())
    }

    /// Block until a token for `host` is available, sleeping in between. Returns
    /// immediately on an unlimited limiter.
    pub fn acquire(&self, host: &str) {
        if !self.is_limited() {
            return;
        }
        loop {
            if self.try_acquire(host) {
                return;
            }
            std::thread::sleep(self.wait_hint());
        }
    }

    /// A reasonable sleep between acquire attempts: the time for one token at the
    /// tighter configured rate (clamped to a sane range).
    fn wait_hint(&self) -> Duration {
        let rps = [self.per_host, self.global]
            .into_iter()
            .flatten()
            .map(|r| r.refill_per_sec)
            .filter(|r| *r > 0.0)
            .fold(f64::INFINITY, f64::min);
        if rps.is_finite() && rps > 0.0 {
            let secs = (1.0 / rps).clamp(0.005, 1.0);
            Duration::from_secs_f64(secs)
        } else {
            Duration::from_millis(50)
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        RateLimiter::unlimited()
    }
}

fn refill(b: &mut Bucket, rate: Rate, now: Instant) {
    let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
    if elapsed > 0.0 {
        b.tokens = (b.tokens + elapsed * rate.refill_per_sec).min(rate.capacity);
        b.last = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_always_allows() {
        let rl = RateLimiter::unlimited();
        assert!(!rl.is_limited());
        for _ in 0..1000 {
            assert!(rl.try_acquire("h"));
        }
    }

    #[test]
    fn per_host_bucket_drains_and_refills() {
        // 2 rps → capacity 2. Deterministic via injected instants.
        let rl = RateLimiter::new(Some(2.0), None);
        let t0 = Instant::now();
        // Two tokens available immediately (burst = capacity).
        assert!(rl.try_acquire_at("a", t0));
        assert!(rl.try_acquire_at("a", t0));
        // Third is refused — bucket empty.
        assert!(!rl.try_acquire_at("a", t0));
        // After 0.5s one token refills (2 rps).
        assert!(rl.try_acquire_at("a", t0 + Duration::from_millis(500)));
        assert!(!rl.try_acquire_at("a", t0 + Duration::from_millis(500)));
    }

    #[test]
    fn per_host_is_independent_across_hosts() {
        let rl = RateLimiter::new(Some(1.0), None);
        let t0 = Instant::now();
        assert!(rl.try_acquire_at("a", t0));
        assert!(!rl.try_acquire_at("a", t0)); // a drained
        assert!(rl.try_acquire_at("b", t0)); // b independent
    }

    #[test]
    fn global_cap_applies_across_hosts() {
        // Global 1 rps, no per-host: one request total per second regardless of host.
        let rl = RateLimiter::new(None, Some(1.0));
        let t0 = Instant::now();
        assert!(rl.try_acquire_at("a", t0));
        assert!(!rl.try_acquire_at("b", t0)); // global bucket drained by host a
    }

    #[test]
    fn both_dimensions_must_allow() {
        // per-host 5 rps, global 1 rps → global is the binding constraint.
        let rl = RateLimiter::new(Some(5.0), Some(1.0));
        let t0 = Instant::now();
        assert!(rl.try_acquire_at("a", t0));
        assert!(!rl.try_acquire_at("a", t0)); // global empty even though host has tokens
    }

    #[test]
    fn acquire_blocks_then_returns() {
        // A tight real-time check: 50 rps → second acquire waits ~20ms.
        let rl = RateLimiter::new(Some(50.0), None);
        assert!(rl.try_acquire("h")); // burst token
                                      // Drain the burst, then time a blocking acquire.
        while rl.try_acquire("h") {}
        let start = Instant::now();
        rl.acquire("h");
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
