//! Per-client request quotas.
//!
//! The service already sheds load globally: a semaphore caps in-flight
//! executions and returns `503` past it. That protects the host, not the
//! callers — one client in a retry loop can hold every permit and every other
//! client sees `503`. A global cap is a fuse, not a quota.
//!
//! This is the quota. Each client gets its own token bucket, so a client that
//! exceeds its rate is throttled without affecting anyone else's.
//!
//! # What counts as a client
//!
//! Whatever the caller passes as `key`. [`crate::server`] uses a digest of the
//! bearer token when one is present and the peer address otherwise, so an
//! unauthenticated deployment still gets per-source limits. The digest matters:
//! bucket keys end up in maps that get logged and dumped, and a raw token in
//! there is a credential in a crash report.
//!
//! # Bounding the map
//!
//! Keys come from callers, so the bucket map is attacker-growable — the same
//! unbounded-cache shape that was fixed in [`crate::registry`]. Buckets idle
//! for ten minutes are dropped, and past ten thousand clients the oldest are
//! evicted regardless. Eviction is safe: a missing bucket is recreated full,
//! which is the same as never having been rate limited.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Drop buckets untouched for this long.
const IDLE_EVICTION: Duration = Duration::from_secs(600);

/// Hard cap on tracked clients, so the map cannot be grown without bound.
const MAX_BUCKETS: usize = 10_000;

/// A refill rate and a burst allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Sustained rate, in requests per minute.
    pub per_minute: u32,
    /// How many requests may arrive at once before the sustained rate applies.
    pub burst: u32,
}

impl RateLimit {
    /// A limit, with `burst` clamped to at least one request.
    pub fn new(per_minute: u32, burst: u32) -> Self {
        RateLimit {
            per_minute,
            burst: burst.max(1),
        }
    }

    /// Tokens added per second.
    fn refill_per_second(&self) -> f64 {
        f64::from(self.per_minute) / 60.0
    }
}

/// A request was refused, and roughly when to try again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Throttled {
    /// Seconds to wait, for a `Retry-After` header. Always at least 1, since
    /// `Retry-After: 0` invites an immediate retry that will also fail.
    pub retry_after_secs: u64,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Token buckets keyed by client.
#[derive(Debug)]
pub struct RateLimiter {
    limit: RateLimit,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// A limiter with no clients yet.
    pub fn new(limit: RateLimit) -> Self {
        RateLimiter {
            limit,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// The configured limit.
    pub fn limit(&self) -> RateLimit {
        self.limit
    }

    /// Take one token for `key`, or report how long to wait.
    ///
    /// A poisoned lock is treated as "allow": the limiter is a quota, and
    /// failing it closed would turn one panicking request into a total outage.
    pub fn check(&self, key: &str) -> Result<(), Throttled> {
        self.check_at(key, Instant::now())
    }

    /// [`RateLimiter::check`] against an explicit clock, for tests.
    pub fn check_at(&self, key: &str, now: Instant) -> Result<(), Throttled> {
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(_) => return Ok(()),
        };

        if buckets.len() >= MAX_BUCKETS {
            evict(&mut buckets, now);
        }

        let burst = f64::from(self.limit.burst);
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: burst,
            last: now,
        });

        // Refill for the time that passed, then spend one token.
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.limit.refill_per_second()).min(burst);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }

        let refill = self.limit.refill_per_second();
        let wait = if refill > 0.0 {
            ((1.0 - bucket.tokens) / refill).ceil() as u64
        } else {
            // `per_minute: 0` means the bucket never refills: the burst is the
            // entire allowance. Nothing useful to promise, so say a minute.
            60
        };
        Err(Throttled {
            retry_after_secs: wait.max(1),
        })
    }

    /// Number of tracked clients, for tests and metrics.
    pub fn tracked(&self) -> usize {
        self.buckets.lock().map(|b| b.len()).unwrap_or(0)
    }
}

/// Drop idle buckets; if that is not enough, drop the least recently used.
fn evict(buckets: &mut HashMap<String, Bucket>, now: Instant) {
    buckets.retain(|_, b| now.saturating_duration_since(b.last) < IDLE_EVICTION);
    if buckets.len() < MAX_BUCKETS {
        return;
    }
    let mut by_age: Vec<(String, Instant)> =
        buckets.iter().map(|(k, b)| (k.clone(), b.last)).collect();
    by_age.sort_by_key(|(_, last)| *last);
    for (key, _) in by_age.into_iter().take(MAX_BUCKETS / 4) {
        buckets.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_allowed_and_then_the_rate_applies() {
        let limiter = RateLimiter::new(RateLimit::new(60, 5));
        let t0 = Instant::now();

        for i in 0..5 {
            assert!(limiter.check_at("a", t0).is_ok(), "burst request {i}");
        }
        assert!(limiter.check_at("a", t0).is_err(), "burst was not capped");
    }

    #[test]
    fn tokens_refill_over_time() {
        // 60/minute is one per second.
        let limiter = RateLimiter::new(RateLimit::new(60, 2));
        let t0 = Instant::now();

        assert!(limiter.check_at("a", t0).is_ok());
        assert!(limiter.check_at("a", t0).is_ok());
        assert!(limiter.check_at("a", t0).is_err());

        assert!(limiter.check_at("a", t0 + Duration::from_secs(1)).is_ok());
        assert!(limiter.check_at("a", t0 + Duration::from_secs(1)).is_err());
    }

    #[test]
    fn refill_does_not_exceed_the_burst() {
        // Idling for an hour must not bank an hour of requests.
        let limiter = RateLimiter::new(RateLimit::new(60, 3));
        let t0 = Instant::now();
        assert!(limiter.check_at("a", t0).is_ok());

        let later = t0 + Duration::from_secs(3600);
        for i in 0..3 {
            assert!(limiter.check_at("a", later).is_ok(), "request {i}");
        }
        assert!(limiter.check_at("a", later).is_err(), "burst was banked");
    }

    #[test]
    fn one_client_exhausting_its_quota_does_not_affect_another() {
        // The whole point: this is what the global semaphore could not do.
        let limiter = RateLimiter::new(RateLimit::new(60, 2));
        let t0 = Instant::now();

        assert!(limiter.check_at("noisy", t0).is_ok());
        assert!(limiter.check_at("noisy", t0).is_ok());
        assert!(limiter.check_at("noisy", t0).is_err());

        assert!(limiter.check_at("quiet", t0).is_ok());
        assert!(limiter.check_at("quiet", t0).is_ok());
    }

    #[test]
    fn retry_after_is_never_zero() {
        let limiter = RateLimiter::new(RateLimit::new(60, 1));
        let t0 = Instant::now();
        assert!(limiter.check_at("a", t0).is_ok());

        let throttled = limiter.check_at("a", t0).unwrap_err();
        assert!(throttled.retry_after_secs >= 1);
    }

    #[test]
    fn a_zero_rate_allows_only_the_burst() {
        let limiter = RateLimiter::new(RateLimit::new(0, 2));
        let t0 = Instant::now();
        assert!(limiter.check_at("a", t0).is_ok());
        assert!(limiter.check_at("a", t0).is_ok());
        assert!(limiter
            .check_at("a", t0 + Duration::from_secs(86_400))
            .is_err());
    }

    #[test]
    fn a_burst_of_zero_is_clamped_to_one() {
        // Otherwise the bucket starts empty and refuses every request forever.
        let limiter = RateLimiter::new(RateLimit::new(60, 0));
        assert_eq!(limiter.limit().burst, 1);
        assert!(limiter.check("a").is_ok());
    }

    #[test]
    fn idle_buckets_are_evicted_so_the_map_cannot_grow_without_bound() {
        let limiter = RateLimiter::new(RateLimit::new(600, 1));
        let t0 = Instant::now();
        for i in 0..MAX_BUCKETS {
            let _ = limiter.check_at(&format!("client{i}"), t0);
        }
        assert_eq!(limiter.tracked(), MAX_BUCKETS);

        // One more, long enough later that everything before it is idle.
        let _ = limiter.check_at("newcomer", t0 + IDLE_EVICTION + Duration::from_secs(1));
        assert!(
            limiter.tracked() < MAX_BUCKETS,
            "idle buckets were not evicted: {}",
            limiter.tracked()
        );
    }

    #[test]
    fn eviction_falls_back_to_dropping_the_oldest_when_nothing_is_idle() {
        let limiter = RateLimiter::new(RateLimit::new(600, 1));
        let t0 = Instant::now();
        for i in 0..MAX_BUCKETS {
            // Staggered, but all recent: none qualify as idle.
            let _ = limiter.check_at(&format!("client{i}"), t0 + Duration::from_millis(i as u64));
        }
        let _ = limiter.check_at("newcomer", t0 + Duration::from_secs(1));
        assert!(
            limiter.tracked() < MAX_BUCKETS,
            "LRU eviction did not run: {}",
            limiter.tracked()
        );
    }
}
