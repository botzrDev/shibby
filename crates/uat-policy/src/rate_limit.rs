//! Per-caller-key rate limits (HLX-113 / §6.4).
//!
//! Three caps, all keyed by authenticated [`NodeId`] from the QUIC handshake
//! (never by IP — that would rate-limit the relay):
//!
//! | Cap | Default | Meaning |
//! |-----|---------|---------|
//! | concurrent calls | 8 | admitted in-flight calls for this peer |
//! | calls / minute | 60 | admit attempts (accepted or rejected) in a 60s sliding window |
//! | live frames | 8 | open connections for this peer (1:1 with a call in UAT) |
//!
//! With one call per connection, concurrent and live-frames both count admitted
//! open connections; either cap may reject. They remain separate knobs so an
//! operator can tighten one without the other if the model grows.
//!
//! Enforcement is **connection admission**: [`RateLimiter::try_admit`] runs
//! after the allowlist / biscuit connection gate and **before** `accept_bi`.
//! Exceeding any cap closes with `CloseCode::RateLimited` and never accepts a
//! stream. Rate limiting is separate from authorization — the audit record uses
//! `authorization: NotReached`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use uat_core::NodeId;

/// Default max concurrent admitted calls per caller [`NodeId`].
pub const DEFAULT_MAX_CONCURRENT_CALLS: u32 = 8;
/// Default max admit attempts per caller [`NodeId`] in any 60-second window.
pub const DEFAULT_MAX_CALLS_PER_MINUTE: u32 = 60;
/// Default max live (open) connections per caller [`NodeId`].
pub const DEFAULT_MAX_LIVE_FRAMES: u32 = 8;

const CALLS_PER_MINUTE_WINDOW: Duration = Duration::from_secs(60);

/// Configurable caps for [`RateLimiter`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    /// Max simultaneous admitted calls for one peer.
    pub max_concurrent_calls: u32,
    /// Max admit attempts (success or reject) for one peer per 60s window.
    pub max_calls_per_minute: u32,
    /// Max open connections for one peer.
    pub max_live_frames: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_concurrent_calls: DEFAULT_MAX_CONCURRENT_CALLS,
            max_calls_per_minute: DEFAULT_MAX_CALLS_PER_MINUTE,
            max_live_frames: DEFAULT_MAX_LIVE_FRAMES,
        }
    }
}

impl RateLimitConfig {
    /// Production defaults (see module docs).
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            max_concurrent_calls: DEFAULT_MAX_CONCURRENT_CALLS,
            max_calls_per_minute: DEFAULT_MAX_CALLS_PER_MINUTE,
            max_live_frames: DEFAULT_MAX_LIVE_FRAMES,
        }
    }

    /// Test helper: all three caps set to `n`.
    #[must_use]
    pub const fn tight(n: u32) -> Self {
        Self {
            max_concurrent_calls: n,
            max_calls_per_minute: n,
            max_live_frames: n,
        }
    }
}

/// Why [`RateLimiter::try_admit`] rejected a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RateLimitExceeded {
    /// Peer already holds `max_concurrent_calls` in-flight calls.
    ConcurrentCalls,
    /// Peer exceeded `max_calls_per_minute` in the sliding window.
    CallsPerMinute,
    /// Peer already holds `max_live_frames` open connections.
    LiveFrames,
}

#[derive(Debug, Default)]
struct PeerCounters {
    /// Admitted open connections / in-flight calls.
    in_flight: u32,
    /// Timestamps of recent admit attempts (sliding 60s window).
    attempts: VecDeque<Instant>,
}

/// In-memory per-[`NodeId`] rate limiter.
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    inner: Mutex<HashMap<NodeId, PeerCounters>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

impl RateLimiter {
    /// Create a limiter with `config`.
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Shared handle for [`crate`]/] / node wiring.
    #[must_use]
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Borrow the active caps.
    #[must_use]
    pub const fn config(&self) -> RateLimitConfig {
        self.config
    }

    /// Try to admit a new connection from `peer`.
    ///
    /// On success, increments concurrent / live-frames and records a CPM
    /// attempt. The returned [`RateLimitPermit`] decrements those counters on
    /// drop (call end). Rejected attempts still count toward calls/minute.
    pub fn try_admit(self: &Arc<Self>, peer: NodeId) -> Result<RateLimitPermit, RateLimitExceeded> {
        self.try_admit_at(peer, Instant::now())
    }

    /// [`Self::try_admit`] with an explicit clock (unit tests).
    pub fn try_admit_at(
        self: &Arc<Self>,
        peer: NodeId,
        now: Instant,
    ) -> Result<RateLimitPermit, RateLimitExceeded> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry(peer).or_default();

        // Always record the attempt for CPM (including rejects).
        prune_attempts(&mut entry.attempts, now);
        entry.attempts.push_back(now);
        let attempt_count = entry.attempts.len() as u32;

        if attempt_count > self.config.max_calls_per_minute {
            return Err(RateLimitExceeded::CallsPerMinute);
        }
        if entry.in_flight >= self.config.max_concurrent_calls {
            return Err(RateLimitExceeded::ConcurrentCalls);
        }
        if entry.in_flight >= self.config.max_live_frames {
            return Err(RateLimitExceeded::LiveFrames);
        }

        entry.in_flight = entry.in_flight.saturating_add(1);
        Ok(RateLimitPermit {
            limiter: Arc::clone(self),
            peer,
            released: false,
        })
    }

    fn release(&self, peer: NodeId) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.get_mut(&peer) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
            if entry.in_flight == 0 && entry.attempts.is_empty() {
                guard.remove(&peer);
            }
        }
    }

    /// Current in-flight count for `peer` (tests).
    #[must_use]
    pub fn in_flight(&self, peer: NodeId) -> u32 {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.get(&peer).map(|e| e.in_flight).unwrap_or(0)
    }

    /// Attempt timestamps still inside the CPM window for `peer` (tests).
    #[must_use]
    pub fn attempts_in_window(&self, peer: NodeId, now: Instant) -> u32 {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = guard.get_mut(&peer) else {
            return 0;
        };
        prune_attempts(&mut entry.attempts, now);
        entry.attempts.len() as u32
    }
}

fn prune_attempts(attempts: &mut VecDeque<Instant>, now: Instant) {
    while attempts
        .front()
        .is_some_and(|t| now.saturating_duration_since(*t) >= CALLS_PER_MINUTE_WINDOW)
    {
        attempts.pop_front();
    }
}

/// RAII permit: holds one admitted slot until dropped (call / connection end).
#[derive(Debug)]
pub struct RateLimitPermit {
    limiter: Arc<RateLimiter>,
    peer: NodeId,
    released: bool,
}

impl RateLimitPermit {
    /// Peer this permit was issued for.
    #[must_use]
    pub fn peer(&self) -> NodeId {
        self.peer
    }

    /// Explicitly release early (normally Drop is enough).
    pub fn release(mut self) {
        self.release_now();
    }

    fn release_now(&mut self) {
        if !self.released {
            self.released = true;
            self.limiter.release(self.peer);
        }
    }
}

impl Drop for RateLimitPermit {
    fn drop(&mut self) {
        self.release_now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(b: u8) -> NodeId {
        NodeId::from_bytes([b; 32])
    }

    #[test]
    fn defaults_are_documented_values() {
        let c = RateLimitConfig::default();
        assert_eq!(c.max_concurrent_calls, 8);
        assert_eq!(c.max_calls_per_minute, 60);
        assert_eq!(c.max_live_frames, 8);
    }

    #[test]
    fn concurrent_cap_rejects_before_stream_semantics() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_concurrent_calls: 1,
            max_calls_per_minute: 100,
            max_live_frames: 100,
        })
        .shared();
        let p = peer(1);
        let t0 = Instant::now();
        let _hold = limiter.try_admit_at(p, t0).expect("first");
        assert_eq!(limiter.in_flight(p), 1);
        let err = limiter.try_admit_at(p, t0).unwrap_err();
        assert_eq!(err, RateLimitExceeded::ConcurrentCalls);
        // Reject still counted toward CPM.
        assert_eq!(limiter.attempts_in_window(p, t0), 2);
    }

    #[test]
    fn live_frames_cap_independent_of_concurrent() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_concurrent_calls: 100,
            max_calls_per_minute: 100,
            max_live_frames: 1,
        })
        .shared();
        let p = peer(2);
        let t0 = Instant::now();
        let _hold = limiter.try_admit_at(p, t0).unwrap();
        assert_eq!(
            limiter.try_admit_at(p, t0).unwrap_err(),
            RateLimitExceeded::LiveFrames
        );
    }

    #[test]
    fn calls_per_minute_sliding_window() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_concurrent_calls: 100,
            max_calls_per_minute: 2,
            max_live_frames: 100,
        })
        .shared();
        let p = peer(3);
        let t0 = Instant::now();
        // Admit+release so in_flight stays 0; only CPM matters.
        drop(limiter.try_admit_at(p, t0).unwrap());
        drop(limiter.try_admit_at(p, t0 + Duration::from_secs(1)).unwrap());
        assert_eq!(
            limiter
                .try_admit_at(p, t0 + Duration::from_secs(2))
                .unwrap_err(),
            RateLimitExceeded::CallsPerMinute
        );
        // Advance past the youngest attempt (t0+2s) by a full window.
        let later = t0 + Duration::from_secs(2) + CALLS_PER_MINUTE_WINDOW;
        assert_eq!(limiter.attempts_in_window(p, later), 0);
        limiter.try_admit_at(p, later).expect("window reset");
    }

    #[test]
    fn permit_drop_releases_slot() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_concurrent_calls: 1,
            max_calls_per_minute: 100,
            max_live_frames: 1,
        })
        .shared();
        let p = peer(4);
        {
            let _permit = limiter.try_admit(p).unwrap();
            assert_eq!(limiter.in_flight(p), 1);
        }
        assert_eq!(limiter.in_flight(p), 0);
        limiter.try_admit(p).expect("slot free after drop");
    }

    #[test]
    fn peers_are_independent() {
        let limiter = RateLimiter::new(RateLimitConfig::tight(1)).shared();
        let _a = limiter.try_admit(peer(5)).unwrap();
        limiter.try_admit(peer(6)).expect("other peer");
    }
}
