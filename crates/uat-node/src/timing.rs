//! Protocol timer helpers and QUIC transport config for UAT endpoints.

use std::time::Duration;

use iroh::endpoint::{IdleTimeout, QuicTransportConfig, VarInt};
use uat_core::{Deadline, GRACE_MS, QUIC_IDLE_TIMEOUT_MS, QUIC_KEEP_ALIVE_MS};

/// Callee budget: `deadline` milliseconds from receipt of Submit.
#[must_use]
pub fn callee_budget(deadline: Deadline) -> Duration {
    Duration::from_millis(u64::from(deadline.as_u32()))
}

/// Caller budget: `deadline + GRACE` from Send(Submit) (A1.2.3).
#[must_use]
pub fn caller_budget(deadline: Deadline) -> Duration {
    Duration::from_millis(u64::from(deadline.as_u32()).saturating_add(GRACE_MS))
}

/// QUIC idle timeout duration.
#[must_use]
pub fn quic_idle_timeout() -> Duration {
    Duration::from_millis(QUIC_IDLE_TIMEOUT_MS)
}

/// QUIC keep-alive interval.
#[must_use]
pub fn quic_keep_alive() -> Duration {
    Duration::from_millis(QUIC_KEEP_ALIVE_MS)
}

/// Build the UAT [`QuicTransportConfig`]: idle `10_000` ms, keep-alive `3_000` ms.
#[must_use]
pub fn uat_transport_config() -> QuicTransportConfig {
    let idle: IdleTimeout = VarInt::from_u32(QUIC_IDLE_TIMEOUT_MS as u32).into();
    QuicTransportConfig::builder()
        .max_idle_timeout(Some(idle))
        .keep_alive_interval(quic_keep_alive())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uat_core::Deadline;

    #[test]
    fn caller_budget_is_deadline_plus_grace() {
        let d = Deadline::new(1_000).unwrap();
        assert_eq!(caller_budget(d), Duration::from_millis(1_000 + GRACE_MS));
        assert_eq!(callee_budget(d), Duration::from_millis(1_000));
    }
}
