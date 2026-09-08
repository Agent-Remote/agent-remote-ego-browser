use std::time::Duration;

/// Lease health sub-state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseHealth {
    Healthy,
    RenewalGrace,
    Expired,
}

/// Lease timing policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeasePolicy {
    pub lease_seconds: u64,
    pub renew_interval_seconds: u64,
    pub failure_grace_seconds: u64,
    pub admission_min_remaining_seconds: u64,
    pub execute_max: Duration,
    pub absolute_ttl_seconds: u64,
}

impl Default for LeasePolicy {
    fn default() -> Self {
        Self {
            lease_seconds: crate::DEFAULT_LEASE_SECONDS,
            renew_interval_seconds: crate::LEASE_RENEW_INTERVAL_SECONDS,
            failure_grace_seconds: crate::LEASE_RENEW_FAILURE_GRACE_SECONDS,
            admission_min_remaining_seconds: crate::LEASE_ADMISSION_MIN_REMAINING_SECONDS,
            execute_max: Duration::from_millis(crate::MAX_EXECUTE_TIMEOUT_MS),
            absolute_ttl_seconds: crate::ABSOLUTE_BINDING_TTL_SECONDS,
        }
    }
}

/// Mutable lease state used by broker and bridge guards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseState {
    pub generation: u64,
    pub activated_at: u64,
    pub lease_until: u64,
    pub absolute_ttl_until: u64,
    pub health: LeaseHealth,
    pub grace_until: Option<u64>,
    pub revoked: bool,
}

impl LeaseState {
    /// Create a fresh lease at a given Unix timestamp.
    pub fn new(generation: u64, now: u64, policy: LeasePolicy) -> Self {
        Self {
            generation,
            activated_at: now,
            lease_until: now.saturating_add(policy.lease_seconds),
            absolute_ttl_until: now.saturating_add(policy.absolute_ttl_seconds),
            health: LeaseHealth::Healthy,
            grace_until: None,
            revoked: false,
        }
    }

    /// Check whether a new request may be admitted at `now`.
    pub fn admit(&self, now: u64, policy: LeasePolicy) -> Admission {
        if self.revoked {
            return Admission::BindingRevoked;
        }
        if now >= self.absolute_ttl_until || now >= self.lease_until {
            return Admission::Expired;
        }
        if self.health != LeaseHealth::Healthy {
            return Admission::RenewalRequired;
        }
        if self.lease_until.saturating_sub(now) < policy.admission_min_remaining_seconds {
            return Admission::RenewalRequired;
        }
        Admission::Allowed
    }

    /// Mark a failed renewal and begin the bounded grace interval.
    pub fn renewal_failed(&mut self, now: u64, policy: LeasePolicy) {
        if self.revoked || now >= self.absolute_ttl_until {
            self.health = LeaseHealth::Expired;
            self.grace_until = None;
            return;
        }
        self.health = LeaseHealth::RenewalGrace;
        self.grace_until = Some(now.saturating_add(policy.failure_grace_seconds));
    }

    /// Apply a successful compare-and-swap renewal.
    pub fn renew(
        &mut self,
        expected_generation: u64,
        now: u64,
        policy: LeasePolicy,
    ) -> RenewalOutcome {
        if self.revoked || expected_generation != self.generation {
            return RenewalOutcome::Rejected;
        }
        if now >= self.absolute_ttl_until {
            self.health = LeaseHealth::Expired;
            return RenewalOutcome::Expired;
        }
        let candidate = now
            .saturating_add(policy.lease_seconds)
            .min(self.absolute_ttl_until);
        if candidate <= now {
            self.health = LeaseHealth::Expired;
            return RenewalOutcome::Expired;
        }
        self.lease_until = candidate;
        self.health = LeaseHealth::Healthy;
        self.grace_until = None;
        RenewalOutcome::Renewed(candidate)
    }

    /// Advance expiry/grace state using a monotonic wall-clock sample.
    pub fn observe(&mut self, now: u64) -> LeaseHealth {
        if self.revoked || now >= self.absolute_ttl_until {
            self.health = LeaseHealth::Expired;
            return self.health;
        }
        let grace_expired = self.health == LeaseHealth::RenewalGrace
            && self.grace_until.is_some_and(|deadline| now >= deadline);
        let lease_expired = self.health == LeaseHealth::Healthy && now >= self.lease_until;
        if grace_expired || lease_expired {
            self.health = LeaseHealth::Expired;
        }
        self.health
    }

    /// Revoke the lease and make all permits invalid.
    pub fn revoke(&mut self) {
        self.revoked = true;
        self.health = LeaseHealth::Expired;
        self.grace_until = None;
    }
}

/// Result of admission checking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    RenewalRequired,
    Expired,
    BindingRevoked,
}

/// Result of a renewal CAS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenewalOutcome {
    Renewed(u64),
    Rejected,
    Expired,
}
