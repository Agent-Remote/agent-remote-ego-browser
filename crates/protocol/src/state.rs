use std::fmt;

/// Persisted binding lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingState {
    PendingDevice,
    Connecting,
    ProbingLocalBrowser,
    Active,
    Paused,
    Stopping,
    Stopped,
    Expired,
    Failed,
    Revoked,
}

impl BindingState {
    /// Return the wire representation used by the control plane.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingDevice => "pending_device",
            Self::Connecting => "connecting",
            Self::ProbingLocalBrowser => "probing_local_browser",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Expired => "expired",
            Self::Failed => "failed",
            Self::Revoked => "revoked",
        }
    }

    /// Check whether a transition is permitted by the binding state machine.
    pub fn can_transition_to(self, next: Self) -> bool {
        if matches!(
            self,
            Self::Stopped | Self::Expired | Self::Failed | Self::Revoked
        ) {
            return false;
        }
        matches!(
            (self, next),
            (
                Self::PendingDevice,
                Self::Connecting | Self::Expired | Self::Failed | Self::Revoked
            ) | (
                Self::Connecting,
                Self::ProbingLocalBrowser | Self::Expired | Self::Failed | Self::Revoked
            ) | (
                Self::ProbingLocalBrowser,
                Self::Active | Self::Expired | Self::Failed | Self::Revoked
            ) | (
                Self::Active,
                Self::Paused | Self::Stopping | Self::Expired | Self::Failed | Self::Revoked
            ) | (
                Self::Paused,
                Self::Active | Self::Stopping | Self::Expired | Self::Failed | Self::Revoked
            ) | (
                Self::Stopping,
                Self::Stopped | Self::Expired | Self::Failed | Self::Revoked
            )
        )
    }

    /// Apply a validated transition.
    pub fn transition(&mut self, next: Self) -> Result<(), StateError> {
        if !self.can_transition_to(next) {
            return Err(StateError::InvalidTransition {
                from: self.as_str(),
                to: next.as_str(),
            });
        }
        *self = next;
        Ok(())
    }
}

/// Local execution state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionState {
    Idle,
    Accepting,
    Running,
    CollectingOutput,
    Completed,
    Cancelled,
    TimedOut,
    BindingRevoked,
    BridgeFailed,
    UnknownResult,
}

impl ExecutionState {
    /// Return the wire representation used by responses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Accepting => "accepting",
            Self::Running => "running",
            Self::CollectingOutput => "collecting_output",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::BindingRevoked => "binding_revoked",
            Self::BridgeFailed => "bridge_failed",
            Self::UnknownResult => "unknown_result",
        }
    }

    /// Check and apply an execution transition.
    pub fn transition(&mut self, next: Self) -> Result<(), StateError> {
        let valid = matches!(
            (*self, next),
            (Self::Idle, Self::Accepting)
                | (Self::Accepting, Self::Running)
                | (Self::Running, Self::CollectingOutput)
                | (Self::CollectingOutput, Self::Completed)
                | (
                    Self::Accepting | Self::Running | Self::CollectingOutput,
                    Self::Cancelled
                        | Self::TimedOut
                        | Self::BindingRevoked
                        | Self::BridgeFailed
                        | Self::UnknownResult
                )
        );
        if !valid {
            return Err(StateError::InvalidTransition {
                from: self.as_str(),
                to: next.as_str(),
            });
        }
        *self = next;
        Ok(())
    }
}

/// State-machine errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateError {
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(formatter, "invalid transition {from} -> {to}")
            }
        }
    }
}

impl std::error::Error for StateError {}
