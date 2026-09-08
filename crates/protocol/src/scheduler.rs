use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::types::{ConcurrencyMode, ProtocolError};

/// Normalized collaboration-lock declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestScope {
    pub mode: ConcurrencyMode,
    pub task_space: Option<String>,
    pub tab: Option<String>,
}

impl RequestScope {
    /// Normalize missing, wildcard, or malformed scopes to a binding lock.
    pub fn normalized(
        mode: Option<ConcurrencyMode>,
        task_space: Option<&str>,
        tab: Option<&str>,
    ) -> Self {
        let mode = mode.unwrap_or(ConcurrencyMode::Binding);
        let task_space = task_space.map(str::trim).filter(|value| !value.is_empty());
        let tab = tab.map(str::trim).filter(|value| !value.is_empty());
        if mode == ConcurrencyMode::Binding
            || task_space.is_none()
            || task_space.is_some_and(|value| !valid_scope(value))
            || task_space.is_some_and(|value| value.contains('*'))
            || (mode == ConcurrencyMode::TaskSpaceTab
                && (tab.is_none()
                    || tab.is_some_and(|value| value.contains('*') || !valid_scope(value))))
        {
            return Self {
                mode: ConcurrencyMode::Binding,
                task_space: None,
                tab: None,
            };
        }
        Self {
            mode,
            task_space: task_space.map(str::to_owned),
            tab: tab.map(str::to_owned),
        }
    }
}

struct SchedulerInner {
    active: usize,
    binding_held: bool,
    keys: HashSet<String>,
}

/// Immediate-fail scheduler for normal requests.
#[derive(Clone)]
pub struct Scheduler {
    maximum: usize,
    inner: Arc<Mutex<SchedulerInner>>,
}

impl Scheduler {
    /// Create a scheduler with a hard parallelism limit.
    pub fn new(maximum: usize) -> Result<Self, SchedulerError> {
        if maximum == 0 || maximum > 4 {
            return Err(SchedulerError::InvalidMaximum);
        }
        Ok(Self {
            maximum,
            inner: Arc::new(Mutex::new(SchedulerInner {
                active: 0,
                binding_held: false,
                keys: HashSet::new(),
            })),
        })
    }

    /// Try to acquire all locks in Task Space -> Tab order without queueing.
    pub fn try_acquire(
        &self,
        generation: u64,
        request_id: impl Into<String>,
        scope: RequestScope,
    ) -> Result<PermitGuard, SchedulerError> {
        let request_id = request_id.into();
        let mut state = self.inner.lock().map_err(|_| SchedulerError::Poisoned)?;
        if state.active >= self.maximum {
            return Err(SchedulerError::LimitReached);
        }
        let keys = lock_keys(&scope);
        if scope.mode == ConcurrencyMode::Binding {
            if state.active != 0 || state.binding_held {
                return Err(SchedulerError::Conflict);
            }
        } else if state.binding_held || keys.iter().any(|key| state.keys.contains(key)) {
            return Err(SchedulerError::Conflict);
        }
        for key in &keys {
            state.keys.insert(key.clone());
        }
        state.binding_held |= scope.mode == ConcurrencyMode::Binding;
        state.active += 1;
        Ok(PermitGuard {
            scheduler: Arc::clone(&self.inner),
            keys,
            binding: scope.mode == ConcurrencyMode::Binding,
            generation,
            request_id,
        })
    }

    /// Return the current number of active guarded requests.
    pub fn active_count(&self) -> usize {
        self.inner
            .lock()
            .map(|state| state.active)
            .unwrap_or(self.maximum)
    }

    /// Return the configured maximum.
    pub const fn maximum(&self) -> usize {
        self.maximum
    }
}

fn lock_keys(scope: &RequestScope) -> Vec<String> {
    match scope.mode {
        ConcurrencyMode::Binding => vec!["binding".to_owned()],
        ConcurrencyMode::TaskSpace => vec![format!(
            "task-space:{}",
            scope.task_space.as_deref().unwrap_or_default()
        )],
        ConcurrencyMode::TaskSpaceTab => vec![
            format!(
                "task-space:{}",
                scope.task_space.as_deref().unwrap_or_default()
            ),
            format!(
                "tab:{}:{}",
                scope.task_space.as_deref().unwrap_or_default(),
                scope.tab.as_deref().unwrap_or_default()
            ),
        ],
    }
}

fn valid_scope(value: &str) -> bool {
    value.len() <= 256 && value.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
}

/// RAII guard for scheduler locks and permit lifetime.
pub struct PermitGuard {
    scheduler: Arc<Mutex<SchedulerInner>>,
    keys: Vec<String>,
    binding: bool,
    /// Generation this permit belongs to.
    pub generation: u64,
    /// Request identifier bound to this permit.
    pub request_id: String,
}

impl Drop for PermitGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.scheduler.lock() {
            // Remove in reverse acquisition order, mirroring the documented lock discipline.
            for key in self.keys.iter().rev() {
                state.keys.remove(key);
            }
            if self.binding {
                state.binding_held = false;
            }
            state.active = state.active.saturating_sub(1);
        }
    }
}

impl PermitGuard {
    /// Check that a caller still refers to the request represented by this guard.
    pub fn matches(&self, generation: u64, request_id: &str) -> bool {
        self.generation == generation && self.request_id == request_id
    }
}

/// Scheduler failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerError {
    InvalidMaximum,
    LimitReached,
    Conflict,
    Poisoned,
}

impl std::fmt::Display for SchedulerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidMaximum => "invalid maximum parallel requests",
            Self::LimitReached => "maximum parallel requests reached",
            Self::Conflict => "concurrency conflict",
            Self::Poisoned => "scheduler state unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SchedulerError {}

impl From<SchedulerError> for ProtocolError {
    fn from(error: SchedulerError) -> Self {
        match error {
            SchedulerError::Conflict | SchedulerError::LimitReached => {
                ProtocolError::ConcurrencyConflict
            }
            _ => ProtocolError::Io(error.to_string()),
        }
    }
}

#[cfg(test)]
#[path = "tests/scheduler.rs"]
mod tests;
