use super::{RequestScope, Scheduler};
use crate::types::ConcurrencyMode;

#[test]
fn scopes_conflict_immediately_and_release_after_drop() {
    let scheduler = Scheduler::new(4).unwrap();
    let first = scheduler
        .try_acquire(
            1,
            "one",
            RequestScope::normalized(Some(ConcurrencyMode::TaskSpaceTab), Some("a"), Some("x")),
        )
        .unwrap();
    assert!(scheduler
        .try_acquire(
            1,
            "two",
            RequestScope::normalized(Some(ConcurrencyMode::TaskSpaceTab), Some("a"), Some("y")),
        )
        .is_err());
    drop(first);
    assert!(scheduler
        .try_acquire(
            1,
            "three",
            RequestScope::normalized(Some(ConcurrencyMode::TaskSpaceTab), Some("a"), Some("x")),
        )
        .is_ok());
}

#[test]
fn wildcard_uses_binding_lock() {
    let scheduler = Scheduler::new(4).unwrap();
    let first = scheduler
        .try_acquire(
            1,
            "one",
            RequestScope::normalized(Some(ConcurrencyMode::TaskSpaceTab), Some("a"), Some("*")),
        )
        .unwrap();
    assert!(scheduler
        .try_acquire(
            1,
            "two",
            RequestScope::normalized(Some(ConcurrencyMode::TaskSpace), Some("b"), None),
        )
        .is_err());
    drop(first);
}

#[test]
fn same_tab_name_in_different_task_spaces_does_not_conflict() {
    let scheduler = Scheduler::new(4).unwrap();
    let first = scheduler
        .try_acquire(
            1,
            "one",
            RequestScope::normalized(
                Some(ConcurrencyMode::TaskSpaceTab),
                Some("space-a"),
                Some("tab-1"),
            ),
        )
        .unwrap();
    assert!(scheduler
        .try_acquire(
            1,
            "two",
            RequestScope::normalized(
                Some(ConcurrencyMode::TaskSpaceTab),
                Some("space-b"),
                Some("tab-1"),
            ),
        )
        .is_ok());
    assert!(first.matches(1, "one"));
}
