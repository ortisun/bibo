//! The call budget of the server (ADR 0021, decision 4, item 4), per scope (TR-6 of the security
//! review).
//!
//! One budget for every clone of a server was one budget for every run of a long-lived gateway:
//! the probes alone spent it within hours, and every `pg_*` call failed after that for the rest
//! of the process. A budget is now one of:
//!
//! - [`BudgetScope::Window`]: one budget for the server, renewed every window. `apps/mcp-postgres`
//!   serves one engineer this way; the window is in its configuration.
//! - [`BudgetScope::PerCallerScope`]: one budget per scope the caller names in the request's
//!   `_meta`, under [`BUDGET_SCOPE_META_KEY`]. The gateway names the run, so each troubleshooting
//!   run has a budget of its own. Only a trusted in-process caller may be served this way: a
//!   remote client could name a new scope for each call. A call that names no scope is refused.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

pub use factory_domain::troubleshooting::BUDGET_SCOPE_META_KEY;

use crate::ToolFailure;

/// How many caller scopes are remembered at most. Past it the oldest is forgotten (a run that
/// ended long ago).
pub const MAX_SCOPES: usize = 256;

/// The longest scope name accepted, in bytes.
const MAX_SCOPE_BYTES: usize = 128;

/// What one budget covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetScope {
    /// One budget for the server, renewed when the window has passed since it started.
    Window(Duration),
    /// One budget per scope named in the request's `_meta` under [`BUDGET_SCOPE_META_KEY`]. For a
    /// trusted in-process caller only.
    PerCallerScope,
}

/// The default window of [`BudgetScope::Window`]: one hour.
pub const DEFAULT_BUDGET_WINDOW: Duration = Duration::from_secs(3600);

#[derive(Debug)]
struct State {
    window_started: Instant,
    used_in_window: u64,
    by_scope: HashMap<String, u64>,
    order: VecDeque<String>,
}

/// The budgets of one server, shared by its clones.
#[derive(Debug)]
pub(crate) struct CallBudgets {
    scope: BudgetScope,
    max_calls: u64,
    state: Mutex<State>,
}

impl CallBudgets {
    pub(crate) fn new(scope: BudgetScope, max_calls: u64) -> Self {
        Self {
            scope,
            max_calls,
            state: Mutex::new(State {
                window_started: Instant::now(),
                used_in_window: 0,
                by_scope: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    pub(crate) fn scope(&self) -> BudgetScope {
        self.scope
    }

    /// Charges one call, or refuses it.
    ///
    /// # Errors
    /// [`ToolFailure::CallBudgetSpent`] when the budget of the window or of the caller's scope is
    /// spent; [`ToolFailure::Refused`] when the server budgets by caller scope and the call names
    /// none, or one that is not a short printable name.
    pub(crate) fn charge(&self, caller_scope: Option<&str>) -> Result<(), ToolFailure> {
        let spent = ToolFailure::CallBudgetSpent {
            limit: self.max_calls,
        };
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match self.scope {
            BudgetScope::Window(window) => {
                if state.window_started.elapsed() >= window {
                    state.window_started = Instant::now();
                    state.used_in_window = 0;
                }
                if state.used_in_window >= self.max_calls {
                    return Err(spent);
                }
                state.used_in_window += 1;
                Ok(())
            }
            BudgetScope::PerCallerScope => {
                let Some(name) = caller_scope.filter(|name| {
                    !name.is_empty()
                        && name.len() <= MAX_SCOPE_BYTES
                        && name.bytes().all(|b| b.is_ascii_graphic())
                }) else {
                    return Err(ToolFailure::Refused(
                        "this server budgets calls per run, and the call names no run".to_owned(),
                    ));
                };
                if !state.by_scope.contains_key(name) {
                    while state.order.len() >= MAX_SCOPES {
                        if let Some(oldest) = state.order.pop_front() {
                            state.by_scope.remove(&oldest);
                        }
                    }
                    state.order.push_back(name.to_owned());
                    state.by_scope.insert(name.to_owned(), 0);
                }
                let used = state.by_scope.entry(name.to_owned()).or_insert(0);
                if *used >= self.max_calls {
                    return Err(spent);
                }
                *used += 1;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_caller_scope_has_its_own_budget() {
        let budgets = CallBudgets::new(BudgetScope::PerCallerScope, 2);
        for run in ["run-1", "run-2"] {
            assert_eq!(budgets.charge(Some(run)), Ok(()));
            assert_eq!(budgets.charge(Some(run)), Ok(()));
            assert_eq!(
                budgets.charge(Some(run)),
                Err(ToolFailure::CallBudgetSpent { limit: 2 })
            );
        }
        assert!(matches!(budgets.charge(None), Err(ToolFailure::Refused(_))));
        assert!(matches!(
            budgets.charge(Some("")),
            Err(ToolFailure::Refused(_))
        ));
        assert!(matches!(
            budgets.charge(Some("a run")),
            Err(ToolFailure::Refused(_))
        ));
    }

    #[test]
    fn the_oldest_scope_is_forgotten_past_the_cap() {
        let budgets = CallBudgets::new(BudgetScope::PerCallerScope, 1);
        assert_eq!(budgets.charge(Some("first")), Ok(()));
        for n in 0..MAX_SCOPES {
            assert_eq!(budgets.charge(Some(&format!("run-{n}"))), Ok(()));
        }
        // "first" was forgotten, so it starts again; the newest is still spent.
        assert_eq!(budgets.charge(Some("first")), Ok(()));
        assert!(
            budgets
                .charge(Some(&format!("run-{}", MAX_SCOPES - 1)))
                .is_err()
        );
    }

    #[test]
    fn a_window_budget_renews_when_the_window_passes() {
        let budgets = CallBudgets::new(BudgetScope::Window(Duration::from_millis(50)), 1);
        assert_eq!(budgets.charge(Some("ignored")), Ok(()));
        assert!(budgets.charge(None).is_err());
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(budgets.charge(None), Ok(()));
        assert_eq!(
            budgets.scope(),
            BudgetScope::Window(Duration::from_millis(50))
        );
    }
}
