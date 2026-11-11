//! The `refresh_reports` task (P3-A04, FR-2.1, #36): one fresh configuration, inventory, and package
//! report each, sent now.
//!
//! The task has no parameters (the catalog, P3-S01: it always refreshes all three, as the dashboard's
//! "Request fresh reports" does), so anything in `parameters` is refused `invalid_params` with nothing
//! run. It collects and sends nothing itself: it asks the report loops ([`crate::report::refresh`]),
//! which treat the ask like the heartbeat's `report_request` directive (DEC-13). Each type's one
//! reporter collects after the ask, sends with its own retries and report id, and so never sends a
//! second report beside a scheduled one or a directive's (no duplicate snapshots). No program is run,
//! so the catalog's `read_only` privilege is all it needs and more than it uses.
//!
//! **Result.** The task waits until each of the three reports, collected after it asked, has been
//! accepted or rejected by the server:
//!
//! - all three accepted: `succeeded`, `details.reports_sent` = `["config", "inventory", "packages"]`;
//! - any rejected for its content: `failed` with `agent_error` (the agent built a report the server
//!   refuses), `reports_sent` listing those accepted;
//! - still waiting at the deadline (the server unreachable, a report that could not be built): the
//!   executor reports `timed_out`; the output says which were sent.
//!
//! It is interruptible (catalog): a cancel or the agent stopping ends the wait at once and withdraws the
//! asks no loop has taken yet; a report already being collected is sent all the same, as a scheduled
//! one would be. The output names each report as it is accepted or rejected.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value};

use super::executor::{Finish, Job, Run, Stop, TaskImpl, parse};
use super::ledger::Outcome;
use super::settings::TaskSettings;
use crate::report::{Refresh, ReportType};

/// The catalog type id.
pub const TYPE_ID: &str = "refresh_reports";

/// How often the wait looks at the deadline and the server's cancel, at most.
const POLL: Duration = Duration::from_millis(250);

/// The task type.
pub struct RefreshReports {
    reports: Arc<Refresh>,
}

impl RefreshReports {
    pub fn new(reports: Arc<Refresh>) -> Self {
        Self { reports }
    }
}

/// The catalog's parameters: none.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {}

impl TaskImpl for RefreshReports {
    fn type_id(&self) -> &'static str {
        TYPE_ID
    }

    fn prepare(&self, parameters: &Value, _: &TaskSettings) -> Result<Box<dyn Job>, &'static str> {
        let Params {} = parse(parameters)?;
        Ok(Box::new(RefreshJob {
            reports: Arc::clone(&self.reports),
        }))
    }
}

struct RefreshJob {
    reports: Arc<Refresh>,
}

impl Job for RefreshJob {
    fn run(&self, run: &mut Run<'_>) -> Result<Finish, Stop> {
        let types = ReportType::ALL;
        let since = self.reports.ask(&types);
        run.note("asked for a fresh config, inventory, and packages report");
        let mut ended: [Option<bool>; 3] = [None; 3];
        loop {
            for (i, ty) in types.iter().enumerate() {
                if ended[i].is_some() {
                    continue;
                }
                if let Some(accepted) = self.reports.outcome(*ty, since) {
                    ended[i] = Some(accepted);
                    run.note(&if accepted {
                        format!("{} report sent and accepted", ty.name())
                    } else {
                        format!(
                            "{} report rejected by the server for its content (see the agent's log)",
                            ty.name()
                        )
                    });
                }
            }
            if ended.iter().all(Option::is_some) {
                break;
            }
            if let Some(stop) = run.stopped() {
                self.reports.withdraw(&types);
                return Err(stop);
            }
            self.reports.wait(POLL);
        }
        let sent: Vec<Value> = types
            .iter()
            .zip(ended)
            .filter(|(_, accepted)| *accepted == Some(true))
            .map(|(ty, _)| Value::from(ty.name()))
            .collect();
        let all = sent.len() == types.len();
        let mut details = Map::new();
        details.insert("reports_sent".into(), Value::Array(sent));
        Ok(Finish {
            outcome: if all {
                Outcome::Succeeded
            } else {
                Outcome::Failed
            },
            reason: (!all).then_some("agent_error"),
            exit_status: None,
            details,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use serde_json::json;

    use super::*;
    use crate::report::refresh::Done;
    use crate::shutdown::Shutdown;
    use crate::tasks::executor::tests::{TestControl, delivered};
    use crate::tasks::executor::{Executor, Registry};

    fn registry(reports: &Arc<Refresh>) -> Registry {
        Registry::new(
            vec![Box::new(RefreshReports::new(Arc::clone(reports)))],
            TaskSettings::default(),
            // Never asked: this type runs no program, let alone one in a transient unit.
            Box::new(crate::tasks::executor::unit::Systemd),
        )
    }

    /// Stands in for the three report loops: takes each ask and settles it as `accept` says.
    fn loops(reports: &Refresh, accept: impl Fn(ReportType) -> Option<bool>, stop: &Shutdown) {
        while !stop.is_requested() {
            for ty in ReportType::ALL {
                if reports.take(ty)
                    && let Some(accepted) = accept(ty)
                {
                    reports.settle(
                        ty,
                        Done {
                            built_at: Instant::now(),
                            accepted,
                        },
                    );
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn run_with_loops(
        accept: impl Fn(ReportType) -> Option<bool> + Sync,
        parameters: Value,
        timeout: u64,
        control: &TestControl,
    ) -> crate::tasks::executor::Execution {
        let reports = Arc::new(Refresh::new());
        let registry = registry(&reports);
        let task = delivered(TYPE_ID, parameters, timeout);
        registry.check(&task).expect("passes its checks");
        let stop = Shutdown::default();
        std::thread::scope(|scope| {
            scope.spawn(|| loops(&reports, &accept, &stop));
            let ran = registry.run(&task, control).expect("not detached");
            stop.request();
            ran
        })
    }

    #[test]
    fn fresh_reports_of_all_three_types_succeed_and_are_listed() {
        let ran = run_with_loops(|_| Some(true), json!({}), 60, &TestControl::default());
        assert_eq!((ran.outcome, ran.reason), (Outcome::Succeeded, None));
        assert_eq!(
            Value::Object(ran.details.clone()),
            json!({"reports_sent": ["config", "inventory", "packages"]})
        );
        assert_eq!(ran.exit_status, None);
        for ty in ["config", "inventory", "packages"] {
            assert!(
                ran.output
                    .contains(&format!("{ty} report sent and accepted")),
                "{}",
                ran.output
            );
        }
    }

    #[test]
    fn a_rejected_report_fails_the_task_and_is_left_out_of_reports_sent() {
        let ran = run_with_loops(
            |ty| Some(ty != ReportType::Packages),
            json!({}),
            60,
            &TestControl::default(),
        );
        assert_eq!(
            (ran.outcome, ran.reason),
            (Outcome::Failed, Some("agent_error"))
        );
        assert_eq!(ran.details["reports_sent"], json!(["config", "inventory"]));
        assert!(
            ran.output.contains("packages report rejected"),
            "{}",
            ran.output
        );
    }

    #[test]
    fn a_report_that_never_arrives_times_out_saying_what_was_sent() {
        let started = Instant::now();
        let ran = run_with_loops(
            |ty| (ty == ReportType::Config).then_some(true),
            json!({}),
            1,
            &TestControl::default(),
        );
        assert_eq!(ran.outcome, Outcome::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(ran.output.contains("config report sent and accepted"));
        assert!(!ran.output.contains("inventory report sent"));
    }

    #[test]
    fn a_cancel_stops_the_wait_and_withdraws_the_asks() {
        let reports = Arc::new(Refresh::new());
        let registry = registry(&reports);
        let control = TestControl::default();
        control.cancel.set(true);
        let ran = registry
            .run(&delivered(TYPE_ID, json!({}), 60), &control)
            .unwrap();
        assert_eq!(ran.outcome, Outcome::Cancelled);
        for ty in ReportType::ALL {
            assert!(!reports.take(ty), "{ty:?} still asked for");
        }

        let control = TestControl::default();
        control.shutdown.request();
        let ran = registry
            .run(&delivered(TYPE_ID, json!({}), 60), &control)
            .unwrap();
        assert_eq!(
            (ran.outcome, ran.reason),
            (Outcome::Failed, Some("interrupted"))
        );
    }

    #[test]
    fn a_report_built_before_the_task_asked_does_not_count() {
        // A report collected earlier and accepted only now (it waited for its retry) is not fresh.
        let reports = Arc::new(Refresh::new());
        let before = Instant::now();
        let registry = registry(&reports);
        let stop = Shutdown::default();
        let ran = std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut stale_sent = false;
                while !stop.is_requested() {
                    for ty in ReportType::ALL {
                        if !stale_sent {
                            reports.settle(
                                ty,
                                Done {
                                    built_at: before,
                                    accepted: true,
                                },
                            );
                        }
                    }
                    stale_sent = true;
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            let ran = registry
                .run(&delivered(TYPE_ID, json!({}), 1), &TestControl::default())
                .unwrap();
            stop.request();
            ran
        });
        assert_eq!(ran.outcome, Outcome::TimedOut, "{}", ran.output);
    }

    #[test]
    fn any_parameter_is_refused_with_nothing_asked() {
        // P3-A04 AC: the catalog gives this type no parameters, so a report type list (or anything
        // else) is invalid.
        let reports = Arc::new(Refresh::new());
        let registry = registry(&reports);
        for parameters in [
            json!({"types": ["config"]}),
            json!({"types": ["vulnerabilities"]}),
            json!({"command": "id"}),
            json!([]),
            json!(null),
            json!("config"),
        ] {
            assert_eq!(
                registry.check(&delivered(TYPE_ID, parameters.clone(), 60)),
                Err("invalid_params"),
                "{parameters}"
            );
        }
        for ty in ReportType::ALL {
            assert!(!reports.take(ty));
        }
    }
}
