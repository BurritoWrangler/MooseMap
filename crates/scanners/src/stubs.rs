//! Planned tool adapters, stubbed.
//!
//! These implement the [`StageExecutor`] trait so the pipeline is complete end
//! to end, but they don't yet drive their tools. Each one detects whether its
//! binary is installed and returns a clear [`StageOutcome::Skipped`] explaining
//! what remains to be implemented. Fleshing one out means replacing the body of
//! `execute` with real argument-building + output parsing, following the shape
//! of the nmap adapter.

use crate::tool;
use moosemap_core::engine::{async_trait, StageContext, StageExecutor, StageOutcome};
use moosemap_core::model::Stage;

/// Macro to define a simple "planned" executor stub.
macro_rules! planned_stub {
    ($ty:ident, $stage:expr, $name:literal, $bin:literal, $note:literal) => {
        #[doc = concat!("Planned adapter for `", $bin, "`. Not yet implemented.")]
        pub struct $ty;

        #[async_trait]
        impl StageExecutor for $ty {
            fn stage(&self) -> Stage {
                $stage
            }
            fn name(&self) -> &str {
                $name
            }
            async fn execute(
                &self,
                ctx: &StageContext,
            ) -> anyhow::Result<StageOutcome> {
                let installed = tool::is_installed($bin);
                let reason = if installed {
                    concat!($bin, " present but adapter not yet implemented: ", $note)
                } else {
                    concat!($bin, " not installed (planned: ", $note, ")")
                };
                ctx.info(format!("{} -> skipped ({reason})", $name));
                Ok(StageOutcome::Skipped(reason.to_string()))
            }
        }
    };
}

planned_stub!(
    MasscanPortScan,
    Stage::PortScan,
    "masscan-portscan",
    "masscan",
    "high-rate port sweeping to complement nmap"
);

// NOTE: nmap, httpx (web recon), nuclei (vuln scan) and subfinder (discovery)
// are now real adapters in their own modules. masscan remains a planned stub.

#[cfg(test)]
mod tests {
    use super::*;
    use moosemap_core::engine::Engine;
    use moosemap_core::{Run, ScopeGuard};
    use std::sync::Arc;

    #[tokio::test]
    async fn stub_skips_gracefully() {
        // A pipeline made only of the stub completes (as all-skipped), never fails.
        let engine = Engine::new(vec![Arc::new(MasscanPortScan)], 64);
        let run = Run::new("stub", vec!["192.0.2.0/24".into()]);
        let scope = Arc::new(ScopeGuard::from_input("192.0.2.0/24").unwrap());
        let result = engine.run(&run, scope).await;
        assert_eq!(result.status, moosemap_core::RunStatus::Completed);
    }
}
