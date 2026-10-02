use crate::system::windows_tools::{
    execute, prepare, ExecutionApproval, PreparedToolCommand, ToolExecutionResult, WindowsTool,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum SystemFinding {
    ComponentStoreCorruption,
    ProtectedSystemFileCorruption,
    DefenderSignaturesOutdated,
    DnsResolutionIssue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepairPlanState {
    Draft,
    Approved,
    Executed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairStep {
    pub step_id: String,
    pub finding: SystemFinding,
    pub command: PreparedToolCommand,
    pub requires_restore_point: bool,
    pub requires_explicit_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairPlan {
    pub plan_id: String,
    pub created_at: String,
    pub state: RepairPlanState,
    pub dry_run: bool,
    pub steps: Vec<RepairStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairPlanResult {
    pub plan: RepairPlan,
    pub approved_steps: usize,
    pub blocked_steps: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepairExecutionState {
    NotApproved,
    Completed,
    PartiallyCompleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairStepExecution {
    pub step: RepairStep,
    pub result: Option<ToolExecutionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairExecutionResult {
    pub plan: RepairPlan,
    pub state: RepairExecutionState,
    pub executed_steps: usize,
    pub succeeded_steps: usize,
    pub failed_steps: usize,
    pub steps: Vec<RepairStepExecution>,
}

pub fn create_plan(findings: &[SystemFinding]) -> RepairPlan {
    let steps = findings
        .iter()
        .enumerate()
        .map(|(index, finding)| {
            let command = prepare(tool_for_finding(finding));

            RepairStep {
                step_id: format!("repair-step-{}", index + 1),
                finding: finding.clone(),
                requires_restore_point: command.safety
                    == crate::system::windows_tools::ToolSafety::ChangesSystem,
                requires_explicit_approval: command.safety
                    == crate::system::windows_tools::ToolSafety::ChangesSystem,
                command,
            }
        })
        .collect();

    RepairPlan {
        plan_id: format!(
            "repair-plan-{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ),
        created_at: Utc::now().to_rfc3339(),
        state: RepairPlanState::Draft,
        dry_run: true,
        steps,
    }
}

pub fn approve_plan(mut plan: RepairPlan, approval: ExecutionApproval) -> RepairPlanResult {
    let approved_steps = plan
        .steps
        .iter()
        .filter(|step| crate::system::windows_tools::may_execute(&step.command, approval))
        .count();

    let blocked_steps = plan.steps.len() - approved_steps;

    if blocked_steps == 0 {
        plan.state = RepairPlanState::Approved;
        plan.dry_run = false;
    }

    RepairPlanResult {
        plan,
        approved_steps,
        blocked_steps,
    }
}

pub fn execute_plan(mut plan: RepairPlan, approval: ExecutionApproval) -> RepairExecutionResult {
    let approved =
        plan.state == RepairPlanState::Approved && !plan.dry_run && approval.explicitly_approved;

    if !approved {
        return RepairExecutionResult {
            executed_steps: 0,
            succeeded_steps: 0,
            failed_steps: 0,
            state: RepairExecutionState::NotApproved,
            steps: plan
                .steps
                .iter()
                .cloned()
                .map(|step| RepairStepExecution { step, result: None })
                .collect(),
            plan,
        };
    }

    let mut executions = Vec::with_capacity(plan.steps.len());
    let mut succeeded_steps = 0usize;

    for step in &plan.steps {
        let result = execute(step.command.tool, approval);

        if result.success {
            succeeded_steps += 1;
        }

        executions.push(RepairStepExecution {
            step: step.clone(),
            result: Some(result),
        });
    }

    let executed_steps = executions.len();
    let failed_steps = executed_steps.saturating_sub(succeeded_steps);

    plan.state = RepairPlanState::Executed;

    RepairExecutionResult {
        plan,
        state: if failed_steps == 0 {
            RepairExecutionState::Completed
        } else {
            RepairExecutionState::PartiallyCompleted
        },
        executed_steps,
        succeeded_steps,
        failed_steps,
        steps: executions,
    }
}

fn tool_for_finding(finding: &SystemFinding) -> WindowsTool {
    match finding {
        SystemFinding::ComponentStoreCorruption => WindowsTool::DismRestoreHealth,
        SystemFinding::ProtectedSystemFileCorruption => WindowsTool::SfcRepair,
        SystemFinding::DefenderSignaturesOutdated => WindowsTool::DefenderSignatureUpdate,
        SystemFinding::DnsResolutionIssue => WindowsTool::FlushDnsCache,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_plan_is_dry_run_by_default() {
        let plan = create_plan(&[SystemFinding::ComponentStoreCorruption]);

        assert!(plan.dry_run);
        assert_eq!(plan.state, RepairPlanState::Draft);
        assert_eq!(plan.steps.len(), 1);
        assert!(plan.steps[0].requires_restore_point);
    }

    #[test]
    fn unapproved_plan_cannot_change_system() {
        let plan = create_plan(&[SystemFinding::DnsResolutionIssue]);

        let result = approve_plan(
            plan,
            ExecutionApproval {
                explicitly_approved: false,
            },
        );

        assert_eq!(result.approved_steps, 0);
        assert_eq!(result.blocked_steps, 1);
        assert_eq!(result.plan.state, RepairPlanState::Draft);
    }

    #[test]
    fn approved_plan_becomes_executable() {
        let plan = create_plan(&[
            SystemFinding::ProtectedSystemFileCorruption,
            SystemFinding::DefenderSignaturesOutdated,
        ]);

        let result = approve_plan(
            plan,
            ExecutionApproval {
                explicitly_approved: true,
            },
        );

        assert_eq!(result.approved_steps, 2);
        assert_eq!(result.blocked_steps, 0);
        assert_eq!(result.plan.state, RepairPlanState::Approved);
        assert!(!result.plan.dry_run);
    }

    #[test]
    fn execution_requires_an_approved_plan() {
        let plan = create_plan(&[SystemFinding::DnsResolutionIssue]);

        let result = execute_plan(
            plan,
            ExecutionApproval {
                explicitly_approved: false,
            },
        );

        assert_eq!(result.state, RepairExecutionState::NotApproved);
        assert_eq!(result.executed_steps, 0);
        assert_eq!(result.steps.len(), 1);
    }
}
