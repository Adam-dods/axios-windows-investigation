use anyhow::Result;
use axios_core::{analysis, network, persistence, security, storage, system, telemetry};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "axios-core",
    version,
    about = "AXIOS Windows System Operations Engine"
)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand)]
enum CliCommand {
    Status,

    Collect {
        #[arg(short, long, default_value = "axios-system.json")]
        output: String,
    },

    Processes,
    Network,
    Services,
    Drivers,
    Startup,
    RegistryPersistence,
    PersistenceCoverage,
    Tasks,
    Defender,
    Firewall,
    Updates,
    SoftwareInventory,
    BrowserExtensions,
    HardwareTrust,
    KernelPosture,
    SecurityPosture,
    SecurityReview,

    Compare {
        before: String,
        after: String,

        #[arg(short, long)]
        output: Option<String>,
    },

    BaselineCreate {
        snapshot: String,

        #[arg(short, long, default_value = "axios-baseline.json")]
        output: String,
    },

    BaselineVerify {
        baseline: String,
    },

    BaselineCompare {
        baseline: String,
        snapshot: String,

        #[arg(short, long)]
        output: Option<String>,
    },

    BaselineReport {
        baseline: String,
        snapshot: String,

        #[arg(short, long)]
        output: Option<String>,
    },

    Timeline {
        input: String,
    },

    Monitor {
        #[arg(short, long, default_value = "axios-timeline.jsonl")]
        output: String,

        #[arg(short, long, default_value_t = 1)]
        interval: u64,
    },

    TimelineDump {
        input: String,
    },

    ToolPlan {
        tool: String,
    },

    ToolRun {
        tool: String,

        #[arg(long)]
        approve_system_change: bool,
    },

    RepairPlan {
        #[arg(value_enum, required = true)]
        findings: Vec<system::repair::SystemFinding>,
    },

    RepairRun {
        #[arg(value_enum, required = true)]
        findings: Vec<system::repair::SystemFinding>,

        #[arg(long)]
        approve_system_change: bool,
    },

    ProcessStop {
        pid: u32,

        #[arg(long)]
        approve_system_change: bool,
    },

    ServiceControl {
        service: String,

        #[arg(value_enum)]
        action: system::remediation::ServiceControlAction,

        #[arg(long)]
        approve_system_change: bool,
    },

    FirewallProgram {
        path: String,

        #[arg(value_enum)]
        action: system::remediation::FirewallProgramAction,

        #[arg(long, value_enum, default_value_t = system::remediation::FirewallDirection::Outbound)]
        direction: system::remediation::FirewallDirection,

        #[arg(long)]
        approve_system_change: bool,
    },

    RegistryRunRemove {
        #[arg(value_enum)]
        location: system::registry_remediation::RegistryRunLocation,

        value_name: String,

        #[arg(long)]
        approve_system_change: bool,
    },

    ScheduledTaskControl {
        task_name: String,

        #[arg(value_enum)]
        action: system::task_remediation::ScheduledTaskAction,

        #[arg(long)]
        approve_system_change: bool,
    },

    AccessSurface,

    DefenderScan {
        #[arg(value_enum)]
        scan_kind: system::defender_scan::DefenderScanKind,

        #[arg(long)]
        path: Option<String>,

        #[arg(long)]
        approve_system_change: bool,
    },

    ExtendedPersistence,

    NetworkPosture,

    ContextPosture,

    EvidenceBundle,

    HealthPosture,

    DeepInvestigation,

    LiveActivity,

    EventCorrelation {
        #[arg(long, default_value_t = 24)]
        hours: i64,
    },
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn write_or_print<T: serde::Serialize>(value: &T, output: Option<String>) -> Result<()> {
    if let Some(output_path) = output {
        std::fs::write(&output_path, serde_json::to_string_pretty(value)?)?;

        println!("AXIOS output saved: {}", output_path);
        Ok(())
    } else {
        print_json(value)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Status => {
            let snapshot = storage::snapshot::collect();

            print_json(&serde_json::json!({
                "axios_version": snapshot.axios_version,
                "timestamp": snapshot.timestamp,
                "system": snapshot.system,
                "process_count": snapshot.processes.len()
            }))
        }

        CliCommand::Collect { output } => storage::snapshot::save(&output),

        CliCommand::Processes => {
            let snapshot = storage::snapshot::collect();
            print_json(&snapshot.processes)
        }

        CliCommand::Network => print_json(&network::collector::collect()),

        CliCommand::Services => print_json(&persistence::services::collect()),

        CliCommand::Drivers => print_json(&persistence::drivers::collect()),

        CliCommand::Startup => print_json(&persistence::startup::collect()),

        CliCommand::RegistryPersistence => print_json(&persistence::registry::collect()),

        CliCommand::PersistenceCoverage => print_json(&persistence::coverage::collect()),

        CliCommand::Tasks => print_json(&persistence::tasks::collect()),

        CliCommand::Defender => print_json(&security::defender::collect()),

        CliCommand::Firewall => print_json(&security::firewall::collect()),

        CliCommand::BrowserExtensions => print_json(&system::browser_extensions::collect()),

        CliCommand::HardwareTrust => print_json(&system::hardware_trust::collect()),

        CliCommand::KernelPosture => print_json(&system::kernel_posture::collect()),

        CliCommand::SecurityPosture => print_json(&system::security_posture::collect()),

        CliCommand::SecurityReview => print_json(&analysis::security_review::collect()),

        CliCommand::Updates => print_json(&system::updates::collect()),

        CliCommand::SoftwareInventory => print_json(&system::software_inventory::collect()),

        CliCommand::Compare {
            before,
            after,
            output,
        } => {
            let comparison = analysis::diff::compare_files(&before, &after)?;

            write_or_print(&comparison, output)
        }

        CliCommand::BaselineCreate { snapshot, output } => {
            let baseline = storage::baseline::create_from_snapshot_file(&snapshot, &output)?;

            print_json(&serde_json::json!({
                "action": "baseline_created",
                "path": output,
                "created_at": baseline.created_at,
                "snapshot_sha256": baseline.snapshot_sha256
            }))
        }

        CliCommand::BaselineVerify { baseline } => {
            let verification = storage::baseline::verify_file(&baseline)?;

            print_json(&verification)
        }

        CliCommand::BaselineCompare {
            baseline,
            snapshot,
            output,
        } => {
            let comparison =
                storage::baseline::compare_baseline_to_snapshot_file(&baseline, &snapshot)?;

            write_or_print(&comparison, output)
        }

        CliCommand::BaselineReport {
            baseline,
            snapshot,
            output,
        } => {
            let comparison =
                storage::baseline::compare_baseline_to_snapshot_file(&baseline, &snapshot)?;

            let report = analysis::baseline_change_report::build(comparison);

            write_or_print(&report, output)
        }

        CliCommand::Timeline { input } => {
            let summary = telemetry::timeline::summarize_file(&input)?;

            print_json(&summary)
        }

        CliCommand::Monitor { output, interval } => {
            telemetry::monitor::monitor_processes(&output, interval)
        }

        CliCommand::TimelineDump { input } => {
            let events = telemetry::timeline::read_events(&input)?;

            print_json(&events)
        }

        CliCommand::ToolPlan { tool } => {
            let tool = tool.parse().map_err(anyhow::Error::msg)?;

            print_json(&system::windows_tools::prepare(tool))
        }

        CliCommand::ToolRun {
            tool,
            approve_system_change,
        } => {
            let tool = tool.parse().map_err(anyhow::Error::msg)?;

            let result = system::windows_tools::execute(
                tool,
                system::windows_tools::ExecutionApproval {
                    explicitly_approved: approve_system_change,
                },
            );

            print_json(&result)
        }

        CliCommand::RepairPlan { findings } => {
            let plan = system::repair::create_plan(&findings);

            print_json(&plan)
        }

        CliCommand::RepairRun {
            findings,
            approve_system_change,
        } => {
            let approval = system::windows_tools::ExecutionApproval {
                explicitly_approved: approve_system_change,
            };

            let plan = system::repair::create_plan(&findings);
            let approved = system::repair::approve_plan(plan, approval);
            let result = system::repair::execute_plan(approved.plan, approval);

            print_json(&result)
        }

        CliCommand::ProcessStop {
            pid,
            approve_system_change,
        } => {
            let result = system::remediation::terminate_process(
                pid,
                system::windows_tools::ExecutionApproval {
                    explicitly_approved: approve_system_change,
                },
            );

            print_json(&result)
        }

        CliCommand::ServiceControl {
            service,
            action,
            approve_system_change,
        } => {
            let result = system::remediation::control_service(
                service,
                action,
                system::windows_tools::ExecutionApproval {
                    explicitly_approved: approve_system_change,
                },
            );

            print_json(&result)
        }

        CliCommand::FirewallProgram {
            path,
            action,
            direction,
            approve_system_change,
        } => {
            let result = system::remediation::manage_firewall_program_rule(
                path,
                action,
                direction,
                system::windows_tools::ExecutionApproval {
                    explicitly_approved: approve_system_change,
                },
            );

            print_json(&result)
        }

        CliCommand::RegistryRunRemove {
            location,
            value_name,
            approve_system_change,
        } => {
            let result = system::registry_remediation::remove_registry_run_value(
                location,
                value_name,
                system::windows_tools::ExecutionApproval {
                    explicitly_approved: approve_system_change,
                },
            );

            print_json(&result)
        }

        CliCommand::ScheduledTaskControl {
            task_name,
            action,
            approve_system_change,
        } => {
            let result = system::task_remediation::control_scheduled_task(
                task_name,
                action,
                system::windows_tools::ExecutionApproval {
                    explicitly_approved: approve_system_change,
                },
            );

            print_json(&result)
        }

        CliCommand::AccessSurface => print_json(&system::access_surface::collect()),

        CliCommand::DefenderScan {
            scan_kind,
            path,
            approve_system_change,
        } => {
            let result = system::defender_scan::start_scan(
                scan_kind,
                path,
                system::windows_tools::ExecutionApproval {
                    explicitly_approved: approve_system_change,
                },
            );

            print_json(&result)
        }

        CliCommand::ExtendedPersistence => print_json(&persistence::extended::collect()),

        CliCommand::NetworkPosture => print_json(&system::network_posture::collect()),

        CliCommand::ContextPosture => print_json(&system::context_posture::collect()),

        CliCommand::EvidenceBundle => print_json(&analysis::evidence_bundle::collect()),

        CliCommand::HealthPosture => print_json(&system::health_posture::collect()),

        CliCommand::DeepInvestigation => print_json(&analysis::deep_investigation::investigate()),

        CliCommand::LiveActivity => print_json(&analysis::live_activity::collect()),

        CliCommand::EventCorrelation { hours } => {
            print_json(&analysis::event_correlation::collect_recent(hours))
        }
    }
}
