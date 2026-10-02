use anyhow::{bail, Result};
use axios_core::system::universal_file_audit::{
    collect_with_options, AuditMode, AuditOptions, DEFAULT_MAX_ARTIFACTS,
};
use std::path::PathBuf;

#[derive(Debug)]
struct CliOptions {
    mode: AuditMode,
    max_files: usize,
    recent_days: u64,
    roots: Vec<PathBuf>,
    seed_reports: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let Some(options) = parse_options(std::env::args().skip(1))? else {
        print_usage();
        return Ok(());
    };

    let report = collect_with_options(&AuditOptions {
        mode: options.mode,
        max_artifacts: options.max_files,
        recent_days: options.recent_days,
        roots: options.roots,
        seed_reports: options.seed_reports,
    })?;

    println!("{}", serde_json::to_string_pretty(&report)?);

    Ok(())
}

fn parse_options<I, S>(arguments: I) -> Result<Option<CliOptions>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);

    let mut mode = AuditMode::Smart;
    let mut max_files = DEFAULT_MAX_ARTIFACTS;
    let mut recent_days = 30_u64;
    let mut roots = Vec::new();
    let mut seed_reports = Vec::new();
    let mut mode_seen = false;
    let mut max_files_seen = false;
    let mut recent_days_seen = false;

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--mode" => {
                if mode_seen {
                    bail!("--mode or --full was supplied more than once");
                }
                mode_seen = true;
                let value = arguments
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--mode requires a value"))?;
                mode = AuditMode::parse(&value)?;
            }
            "--full" => {
                if mode_seen {
                    bail!("--mode or --full was supplied more than once");
                }
                mode_seen = true;
                mode = AuditMode::Full;
            }
            "--max-files" => {
                if max_files_seen {
                    bail!("--max-files was supplied more than once");
                }
                max_files_seen = true;
                let value = arguments
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--max-files requires a value"))?;
                max_files = value
                    .parse::<usize>()
                    .map_err(|_| anyhow::anyhow!("--max-files must be a non-negative integer"))?;
            }
            "--recent-days" => {
                if recent_days_seen {
                    bail!("--recent-days was supplied more than once");
                }
                recent_days_seen = true;
                let value = arguments
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--recent-days requires a value"))?;
                recent_days = value
                    .parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("--recent-days must be a non-negative integer"))?;
            }
            "--root" => {
                roots.push(PathBuf::from(arguments.next().ok_or_else(|| {
                    anyhow::anyhow!("--root requires a directory path")
                })?));
            }
            "--seed-report" => {
                seed_reports.push(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--seed-report requires a JSON path"))?,
                ));
            }
            "--help" | "-h" => return Ok(None),
            _ => bail!("unknown argument: {argument}"),
        }
    }

    if mode == AuditMode::Targeted && roots.is_empty() && seed_reports.is_empty() {
        bail!("targeted mode requires --root or --seed-report");
    }

    Ok(Some(CliOptions {
        mode,
        max_files,
        recent_days,
        roots,
        seed_reports,
    }))
}

fn print_usage() {
    println!(
        "Usage:\n\
         axios-file-audit.exe [OPTIONS]\n\n\
         Default operation is a bounded smart investigation.\n\n\
         Options:\n\
           --mode <smart|fast|targeted|full>\n\
           --max-files <COUNT>\n\
           --recent-days <DAYS>\n\
           --root <DIRECTORY>       repeatable\n\
           --seed-report <JSON>     repeatable\n\
           --full                   explicit full-drive mode\n\n\
         Smart mode never performs an unlimited full-drive scan.\n\
         Full mode must be requested explicitly."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cli_mode_is_smart() {
        let options = parse_options(Vec::<String>::new()).unwrap().unwrap();

        assert_eq!(options.mode, AuditMode::Smart);
        assert_eq!(options.max_files, DEFAULT_MAX_ARTIFACTS);
    }

    #[test]
    fn explicit_full_mode_is_supported() {
        let options = parse_options(["--full", "--max-files", "25000"])
            .unwrap()
            .unwrap();

        assert_eq!(options.mode, AuditMode::Full);
        assert_eq!(options.max_files, 25_000);
    }

    #[test]
    fn targeted_mode_requires_a_target() {
        let result = parse_options(["--mode", "targeted"]);

        assert!(result.is_err());
    }

    #[test]
    fn seed_reports_are_repeatable() {
        let options = parse_options([
            "--seed-report",
            "persistence.json",
            "--seed-report",
            "live.json",
        ])
        .unwrap()
        .unwrap();

        assert_eq!(options.seed_reports.len(), 2);
    }

    #[test]
    fn repeated_or_conflicting_scalar_options_are_rejected() {
        assert!(parse_options(["--mode", "fast", "--full"]).is_err());
        assert!(parse_options(["--max-files", "10", "--max-files", "20"]).is_err());
        assert!(parse_options(["--recent-days", "7", "--recent-days", "8"]).is_err());
    }

    #[test]
    fn fast_mode_is_supported_and_bounded() {
        let options = parse_options(["--mode", "fast", "--max-files", "3000"])
            .unwrap()
            .unwrap();

        assert_eq!(options.mode, AuditMode::Fast);
        assert_eq!(options.max_files, 3_000);
    }
}
