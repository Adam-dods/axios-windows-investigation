#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

cargo fmt
cargo fmt --check
cargo test --test context_posture_contract
cargo test --test context_complete_reasoning_contract
cargo test --test quick_human_report_contract
cargo test --test human_reporting_all_modes_contract
cargo test --test powershell_parser_safety_contract
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo check --target x86_64-pc-windows-gnu --all-targets

if command -v powershell.exe >/dev/null 2>&1 && command -v wslpath >/dev/null 2>&1; then
    for source in installer/windows/*.ps1; do
        windows_path="$(wslpath -w "$PROJECT_ROOT/$source")"
        powershell.exe -NoProfile -NonInteractive -Command "
            \$errors = \$null
            \$tokens = \$null
            [void][System.Management.Automation.Language.Parser]::ParseFile(
                '$windows_path',
                [ref]\$tokens,
                [ref]\$errors
            )
            if (\$errors.Count -gt 0) {
                \$errors | ForEach-Object { Write-Error \$_.Message }
                exit 1
            }
        "
    done
    echo "AXIOS_WINDOWS_POWERSHELL_PARSE_PASS=true"
else
    echo "AXIOS_WINDOWS_POWERSHELL_PARSE_SKIPPED=true"
fi

bash scripts/build-windows-complete-investigation.sh

archive="$({
    find "${AXIOS_OUTPUT_DIR:-$HOME/Downloads}" \
        -maxdepth 1 -type f \
        -name 'axios-windows-investigation.zip' \
        -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"

test -s "$archive"
sha256sum "$archive"
echo "NEW_WINDOWS_ARCHIVE=$archive"
echo "FINAL_AXIOS_PROFESSIONAL_REPORTING_RELEASE_PASS=true"
