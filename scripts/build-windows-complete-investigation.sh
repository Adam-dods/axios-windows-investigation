#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="x86_64-pc-windows-gnu"
OUTPUT_DIR="${AXIOS_OUTPUT_DIR:-$HOME/Downloads}"

NAMES=(
  axios-core
  axios-file-audit
  axios-application-investigation
  axios-audit-correlate
  axios-trust-review
  axios-kernel-review
  axios-driver-trust
  axios-process-integrity
  axios-network-exposure
  axios-investigation-state
  axios-response-plan
  axios-evidence-review
  axios-network-service-review
  axios-boot-chain-review
  axios-code-integrity-investigation
  axios-sensitive-baseline
  axios-correlation-score
  axios-hardware-advisory
  axios-threat-hypotheses
  axios-reasoning-web
  axios-forensic-export
  axios-behavior-hunt
  axios-defender-evidence
  axios-defender-tamper-review
  axios-persistence-execution-review
  axios-memory-execution-review
  axios-kernel-runtime-integrity
  axios-firmware-identity-review
  axios-runtime-resource-review
  axios-collection-integrity-review
  axios-network-identity-review
  axios-network-deep-review
  axios-privilege-surface-review
  axios-telemetry-integrity-review
  axios-security-controls-review
  axios-remote-access-review
  axios-execution-policy-review
  axios-identity-access-review
  axios-platform-hardening-review
  axios-virtualization-boundary-review
  axios-observation-integrity-review
  axios-user-scope-access-review
  axios-user-exposure-audit
  axios-admin-exposure-audit
  axios-standard-user-response-plan
  axios-developer-credential-view
)

for command in cargo file sha256sum zip unzip mktemp; do
  command -v "$command" >/dev/null ||
    { echo "AXIOS_RELEASE_BUILD_ERROR=missing_command:$command"; exit 1; }
done

mkdir -p "$OUTPUT_DIR"

for name in "${NAMES[@]}"; do
  cargo build --manifest-path "$PROJECT_ROOT/Cargo.toml" \
    --release \
    --target "$TARGET" \
    --bin "$name"
done

TEMP_DIR="$(mktemp -d)"
PACKAGE_NAME="axios-windows-investigation"
ROOT="$TEMP_DIR/$PACKAGE_NAME"
BIN="$ROOT/bin"
OUT="$OUTPUT_DIR/$PACKAGE_NAME.zip"
ARCHIVE="$TEMP_DIR/$PACKAGE_NAME.zip"

cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

mkdir -p "$BIN" "$ROOT/scripts" "$ROOT/output"

for name in "${NAMES[@]}"; do
  source_file="$PROJECT_ROOT/target/$TARGET/release/$name.exe"

  if ! file "$source_file" | grep -qiE 'PE32.*Windows.*x86-64'; then
    file "$source_file"
    echo "AXIOS_RELEASE_BUILD_ERROR=invalid_windows_pe:$name"
    exit 1
  fi

  cp "$source_file" "$BIN/$name.exe"
done

cp "$PROJECT_ROOT/installer/windows/Run-AXIOS-Complete-Investigation.ps1" \
  "$ROOT/scripts/Run-AXIOS-Complete-Investigation.ps1"

cp "$PROJECT_ROOT/installer/windows/Invoke-AXIOS-Mission.ps1" \
  "$ROOT/scripts/Invoke-AXIOS-Mission.ps1"


cp "$PROJECT_ROOT/installer/windows/Run-AXIOS-User-Scope-Review.ps1" \
  "$ROOT/scripts/Run-AXIOS-User-Scope-Review.ps1"

cp "$PROJECT_ROOT/installer/windows/Run-AXIOS-User-Exposure-Audit.ps1" \
  "$ROOT/scripts/Run-AXIOS-User-Exposure-Audit.ps1"

cp "$PROJECT_ROOT/installer/windows/Run-AXIOS-Standard-User-Audit.ps1" \
  "$ROOT/scripts/Run-AXIOS-Standard-User-Audit.ps1"

cp "$PROJECT_ROOT/installer/windows/Run-AXIOS-Developer-Exposure-View.ps1" \
  "$ROOT/scripts/Run-AXIOS-Developer-Exposure-View.ps1"

cp "$PROJECT_ROOT/installer/windows/Run-AXIOS-Administrator-Exposure-Audit.ps1" \
  "$ROOT/scripts/Run-AXIOS-Administrator-Exposure-Audit.ps1"
cp "$PROJECT_ROOT/installer/windows/Run-AXIOS-Network-Deep-Review.ps1" \
  "$ROOT/scripts/Run-AXIOS-Network-Deep-Review.ps1"

cp "$PROJECT_ROOT/installer/windows/Run-AXIOS.ps1" \
  "$ROOT/scripts/Run-AXIOS.ps1"

cp "$PROJECT_ROOT/installer/windows/axios.ps1" \
  "$ROOT/axios.ps1"

cp "$PROJECT_ROOT/installer/windows/Run-AXIOS-Layer.ps1" \
  "$ROOT/scripts/Run-AXIOS-Layer.ps1"

cp "$PROJECT_ROOT/installer/windows/AXIOS-COMMANDS.txt" \
  "$ROOT/AXIOS-COMMANDS.txt"

cp "$PROJECT_ROOT/README.md" "$ROOT/README.md"
cp "$PROJECT_ROOT/LICENSE" "$ROOT/LICENSE"

(
  cd "$ROOT"
  sha256sum \
    bin/*.exe \
    axios.ps1 \
    scripts/*.ps1 \
    AXIOS-COMMANDS.txt \
    README.md \
    LICENSE \
    > SHA256SUMS.txt
)

(
  cd "$TEMP_DIR"
  zip -qr "$ARCHIVE" "$PACKAGE_NAME"
)

unzip -t "$ARCHIVE" >/dev/null
mv -f "$ARCHIVE" "$OUT"

echo "AXIOS_RELEASE_BUILD_PASS=true"
echo "BINARIES_PACKAGED=${#NAMES[@]}"
echo "ZIP=$OUT"
