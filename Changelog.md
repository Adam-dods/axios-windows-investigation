# Changelog

All notable changes to AXIOS are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/), and AXIOS uses **calendar-based release identifiers**.

Release `2026.9.27` is the first stable public release, prepared in September 2026 and published in October 2026.

## Contents

- [2026.9.27: First stable release](#202692727--2026-10-01)
- [Added](#added)
- [Changed](#changed)
- [Performance](#performance)
- [Security](#security)
- [Reliability](#reliability)
- [Testing and validation](#testing-and-validation)
- [Packaging](#packaging)
- [Known limitations](#known-limitations)
- [Compatibility](#compatibility)
- [Release principle](#release-principle)

---

## [2026.9.27] — 2026-10-01

### First stable release

This release establishes the first stable AXIOS Windows investigation platform. It follows **two months and more than 700 hours** of independent development, testing, runtime validation, source review, performance work, and release hardening.

| Measurement | Result |
|---|---:|
| Administrator investigation stages | 42 |
| Packaged Windows executables | 46 |
| Reports observed during final validation | 59 |
| Failed reports during final validation | 0 |
| Total implementation and test code | 51,015 lines |
| Production Rust | 37,361 lines |
| Rust test code | 3,800 lines |
| PowerShell orchestration | 9,644 lines |
| Shell build automation | 210 lines |

**Highlights**

- A stable public interface: `axios.ps1` with eight modes.
- A complete **42-stage** Administrator investigation.
- Correlation, Reasoning Web, and response planning that never exceed the evidence.
- **Administrator runtime cut from ~249.9 s to ~128.6 s** with no collector removed.
- Encrypted credential export with AES-256-GCM and PBKDF2-SHA256.

---

## Added

### Stable public interface

```powershell
.\axios.ps1
```

**Public modes:** `Help`, `User`, `Administrator`, `System`, `Network`, `Persistence`, `Software`, `Results`

| Mode | Focused branches |
|---|---|
| `System` | `overview`, `quick`, `context` |
| `Network` | `overview`, `services`, `connections`, `routing`, `dns`, `firewall`, `wifi`, `full` |

Parameters are validated against the selected mode. Unsupported combinations are rejected **before** execution.

---

### Complete Administrator investigation

A 42-stage Windows investigation workflow covering:

| Area | Stages |
|---|---|
| **Persistence** | Registry persistence, extended persistence |
| **Execution** | Live activity, process integrity, runtime CPU and memory review, memory execution review |
| **Telemetry** | Telemetry integrity, event correlation |
| **Privilege and access** | Privileged execution surfaces, access surfaces, administrator exposure review, identity and credential-access review |
| **Platform trust** | Hardware trust, firmware identity, boot-chain review, platform-hardening review, virtualization-boundary review |
| **Kernel** | Kernel posture, loaded-driver trust, kernel runtime integrity, Code Integrity investigation |
| **Network** | Network posture, network exposure, network service review, network identity and egress, deep network evidence, remote-access review |
| **Defenses** | Security posture, security review, Defender evidence, security-control review, execution-policy and audit visibility |
| **Software** | Browser extensions, software and update exposure, application investigation |
| **Files** | Universal file audit, deep investigation |
| **Health** | Health posture |
| **Integrity and reasoning** | Collection-integrity review, cross-source observation integrity, persistent investigation state, Reasoning Web and response planning |

> Final correlation and reasoning stages run **only after** the required evidence reports have been collected and reviewed.

---

### Standard-user investigation

`User` mode needs no Administrator privileges. It reviews evidence available to the current Windows token:

- User-visible processes
- Startup entries
- Scheduled tasks
- Accessible services
- Network configuration
- User-writable execution surfaces
- Accessible file and registry permissions
- Security-control evidence available without elevation

Restricted evidence is reported as **partial or unavailable**, never as clean.

---

### System investigation

Hardware trust, Secure Boot, TPM, BitLocker visibility, virtualization-based security, kernel posture, driver trust, security controls, system health, context observations, and collection limitations.

---

### Network investigation

Bounded network-security assessment covering:

- Active adapters, IP configuration, DNS, routing, neighbor information
- Firewall profiles and firewall-rule visibility
- Wireless configuration
- TCP connections, UDP endpoints, listeners, network services
- Security-relevant observations
- Explicit authorized target checks

**Target validation rejects:**

| Rejected input | Why |
|---|---|
| CIDR ranges | No implicit scanning of ranges |
| Wildcards | Targets must be explicit |
| Whitespace | Prevents argument smuggling |
| Command-like input | Prevents injection |
| Invalid ports | Only valid ports accepted |
| Implicit network ranges | Only explicit hostnames or IPs |

---

### Persistence investigation

Registry Run entries, startup commands, startup folders, scheduled tasks, services, driver-related persistence, extended persistence sources, WMI permanent event subscriptions, and **persistence-coverage accounting**.

---

### Software and update review

Installed software inventory, update exposure, relevant application posture, browser-extension evidence, and software-related security observations.

---

### Results mode

```powershell
.\axios.ps1 -Mode Results
```

The latest completed command stays available during the active PowerShell session. Results include:

| Group | Contents |
|---|---|
| **Status** | Assessment status, result scope |
| **Findings** | Confirmed threats, important findings, unique context records |
| **Gaps** | Collection gaps, unresolved verification |
| **Reasoning** | Leading hypothesis, hypothesis score, independent evidence sources, contradictions, next-best checks |

Console output hides internal temporary paths and machine receipts by default.

---

### Structured evidence

Structured report fields: success state, collection status, findings, context observations, errors, visibility limitations, evidence references, performance measurements, summary values.

Normalized collection states: `complete`, `partial`, `failed`, `not_attempted`, `unknown`.

> A zero item count is **not** clean evidence unless the capability was successfully collected.

---

### Collection integrity

Reviews for missing reports, failed collectors, partial reports, duplicate evidence, contradictory evidence, invalid evidence references, unsupported conclusions, and inconsistent summary counts. Collector failures remain visible throughout the pipeline.

---

### Evidence correlation

Cross-source correlation across files, processes, services, persistence, network activity, memory execution, drivers, boot integrity, security controls, Defender evidence, event logs, identity and access, and software inventory.

- Provenance stays attached to correlated findings.
- Duplicate observations do not count as independent evidence.

---

### Reasoning Web

Bounded analysis of evidence facts, supported relationships, alternative explanations, contradictions, unresolved facts, hypotheses, confidence values, and next-best verification steps.

It **cannot** create evidence or silently raise confidence beyond the available support, and it preserves the policy that malware is not confirmed without sufficient independent verification.

---

### Response planning

Prioritized plans from supported findings, unresolved facts, and collection limitations. Categories: **High priority**, **Medium priority**, **Verification**, **Contextual follow-up**.

Actions are **advisory** and never executed automatically.

---

### Native Windows verification

- Authenticode verification
- Registry inspection
- Access-control inspection
- Token and privilege context
- Windows cryptographic operations
- Windows security-state collection

Signature verification uses Windows trust facilities with cache-only retrieval where required. Unavailable trust information stays **unknown or partial**.

---

### Developer investigation modes

Isolated from normal public collection paths:

| Command | Purpose |
|---|---|
| `DeveloperExposure` | Evidence-focused exposure assessment for a standard Windows user |
| `DeveloperCredential` | Explicit console-only access to authorized Wi-Fi credential evidence |
| `DeveloperArchive` | Decrypts AXIOS encrypted credential archives to the terminal, no plaintext file |

**Encrypted export specification**

| Property | Value |
|---|---|
| Cipher | AES-256-GCM (authenticated encryption) |
| Key derivation | PBKDF2-SHA256 |
| Iterations | 200,000 |
| File names | Randomized |
| Plaintext file | None |

---

### Package integrity

Validation of required files, required executables, package structure, SHA-256 manifest entries, missing components, incomplete extraction, and modified packaged content. The stable package contains **46 native executables**.

---

### Performance reporting

Measured stages, total and per-stage runtime, output size where available, collector-specific counters, and cache measurements where available. Performance data is written **before** final investigation completion.

---

### Documentation

Project README, architecture documentation, security policy, contribution and testing guidelines, public command documentation, sanitized Windows runtime screenshots, and release and validation information.

---

## Changed

### Product identity

```text
AXIOS
Windows Investigation Platform
```

Calendar-based release identity `2026.9.27`. Temporary development naming and compatibility labels were removed from the public interface.

### Command interface

- Simplified around stable investigation modes.
- Quick and Context are now focused **System branches**, not top-level commands.
- Administrator is the only complete investigation command.
- Developer commands stay hidden from public help.

### Evidence terminology

Clarified the distinction between security findings, review items, context observations, collection limitations, and unsupported conclusions. Context observations are no longer labeled as confirmed security exposures, and raw and unique context counts are labeled separately.

### Console rendering

- Groups security findings by subject
- Flattens nested arrays and objects, avoiding raw PowerShell object rendering
- Suppresses empty headings and hides internal evidence paths
- Displays dates in readable form
- Preserves meaningful words in property names
- Uses consistent dynamic heading separators
- Shows firewall profiles as distinct groups
- Describes unavailable capabilities truthfully

### Network reporting

Unavailable firewall-rule counts changed from a misleading zero to an explicit state:

```text
Firewall rules: not collected (not_attempted)
```

Localized wireless-property names are normalized into professional English labels. Explicit endpoints display without empty process identifiers.

### File-audit coverage

Bounded file-audit truncation now reports `collection_status=partial`, and a truncated audit can no longer contribute to an overall complete status. The report preserves:

- Selected audit mode
- Scanned roots
- Effective artifact limit
- Per-root candidate budget
- Time-budget state
- Artifact count
- Truncation state

### Optional Windows feature collection

Platform-hardening review moved from broad repeated enumeration to **targeted collection** of security-relevant optional features. States normalize to `Enabled` / `Disabled`. Same relevant results, shorter runtime.

---

## Performance

```text
Before:  249,924 ms
After:   128,632 ms
```

That is roughly a **48.5% reduction** (about 2 minutes saved) in the validated Windows environment.

Preserved through the optimization:

- 42 investigation stages
- 59 observed reports
- Evidence correlation, Reasoning Web, response planning
- Package-integrity checks
- Collection-status truthfulness

> No collector was removed to obtain the improvement.

---

## Security

- Strict network target validation
- Mode-specific parameter rejection
- Package-integrity preflight checks
- Source-hygiene checks for personal machine data
- Privacy checks for console output
- Authenticated AES-256-GCM credential exports
- Password-length validation for encrypted exports
- Terminal secret-input masking and console-state restoration
- Native registry-handle cleanup validation
- Conservative handling of unknown trust states
- Explicit privilege checks before execution
- Bounded active network checks
- Validation preventing private paths from entering published source
- Synthetic Windows paths for tests and documentation
- Rejection of command-like network input

---

## Reliability

- Working-directory independence, with restoration in `finally` paths
- PowerShell UTF-8 input, output, and code-page handling
- Windows compatibility fallbacks, including legacy network-adapter and firewall collection
- Normalized handling of Windows root-relative paths
- Explicit tracking of access-denied evidence
- Deduplication before finding and observation counts
- Recovery from poisoned worker-queue synchronization
- Report validation before marking an investigation complete
- Final reviews before success is recorded
- Performance-summary creation before final completion
- Portable-result tolerance for optional report fields

---

## Testing and validation

```bash
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
```

PowerShell files were validated with the PowerShell language parser.

**Release validation also covered:** Windows cross-compilation, package creation, archive integrity, SHA-256 generation, required binary presence, complete extraction of all 46 executables, standard-user runtime, Administrator runtime, Results rendering, network investigation, persistence investigation, developer exposure, encrypted credential export and decryption, partial-coverage propagation, performance reporting.

**Final full-investigation result**

```text
Completion state       : completed
Reports observed       : 59
Reports failed         : 0
Reports partial        : 1
Contradictions         : 0
Unresolved facts       : 0
```

The one partial report came from an explicit bounded file-audit limit and was correctly propagated as partial coverage.

---

## Packaging

Three validated artifacts:

```text
axios-windows-investigation.zip
axios-windows-investigation-source.tgz
axios-windows-investigation-source.txt
```

The Windows package contains the public PowerShell entrypoint, investigation runners, 46 native Windows executables, command reference, integrity manifest, and required package resources.

Build directories, local Git history, credentials, machine evidence, investigation archives, and sensitive files are excluded from source packages.

---

## Known limitations

- AXIOS is currently Windows-focused.
- Some evidence requires Administrator privileges.
- Protected processes and security products may restrict collection.
- Firewall-rule inspection may be unavailable to a standard user.
- Raw packet capture requires a trusted external capture driver and is not provided by socket metadata.
- Bounded file collection may intentionally return partial coverage.
- Windows APIs and evidence availability differ across versions and configurations.
- A completed investigation does **not** prove that a system is clean.
- AXIOS reports and prioritizes evidence but does not automatically remediate.

---

## Compatibility

Designed for supported Windows environments with the required PowerShell and Windows security APIs. Fallbacks exist for supported legacy interfaces where practical. Capabilities unavailable on a specific Windows release remain **explicitly unavailable**, never represented as clean.

---

## Release principle

> **AXIOS must never present more certainty than the collected evidence can support.**

A completed command means the selected bounded workflow finished. It does not mean every possible artifact was visible or that the system is guaranteed clean.

---
