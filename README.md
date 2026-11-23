
# AXIOS

### Windows Investigation Platform

**Evidence first. Honest about what it can't see.**

[Release v2026.11.23](https://github.com/Adam-dods/axios-windows-investigation/releases/tag/v2026.11.23) · Windows · Rust + PowerShell · [Apache 2.0](LICENSE) · [CI](https://github.com/Adam-dods/axios-windows-investigation/actions/workflows/ci.yml)

> A missing signal is not a clean system. An unverified observation is not a confirmed threat. AXIOS is built around that distinction.

## Contents

- [Overview](#what-is-axios) · [Boundaries](#what-axios-is-not) · [Code size](#by-the-numbers) · [Quick start](#quick-start)
- [Documentation](#documentation) · [Principles](#investigation-philosophy) · [Coverage](#what-axios-investigates)
- [Rust](#why-rust) · [Architecture](#architecture) · [Validation](#validated-runtime)
- [Public commands](#public-commands) · [Developer commands](#developer-commands) · [Results](#reading-the-results)
- [Artifacts](#saving-artifacts) · [Build](#building-from-source) · [FAQ](#faq) · [Release](#release)
- [Security](#security) · [Contributing](#contributing) · [License](#license)

## What is AXIOS

AXIOS is a Windows security investigation, evidence-correlation, and forensic-reasoning platform built with **Rust** and **PowerShell**.

It does not just scan and print a verdict. It collects evidence across many layers of the operating system, correlates those layers against each other, and reports each conclusion together with how well it is supported. Where it couldn't see something, it says so.

The first stable release followed two months and 700+ hours of independent engineering and validation.

## What AXIOS is not

- **Not an antivirus.** It investigates and reports; it doesn't quarantine or clean.
- **Not a remediation tool.** It never kills processes, deletes artifacts, or changes security settings.
- **Not a "everything suspicious is malware" scanner.** Unusual does not mean malicious, and AXIOS won't claim compromise from one unsupported indicator.
- **Not a black box.** Every finding keeps its evidence provenance, and every collector reports its own status.

## By the numbers

Physical lines in tracked Rust, PowerShell, Shell and CMD files at release commit `da014b9`, including blank and comment lines. The encoded payload of the single-file CMD asset is excluded.

| Measurement | Value |
|---|---:|
| Total implementation and test code | **52,333 lines** |
| Production Rust (`src/`) / Rust tests (`tests/`) | 37,647 / 3,810 lines |
| Total Rust / PowerShell / Shell / CMD | 41,457 / 10,580 / 235 / 61 lines |
| Rust source / test files | 134 / 71 |
| PowerShell / Shell / CMD files | 16 / 2 / 2 |
| Packaged Windows executables / Administrator stages | 46 / 42 |
| Reports / failed reports in original final validation | 59 / 0 |

Rust collects and correlates Windows evidence, verifies integrity, and structures findings; tests cover behavior, precision, and contracts. PowerShell coordinates native collectors and exposes the public interface. Shell builds packages; CMD launches them on Windows.

## Quick start

Download the [v2026.11.23 CMD asset](https://github.com/Adam-dods/axios-windows-investigation/releases/download/v2026.11.23/axios-windows-investigation.cmd) to **Downloads**. Its published SHA-256 is `796bfdc914bfc29d06fa1ea335d87b89ed53011dcc5939f7636ce9b0bee7c1a7`. The release also provides a [checksum file](https://github.com/Adam-dods/axios-windows-investigation/releases/download/v2026.11.23/axios-windows-investigation.cmd.sha256). In a standard PowerShell window:

```powershell
$Expected = '796bfdc914bfc29d06fa1ea335d87b89ed53011dcc5939f7636ce9b0bee7c1a7'
$Actual = (Get-FileHash "$env:USERPROFILE\Downloads\axios-windows-investigation.cmd" -Algorithm SHA256).Hash
if ($Actual -ne $Expected) { throw 'AXIOS download checksum mismatch' }
& "$env:USERPROFILE\Downloads\axios-windows-investigation.cmd"
Set-Location "$env:USERPROFILE\Downloads\AXIOS\axios-windows-investigation"
.\axios.cmd -Mode Help
.\axios.cmd -Mode User
.\axios.cmd -Mode Network
.\axios.cmd -Mode Results
```

The file extracts into `Downloads\AXIOS` with inline progress and returns to the terminal **without starting an investigation**. Run `.\axios.cmd -Mode Administrator` in an elevated terminal for the full investigation. `axios.ps1` remains available in PowerShell.

The release asset is a single self-extracting CMD file, not the source archive GitHub generates beside it. Downloading the source ZIP alone does not provide the 46 packaged executables. Keep the extracted directory intact so AXIOS can validate its required components.

## Documentation

| Document | Contents |
|---|---|
| [Commands.md](Commands.md) | Complete command guide for every AXIOS mode |
| [Windows.md](Windows.md) | Windows requirements, privileges, and visibility |
| [Changelog.md](Changelog.md) | Release history and validation record |
| [Architecture.md](Architecture.md) | Full technical design |

## Investigation philosophy

AXIOS follows five operating principles.

### 1. Evidence before conclusions
Every security conclusion must connect to collected evidence. Observations, contextual conditions, and confirmed findings are always kept separate.

### 2. Bounded execution
Collectors run under explicit limits for time, files, events, memory regions, output size, and evidence volume. When a limit is reached, AXIOS reports **partial visibility** instead of presenting incomplete evidence as complete.

### 3. Truthful uncertainty
AXIOS distinguishes between verified findings, review items, contextual observations, collection gaps, and unsupported conclusions. A failed or unavailable collector never becomes clean evidence.

### 4. Independent corroboration
Evidence from processes, services, persistence, network state, memory, boot integrity, security controls, software, and event logs is correlated before a higher-confidence conclusion is created.

### 5. Non-destructive investigation
Public commands collect and assess. They do not modify security controls, delete artifacts, terminate processes, or remediate the system.

## What AXIOS investigates

| Area | Coverage |
|---|---|
| **Persistence** | Registry and extended persistence, services, scheduled tasks, startup folders, WMI permanent event subscriptions |
| **Execution** | Processes, runtime activity, CPU and memory behavior |
| **Privilege** | User and administrator exposure, privileged execution surfaces |
| **Platform trust** | Hardware and firmware identity, Secure Boot, boot-chain posture |
| **Kernel** | Kernel posture, runtime integrity, loaded driver trust, native Authenticode verification, Code Integrity evidence |
| **Network** | Adapters, DNS, routing, firewall, Wi-Fi, listeners, connections, services |
| **Defenses** | Security controls and Microsoft Defender evidence |
| **Software** | Inventory and update exposure, browser extensions |
| **Identity** | Credential-access posture, access-control exposure |
| **Isolation** | Virtualization boundaries |
| **Correlation** | Event correlation, file and artifact investigation, cross-source observation integrity |
| **Reasoning** | Persistent investigation state, bounded reasoning, response planning |

## Why Rust

Security software processes untrusted, incomplete evidence. Rust provides memory safety without a garbage collector, native Windows API access, strong evidence types, explicit errors, predictable resource use, and standalone executables. PowerShell remains a transparent operator interface; compiled Rust components perform native collection and analysis.

Rust's ownership and lifetime checks help prevent memory errors in collectors handling malformed input. Typed evidence models and explicit `Result` paths make missing data and failures easier to keep distinct from verified observations. The native executables can run without installing a separate Rust runtime on the investigated Windows machine.

## Architecture

```text
CMD / PowerShell -> parameter, privilege and package validation
    -> bounded runner -> isolated Rust collectors -> structured evidence
    -> integrity and contradiction review -> cross-source correlation
    -> Reasoning Web -> response plan and Results renderer
```

Every layer reports findings, observations, status, errors, and limits. Correlation and reasoning preserve provenance and run after collection. See [Architecture.md](Architecture.md).

## Validated runtime

The original complete Administrator validation run on Windows reported:

```text
Completion state       : completed
Reports observed       : 59
Reports failed         : 0
Reports partial        : 1
High-priority findings : 2
Medium findings        : 3
Contradictions         : 0
Unresolved facts       : 0
```

The partial report was a bounded file-audit candidate limit, recorded as incomplete visibility. For this release, PR #6's final head passed two CI checks (Windows PowerShell/CMD smoke tests and Rust checks). An **earlier** Windows 11 candidate passed 27/27 nonsecret command cases, including both Administrator audit modes at 42/42 stages. After the final TCP display change, the CMD built on Kali was tested on Windows for Network `connections` and `services`; both finished with zero collection errors and correct process-name/PID and IPv6 display. The 27-case matrix was **not rerun on the final CMD**. The maintainer also reports successful use on multiple Windows 11 PCs with different versions; machine-by-machine logs are not published here. These results do not establish universal compatibility.

The CLI distinguishes a completed run from complete visibility: bounded limits and protected Windows surfaces can still produce partial or unavailable reports. Results on one PC describe that PC's observed state, not every installation.

## Public commands

The main `axios.cmd` interface works in CMD and PowerShell. Only `Administrator` requires elevation; other modes can still report protected evidence as unavailable.

| Mode | Example | Purpose |
|---|---|---|
| Help | `.\axios.cmd -Mode Help` | Command reference |
| User | `.\axios.cmd -Mode User` | Evidence available to the current user |
| Administrator | `.\axios.cmd -Mode Administrator` | Complete 42-stage investigation |
| System | `.\axios.ps1 -Mode System` | Hardware, boot, kernel, health (legacy mode) |
| Network | `.\axios.cmd -Mode Network` | Network state and exposure |
| Persistence | `.\axios.ps1 -Mode Persistence` | Startup and persistence (legacy mode) |
| Software | `.\axios.ps1 -Mode Software` | Inventory and updates (legacy mode) |
| Results | `.\axios.cmd -Mode Results` | Latest completed assessment |

Focused User views use `-Focus System`, `SystemQuick`, `SystemContext`, `Persistence`, or `Software`. Legacy PowerShell System uses `-SystemFocus overview`, `quick`, or `context`. PowerShell Network uses `-NetworkFocus overview`, `services`, `connections`, `routing`, `dns`, `firewall`, `wifi`, or `full`.

```powershell
.\axios.cmd -Mode User -Focus SystemQuick
.\axios.ps1 -Mode Network -NetworkFocus connections
.\axios.ps1 -Mode Network -NetworkFocus connections -Target 192.0.2.10 -Ports 80,443
.\axios.ps1 -Mode Administrator -AuditMode smart -MaxFiles 5000
```

Target checks accept only explicit, authorized hostnames or IPs, not CIDR ranges, wildcards, whitespace, or command-like input. See [Commands.md](Commands.md) for all modes and parameters.

### Help and User

`Help` lists supported parameters and examples. `User` reviews processes, startup entries, tasks, accessible network configuration, and exposure available to the current security token. Focused views keep the request narrow:

```powershell
.\axios.cmd -Mode User -Focus System
.\axios.cmd -Mode User -Focus SystemQuick
.\axios.cmd -Mode User -Focus SystemContext
.\axios.cmd -Mode User -Focus Persistence
.\axios.cmd -Mode User -Focus Software
```

### Administrator

Run in an elevated terminal. The 42 stages combine primary collectors, collection-integrity checks, cross-source correlation, investigation state, Reasoning Web, and response planning. The optional smart file audit bounds its candidate count:

```powershell
.\axios.cmd -Mode Administrator
.\axios.ps1 -Mode Administrator -AuditMode smart -MaxFiles 5000
```

### System and Network

Legacy `System` views cover broad security posture (`overview`), important controls (`quick`), and contextual evidence (`context`). Network views are available through PowerShell:

| Network focus | Evidence |
|---|---|
| `overview` | Concise security overview |
| `services` | Listening services and related process context |
| `connections` | TCP connections and UDP endpoints |
| `routing` | Routes, gateways, interfaces, neighbors |
| `dns` | DNS configuration and related evidence |
| `firewall` | Profiles and available rule evidence |
| `wifi` | Active wireless profile and connection properties |
| `full` | Complete bounded Network view |

```powershell
.\axios.ps1 -Mode System -SystemFocus quick
.\axios.ps1 -Mode Network -NetworkFocus services
.\axios.ps1 -Mode Network -NetworkFocus full
```

### Persistence, Software and Results

Legacy `Persistence` inspects Registry Run entries, startup commands and folders, services, scheduled tasks, extended persistence, and WMI permanent subscriptions. `Software` reviews installed applications and update exposure. `Results` reopens the latest completed assessment and separates findings, review items, context, and collection gaps.

```powershell
.\axios.ps1 -Mode Persistence
.\axios.ps1 -Mode Software
.\axios.cmd -Mode Results
```

## Developer commands

These tools are isolated from normal collection and omitted from public Help output.

| Command | Purpose |
|---|---|
| `.\axios.cmd -Mode DeveloperExposure` | Advanced exposure assessment |
| `.\axios.cmd -Mode DeveloperCredential` | Current Wi-Fi credential in the terminal, with optional encrypted export |
| `.\axios.cmd -Mode DeveloperCredential -Decrypt` | Decrypt an authenticated archive in the terminal |

Legacy `DeveloperArchive` remains available through `axios.ps1`. Export uses AES-256-GCM, password-based key derivation, and a random archive identity. Authentication is verified before decrypt display; no plaintext output file is created. Never publish credentials or machine reports.

The credential display stays in the terminal. If the optional archive is saved, it is encrypted and requires the password to decrypt. Normal User, Network, and Administrator result files do not include the credential view.

## Reading the results

### Collection status

| Status | Meaning |
|---|---|
| `complete` | Bounded collection finished with no reported gap |
| `partial` | Useful evidence collected, but a limit or unavailable capability reduced visibility |
| `failed` | The collector did not produce a valid result |
| `not_attempted` | Not requested, or prerequisites were unavailable |
| `unknown` | Available evidence can't support a truthful status |

A `partial` result is **not necessarily a software failure**. It can mean an access restriction, a bounded evidence limit, an unavailable Windows capability, or a collector that truthfully preserved incomplete visibility.

Review the coverage and collection-error sections before interpreting any finding. A missing protected event log, for example, limits the investigation; it does not establish that the event never occurred.

### Findings model

| Tier | Meaning |
|---|---|
| **High-priority** | Verified conditions requiring urgent review |
| **Medium** | Verified weaknesses with meaningful exposure |
| **Review items** | Observed evidence needing operator validation |
| **Context observations** | Relevant state that is not itself proof of compromise |
| **Visibility limitations** | Evidence that couldn't be collected completely |
| **Collection errors** | Explicit collector or capability failures |

## Saving artifacts

Without `-Save`, PowerShell keeps evidence for the current session. The CMD launcher caches the latest result in the current user profile and removes entries older than one day. Add `-Save` to retain artifacts:

```powershell
.\axios.ps1 -Mode System -Save
.\axios.ps1 -Mode Network -NetworkFocus full -Save
.\axios.ps1 -Mode User -Save
```

`Results` reads the latest completed command available to the session.

## Building from source

**Requirements**

- Rust toolchain and Cargo
- PowerShell
- MinGW-w64 toolchain for the Windows GNU target
- `x86_64-pc-windows-gnu` Rust target
- ZIP and standard Unix build utilities

**Verify**

```bash
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
```

**Build the Windows distribution**

```bash
./scripts/build-windows-complete-investigation.sh
```

The release builder compiles the executables, assembles the package, generates the SHA-256 manifest, and validates the packaged interface.

**Repository layout**

```text
src/         Rust collectors, analysis, evidence models, and binaries
tests/       Integration, runtime, precision, privacy, and contract tests
installer/   Windows PowerShell orchestration and package assets
scripts/     Build, packaging, and public launcher tooling
docs/        Documentation images and visual assets
.github/     Issue and pull-request templates
```

Build directories, investigation results, credentials, dumps, packet captures, keys, and local machine artifacts are excluded from the repository.

## FAQ

**Does AXIOS fix problems it finds?**
No. It's strictly non-destructive. It reports; you decide.

**Why does my run show a `partial` report?**
A limit (like the file-audit candidate cap) or an unavailable capability reduced visibility. AXIOS is telling you exactly where its view ends instead of hiding it.

**Do I need Administrator?**
Only for the full 42-stage investigation. `User` mode works from a standard session.

**Does a finding mean I'm compromised?**
Not by itself. Findings are tiered, and context observations are explicitly *not* proof of compromise.

**Can I scan a whole subnet?**
No. Targeted checks accept only explicit hostnames or IPs, by design.

## Release

AXIOS uses calendar releases. The current stable [v2026.11.23](https://github.com/Adam-dods/axios-windows-investigation/releases/tag/v2026.11.23) was published 23 November 2026 for Windows as `axios-windows-investigation.cmd` plus a `.sha256` file. Rust package metadata still reads `2026.9.27`; the GitHub tag identifies this distribution. The [first stable release](https://github.com/Adam-dods/axios-windows-investigation/releases/tag/v2026.9.27) was published 1 October 2026.

## Security

If Code Integrity blocks an unsigned component, report the limit instead of disabling protections. Please **do not** report suspected vulnerabilities in a public issue. Follow the private process in [SECURITY.md](SECURITY.md).

AXIOS is intended only for authorized investigation of systems you own or are permitted to assess.

## Contributing

See [Contributing.md](Contributing.md) for requirements, validation commands, commit expectations, and pull-request standards. Any change affecting evidence interpretation must preserve:

- Evidence provenance
- Bounded execution
- Explicit error handling
- Truthful collection status
- Separation of findings and context
- Privacy and source-hygiene guarantees

## License

Licensed under the [Apache License 2.0](LICENSE).

Copyright © 2026 Adam-dods.
