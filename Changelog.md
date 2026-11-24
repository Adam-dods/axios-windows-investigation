# Changelog

Notable AXIOS changes, by calendar release. Validation results describe the packages and Windows environments actually tested; they do not guarantee the same result on every PC.

| Release | Date | Summary |
|---|---|---|
| [2026.11.23](#20261123--single-file-windows-cmd) | 2026-11-23 | Single-file self-extracting CMD, `axios.cmd` entry point, result cache, detection fixes |
| [2026.9.27](#2026927--first-stable-release) | 2026-10-01 | First stable release: 42-stage investigation, 46 executables |

---

## [2026.11.23] — Single-file Windows CMD

### Added

- **Single-file release asset:** `axios-windows-investigation.cmd` is self-extracting. It extracts into Downloads, shows progress, and returns **without starting a scan**.
- **`axios.cmd` entry point** for CMD and PowerShell. `axios.ps1` remains available for direct PowerShell use.
- **Main paths:** `User`, `Network`, and `Administrator`, with focused User and Network views, terminal tables, and compact progress for the 42 Administrator stages.
- **Per-user result cache** for separate `axios.cmd` invocations. Direct unsaved `axios.ps1` results stay in the current PowerShell session.

### Corrected and improved

**Detection accuracy**
- Service-path assessment: an unquoted path alone is **context**. A high-priority finding now requires a privileged service *and* a potentially writable interpretation candidate.
- Ordinary outbound connections from user-profile applications stay in network context unless stronger evidence supports a finding.

**Bug fixes**
- Administrator service-path ACL check now distinguishes file creation from subdirectory creation, and a PowerShell switch conversion error at stage 38 is fixed.
- Browser extension manifests and localized messages are read as UTF-8. Unlabelled forensic context now explains that the source supplied no description.

**Display**
- Repeated outbound observations are grouped in the terminal; individual structured records are kept.
- Process names are shown for protected listeners, TCP owning PIDs resolve to collected process names, IPv6 endpoints are bracketed, and legacy Windows event dates render as UTC.
- Improved finding details and the audit-correlation context label.

### Validation and limits

| Check | Result |
|---|---|
| PR #6 | Passed its final two CI checks; merged into `main` |
| Earlier Windows 11 package | **27/27** nonsecret command cases, including both Administrator audit modes at 42/42 stages |
| Final CMD (built on Kali), tested on Windows | Network `connections` and `services`: zero collection errors, expected process/PID and IPv6 display |
| 27-case matrix on the final CMD | ⚠️ **Not repeated** |
| Multiple Windows 11 PCs | Maintainer reports success; logs not published; not a universal compatibility claim |
| One documented validation | User run completed; Administrator 42/42; 0 confirmed threats, 12 important findings, 2 collection gaps **on that PC**. This does not establish that the PC was clean |

**Published CMD SHA-256:**

```text
796bfdc914bfc29d06fa1ea335d87b89ed53011dcc5939f7636ce9b0bee7c1a7
```

The release provides the CMD asset and its `.sha256` file. The GitHub-generated source ZIP does **not** include the packaged executables. Rust package metadata still reads `2026.9.27`, so identify this distribution by the GitHub tag or exact commit.

---

## [2026.9.27] — First stable release

*Published 2026-10-01.* Followed two months and 700+ hours of independent development, review, and validation. The numbers below belong to **this release**, not to the later CMD package.

| Measurement | Recorded result |
|---|---:|
| Administrator stages | 42 |
| Packaged Windows executables | 46 |
| Reports in final validation | 59 |
| Failed reports | 0 |
| Implementation and test code | 51,015 lines |
| Production Rust / Rust tests | 37,361 / 3,800 lines |
| PowerShell / Shell | 9,644 / 210 lines |

### Added

**Interface**
- `axios.ps1` with eight public modes: `Help`, `User`, `Administrator`, `System`, `Network`, `Persistence`, `Software`, `Results`. Mode-specific parameters are checked before execution.
- Focused System views (`overview`, `quick`, `context`) and Network views (`overview`, `services`, `connections`, `routing`, `dns`, `firewall`, `wifi`, `full`).
- Bounded, explicitly authorized target checks. Validation rejects ranges, wildcards, command-like input, and invalid ports.

**Investigation**
- 42-stage Administrator investigation: persistence, execution, telemetry, privileges, platform and kernel trust, network, defenses, software, files, health, integrity, correlation, reasoning, response planning.
- Standard-user investigation that keeps restricted evidence as partial or unavailable.
- Persistence coverage (Registry, startup locations, tasks, services, drivers, WMI permanent event subscriptions), software and update review, and session `Results`.
- Native Windows trust, registry, access-control, privilege, cryptographic, and security-state checks where available.

**Evidence model**
- Structured evidence with collection status, errors, visibility limits, provenance, performance data, and integrity metadata.
- Collection-integrity review, cross-source correlation, Reasoning Web, and advisory response planning. Missing evidence, duplicates, and contradictions cannot silently raise confidence.
- Package-integrity validation and performance reporting before final completion.

**Developer tools**
- Explicit developer exposure and credential commands, outside normal result paths. Optional encrypted export uses AES-256-GCM with PBKDF2-SHA256 (200,000 iterations), randomized filenames, and no plaintext output file.

### Changed

- Clarified findings, review items, context, limitations, and unsupported conclusions. An unusual observation alone is not confirmed compromise.
- Improved terminal rendering of grouped findings, nested data, dates, firewall profiles, unavailable capabilities, and internal-path privacy.
- Unavailable firewall-rule counts now show an explicit uncollected state instead of a misleading zero; wireless-property labels are normalized.
- Truncated file audits are now `partial`, preserving audit mode, scanned roots, candidate limits, time budget, and truncation state.
- Broad repeated optional-feature enumeration replaced by targeted collection of security-relevant Windows features.

### Performance

On the validated Windows environment, Administrator runtime dropped from **249,924 ms to 128,632 ms** (about 48.5%), with all 42 stages, reports, integrity checks, correlation, reasoning, and response planning intact. This measurement is specific to that environment.

### Security and reliability

- **Security:** strict target and parameter validation, privilege checks, bounded active checks, package preflight, privacy and source-hygiene checks, authenticated credential export, masked secret input, conservative unknown-trust handling.
- **Reliability:** working-directory restoration, UTF-8 handling, legacy Windows fallbacks, root-relative paths, access-denied status, deduplication, worker recovery, report validation, portable-result tolerance.

### Testing and packaging

Validation covered Rust formatting, tests, and linting; PowerShell parsing; Windows cross-compilation and runtime checks; archive integrity; extraction of 46 executables; standard-user and Administrator runs; Results; developer flows; partial-coverage propagation; and performance reporting.

The recorded full investigation finished with **59 reports, 0 failed, 1 partial**. The partial report came from a bounded file-audit limit and stayed visible as partial coverage.

Artifacts of this release (they describe the earlier packaging; for the single-file CMD use `v2026.11.23`):

```text
axios-windows-investigation.zip
axios-windows-investigation-source.tgz
axios-windows-investigation-source.txt
```

### Known limitations

AXIOS is Windows-focused. Privileges, protected processes, security products, Windows APIs, and bounded collection can restrict evidence. Socket metadata is not raw packet capture. AXIOS reports and prioritizes evidence; it does not automatically remediate or prove that a completed system is clean.

---

> **AXIOS must never present more certainty than the collected evidence supports.**
