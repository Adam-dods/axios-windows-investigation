# Windows Requirements and Privileges

AXIOS is a Windows-focused security investigation platform. It collects and evaluates Windows security evidence through PowerShell orchestration and packaged native Rust components.

This document explains **what you need to run AXIOS**, **which commands need elevation**, and **how privilege level changes what AXIOS can see**.

> **More privilege can increase visibility, but it never justifies overstating evidence.**

---

## Contents

- [At a glance](#at-a-glance)
- [Requirements](#requirements)
- [Extracting the release package](#extracting-the-release-package)
- [PowerShell requirements](#powershell-requirements)
- [Privilege model](#privilege-model)
- [Command privilege matrix](#command-privilege-matrix)
- [Standard-user visibility](#standard-user-visibility)
- [Administrator visibility](#administrator-visibility)
- [Collection status and access limits](#collection-status-and-access-limits)
- [Compatibility](#compatibility)
- [Recommended starting points](#recommended-starting-points)
- [Troubleshooting](#troubleshooting)

---

## At a glance

| Question | Answer |
|---|---|
| Do I need to install anything? | No. Run the release CMD to extract the package, then use `axios.cmd` |
| Which commands need Administrator? | Only `Administrator` (the full 42-stage investigation) |
| Can I run everything else as a standard user? | Yes, with some protected evidence reported as unavailable |
| Does Administrator guarantee full visibility? | No. Windows protections and security products can still limit it |
| Is inaccessible evidence treated as clean? | Never |

---

## Requirements

To run AXIOS you need:

- A Windows system
- Windows PowerShell
- The official `axios-windows-investigation.cmd` release asset
- Permission to investigate the system
- Administrator PowerShell, **only** for the complete Administrator investigation

AXIOS needs no permanent installation. The release CMD extracts the package into Downloads; run `axios.cmd` from that folder afterward.

---

## Extracting the release package

Download the CMD asset from the [v2026.11.23 release](https://github.com/Adam-dods/axios-windows-investigation/releases/tag/v2026.11.23) into Downloads. Compare its SHA-256 with the value on the release page, then run:

```powershell
Get-FileHash "$env:USERPROFILE\Downloads\axios-windows-investigation.cmd" -Algorithm SHA256
& "$env:USERPROFILE\Downloads\axios-windows-investigation.cmd"
Set-Location "$env:USERPROFILE\Downloads\AXIOS\axios-windows-investigation"
.\axios.cmd -Mode Help
```

Expected package directory (example):

```text
C:\Users\TestUser\Downloads\AXIOS\axios-windows-investigation
```

The CMD shows extraction progress and does not start a scan. AXIOS validates required package components before dependent investigations. If validation reports a missing file, extract the official CMD package again into a clean directory.

---

## PowerShell requirements

The `axios.cmd` interface works in CMD and PowerShell. For example:

```powershell
.\axios.cmd -Mode Help
```

The `axios.ps1` interface also remains available in PowerShell. Keep the same terminal open for session results. If a device's security policy blocks a component, record the limitation; do not disable protections.

---

## Privilege model

AXIOS separates two different things:

| Concept | Meaning |
|---|---|
| **Privilege to start a mode** | Whether the command is allowed to run in your current PowerShell |
| **Visibility of each collector** | What each collector can actually see with your token |

A command can start fine as a standard user while some protected Windows evidence stays unavailable. AXIOS keeps that distinction visible in its output and never treats inaccessible evidence as proof that a protected area is clean.

---

## Command privilege matrix

| Command | Standard user | Administrator | Purpose |
|---|:---:|:---:|---|
| `Help` | ✅ | ✅ | Show supported commands and parameters |
| `User` | ✅ | ✅ | Evidence available to the current user token |
| `System` | ✅ | ✅ | Available system and security posture |
| `Network` | ✅ | ✅ | Available network-security evidence |
| `Persistence` | ✅ | ✅ | Persistence evidence available in the current context |
| `Software` | ✅ | ✅ | Software and update evidence |
| `Results` | ✅ | ✅ | Latest completed session assessment |
| `DeveloperExposure` | ✅ | ✅ | Advanced exposure assessment |
| `DeveloperCredential` | ✅ | ✅ | Active Wi-Fi credential evidence |
| `DeveloperArchive` | ✅ | ✅ | Decrypt a compatible AXIOS credential archive |
| `Administrator` | ❌ | ✅ | Complete 42-stage investigation |

> The full investigation **must** run from an elevated PowerShell window.

---

## Standard-user visibility

Standard-user mode is intentional and useful. It can review:

- User-visible processes
- User startup locations
- Accessible services and tasks
- Accessible network configuration
- Available software evidence
- User-level execution surfaces
- Accessible permissions
- Context and exposure evidence

A standard user may not be able to inspect all protected system locations, firewall rules, protected processes, or system-wide security configuration. When access is restricted, AXIOS reports the limitation explicitly:

```text
firewall_rules: not_attempted; administrator_required
```

---

## Administrator visibility

Open PowerShell with **Run as Administrator**, then:

```powershell
Set-Location "$env:USERPROFILE\Downloads\AXIOS\axios-windows-investigation"
.\axios.ps1 -Mode Administrator
```

Administrator mode coordinates the complete 42-stage investigation. Elevation can expand visibility into:

| Area | Examples |
|---|---|
| **Persistence** | System-wide persistence |
| **Configuration** | Protected security configuration, firewall-rule evidence |
| **Kernel and boot** | Kernel and driver posture, boot and Code Integrity evidence |
| **Runtime** | System-wide process and service context |
| **Telemetry** | Event and telemetry evidence |
| **Platform** | Hardware and firmware trust |
| **Identity** | Identity and access surfaces |
| **Analysis** | Cross-source correlation and final response planning |

> Administrator access does **not** guarantee complete evidence. Windows protections, protected processes, endpoint-security products, unavailable APIs, and bounded collection limits can still reduce visibility.

---

## Collection status and access limits

| Status | Meaning |
|---|---|
| `complete` | Bounded collection finished without a reported gap |
| `partial` | Useful evidence collected, but visibility was limited |
| `failed` | No valid result produced |
| `not_attempted` | Not requested, or prerequisites unavailable |
| `unknown` | Evidence can't support a truthful state |

A `partial` status can come from:

- Standard-user access restrictions
- Administrator privileges being required
- Protected Windows resources
- Endpoint-security interference
- Unavailable Windows capabilities
- A bounded time, file, event, or evidence limit

A completed AXIOS command means the selected bounded workflow finished. It does not mean every possible artifact on the system was visible.

---

## Compatibility

AXIOS is Windows-focused. Evidence availability depends on:

- Windows version and edition
- System configuration and enabled features
- Privilege level
- Security products
- Available Windows APIs

Where practical, AXIOS includes fallbacks for supported Windows interfaces. When a capability is unavailable, the report preserves that state instead of inventing a clean result.

> Before relying on a specific collector in an operational workflow, validate it on the intended Windows environment.

---

## Recommended starting points

| Goal | Commands |
|---|---|
| **Standard user** | `.\axios.ps1 -Mode User` then `.\axios.ps1 -Mode Results` |
| **Administrator** | `.\axios.ps1 -Mode Administrator` then `.\axios.ps1 -Mode Results` |
| **Network** | `.\axios.ps1 -Mode Network -NetworkFocus full` then `.\axios.ps1 -Mode Results` |
| **System** | `.\axios.ps1 -Mode System` then `.\axios.ps1 -Mode Results` |

---

## Troubleshooting

**Administrator mode is rejected**
Open a new PowerShell window with **Run as Administrator**, return to the AXIOS folder, and run the command again.

**Package-integrity validation fails**
Run the official CMD again into a clean directory. Never run AXIOS from an incomplete extraction.

**A report is partial**
Read the displayed visibility limitations and collection errors. A partial result is an honest description of incomplete coverage, not automatically a software failure.

**Results can't find an assessment**
Run `Results` in the same PowerShell session as the assessment (use `-Save` to retain artifacts):

```powershell
.\axios.ps1 -Mode User
.\axios.ps1 -Mode Results
```

---

## Principle

> More privilege can increase visibility, but it never justifies overstating evidence.

AXIOS reports what it could collect, what it could not collect, and why.

---
