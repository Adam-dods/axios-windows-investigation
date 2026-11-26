# AXIOS Command Guide

Run the investigation from one extracted package: **pick a mode → add a focus only if needed → review coverage → save evidence deliberately.**

**Jump to:** [Setup](#setup) · [Cheat sheet](#cheat-sheet) · [Modes](#modes) · [Target checks](#authorized-target-checks) · [Developer commands](#developer-commands) · [Saving](#saving-evidence) · [Parameters](#parameters) · [Reading results](#reading-results) · [Troubleshooting](#troubleshooting)

---

## Setup

Download the [v2026.11.23 CMD asset](https://github.com/Adam-dods/axios-windows-investigation/releases/tag/v2026.11.23) into Downloads (not GitHub's source ZIP). To verify it first, see [Verify the download](#verify-the-download). With Windows PowerShell and permission to investigate the device, extract it once and run a mode:

```powershell
cd ~/Downloads
.\axios-windows-investigation.cmd
cd .\AXIOS\axios-windows-investigation
.\axios.cmd -Mode User
```

The CMD only extracts; the chosen mode displays its result directly in the terminal. Later, enter `~/Downloads/AXIOS/axios-windows-investigation` and run the mode you need. `axios.cmd` works in PowerShell and CMD; `axios.ps1` is also available in PowerShell. Only Administrator mode requires elevation.

### Verify the download

```powershell
(Get-FileHash "$env:USERPROFILE\Downloads\axios-windows-investigation.cmd" -Algorithm SHA256).Hash
```

Expected SHA-256: `796bfdc914bfc29d06fa1ea335d87b89ed53011dcc5939f7636ce9b0bee7c1a7`. Compare it before running the CMD. The [release checksum file](https://github.com/Adam-dods/axios-windows-investigation/releases/download/v2026.11.23/axios-windows-investigation.cmd.sha256) is also available. A matching checksum confirms that the download matches the published digest; it does not prove the program is safe.

> All commands below assume the extracted package is your current directory.

---

## Cheat sheet

| Goal | Command | Admin |
|---|---|:-:|
| See the interface | `.\axios.cmd -Mode Help` | – |
| Standard-user assessment | `.\axios.cmd -Mode User` | – |
| Quick system review | `.\axios.cmd -Mode User -Focus SystemQuick` | – |
| Network assessment | `.\axios.cmd -Mode Network` | – |
| TCP/UDP evidence | `.\axios.cmd -Mode Network -NetworkFocus connections` | – |
| Full 42-stage investigation | `.\axios.cmd -Mode Administrator` | ✅ |
| Reopen the latest result | `.\axios.cmd -Mode Results` | – |

`axios.ps1` accepts the same public modes, e.g. `.\axios.ps1 -Mode User`.

**Which mode?**

| I want to… | Mode |
|---|---|
| list commands | `Help` |
| check exposure with a normal account | `User` |
| run the complete 42-stage investigation | `Administrator` |
| inspect hardware, boot, kernel, controls | `System` *(legacy)* |
| review adapters, DNS, listeners, connections | `Network` |
| review startup and persistence | `Persistence` *(legacy)* |
| review software and updates | `Software` *(legacy)* |
| read the last completed assessment | `Results` |

---

## Modes

### Help

```powershell
.\axios.cmd -Mode Help
```

Lists public modes, focus branches, parameters, privilege needs, and examples. Developer commands are intentionally omitted. Treat the Help shipped with your package as the reference for that build.

### User

```powershell
.\axios.cmd -Mode User
```

Works in standard or elevated sessions. Examines user-visible processes, startup entries, accessible tasks and services, execution surfaces, network configuration, permissions visible to the token, and exposure evidence. Heading: `STANDARD USER SECURITY ASSESSMENT`.

| Focus | Scope |
|---|---|
| `System` | Available system evidence |
| `SystemQuick` | Short review of the most relevant controls |
| `SystemContext` | Time, locale, network context that may explain other findings |
| `Persistence` | Accessible persistence |
| `Software` | Software and updates |

```powershell
.\axios.cmd -Mode User -Focus SystemQuick
```

Protected evidence you can't reach is a **visibility limitation**, never proof of a clean system. A zero-finding result means nothing until you check collector coverage.

### Administrator

Open PowerShell **as Administrator**, return to the folder, then:

```powershell
.\axios.cmd -Mode Administrator
```

Runs 42 stages: persistence, execution, CPU/memory, hardware and firmware, kernel and drivers, network, Defender and controls, software, events, files, boot and Code Integrity, identity, integrity checks, correlation, Reasoning Web, and response planning. Progress counts `[1/42]` to `[42/42]`.

The final `COMPREHENSIVE SECURITY INVESTIGATION` summary contains:

| Group | Contents |
|---|---|
| Run state | Completion, observed / failed / partial reports |
| Findings | High and medium findings, context, collection errors |
| Reasoning | Leading hypothesis, sources, contradictions, unresolved facts |
| Follow-up | Next checks grounded in collected evidence |

Completed stages do **not** imply complete visibility.

**Smart file audit**

```powershell
.\axios.cmd -Mode Administrator -AuditMode smart -MaxFiles 5000
```

`-AuditMode` is `fast` (default) or `smart`. `-MaxFiles` bounds candidates (1–25,000, default 1500). Reaching the limit is reported as partial coverage.

### System *(legacy)*

```powershell
.\axios.cmd -Mode System -SystemFocus quick
```

Hardware trust, Secure Boot, TPM, BitLocker visibility, virtualization-based security, kernel and driver posture, controls, health, boot evidence. Heading: `SYSTEM SECURITY ASSESSMENT`.

| `-SystemFocus` | Scope |
|---|---|
| `overview` | Broad posture |
| `quick` | Important controls |
| `context` | Supporting observations |

A missing TPM, BitLocker, or protected kernel signal is reported with its collection status, never silently treated as absent.

### Network

```powershell
.\axios.cmd -Mode Network
```

Adapters, IP configuration, DNS, routes, neighbors, firewall profiles and rules, Wi-Fi properties, TCP/UDP endpoints, listeners. Heading: `NETWORK SECURITY ASSESSMENT`. Default focus: `full`.

| `-NetworkFocus` | Evidence |
|---|---|
| `overview` | Concise overview |
| `services` | Listeners and service/process context |
| `connections` | TCP connections and UDP endpoints |
| `routing` | Routes, gateways, interfaces, neighbors |
| `dns` | DNS configuration |
| `firewall` | Profiles and available rules |
| `wifi` | Active profile and connection properties |
| `full` | Complete bounded view |

Some firewall evidence needs elevation. If unavailable, AXIOS reports it (for example `not_attempted` with `administrator_required`); it never turns an unknown rule count into zero. Normal Network mode never shows the Wi-Fi password. A routine outbound connection can stay *context*; neither state alone is proof of compromise.

### Persistence *(legacy)*

```powershell
.\axios.cmd -Mode Persistence
```

Registry Run entries, startup commands and folders, scheduled tasks, services, extended persistence, WMI permanent subscriptions. Groups: `ASSESSMENT COVERAGE`, `PERSISTENCE SURFACE`. An unavailable WMI or protected task source limits coverage; absence from a table is not proof that nothing persists there.

### Software *(legacy)*

```powershell
.\axios.cmd -Mode Software
```

Installed software, update exposure, application posture, browser extensions. It never removes or updates anything. Results vary with permissions and Windows APIs, so check collection status when a source is missing.

### Results

```powershell
.\axios.cmd -Mode User
.\axios.cmd -Mode Results
```

Reopens the latest **completed** assessment and separates findings, review items, context, visibility, coverage, unresolved verification, and next checks. Heading: `SECURITY ASSESSMENT SUMMARY`.

- `axios.cmd` keeps a per-user cache across CMD sessions and deletes entries older than one day.
- Direct `axios.ps1` calls keep unsaved evidence only in the current PowerShell session, so run `Results` in the same session.
- Running another mode changes what `Results` shows. Use `-Save` for anything you want to compare later.

---

## Authorized target checks

```powershell
.\axios.ps1 -Mode Network -NetworkFocus connections -Target 192.0.2.10 -Ports 80,443
.\axios.ps1 -Mode Network -NetworkFocus connections -Target server.example.invalid -Ports 443,8443
```

Supply explicit hostnames or IPs plus ports, and only for systems you own or are authorized to test. Use `axios.ps1` so PowerShell binds the comma-separated port array.

`-Target` works only with `connections` (or legacy `targeted`). `-Ports` requires `-Target`.

| Rejected input | Reason |
|---|---|
| `192.168.1.0/24` | CIDR range |
| `192.168.*.*` | Wildcard |
| `127.0.0.1 && whoami` | Command-like input |
| `$(whoami)` | Command-like input |
| Port `0` | Invalid port |

---

## Developer commands

Isolated from normal assessments and hidden from Help. Use only on devices and networks you are authorized to inspect.

| Command | Purpose |
|---|---|
| `.\axios.cmd -Mode DeveloperExposure` | Advanced exposure report (diagnostic; never exploits anything) |
| `.\axios.cmd -Mode DeveloperCredential` | Show the connected Wi-Fi credential in the terminal |
| `.\axios.cmd -Mode DeveloperCredential -Decrypt` | Select and decrypt a compatible archive |

**Credential viewer.** Shows SSID, authentication, cipher, and password **only in the terminal**, then asks whether to save an encrypted copy. Enter or `N` creates no file. `Y` asks for a password and writes a randomly named `.dat` archive in Downloads.

- Encryption: AES-256-GCM, key from PBKDF2-SHA256 (200,000 iterations). No plaintext file is ever written.
- Decryption authenticates the archive first. A wrong password or modified archive yields no plaintext output. If no archive is in Downloads, it says so.
- Never combine the credential view with `-Save`, `-Target`, or `-Ports`.
- Normal User, Network, and Administrator results never contain credential data.

Legacy equivalents: `.\axios.ps1 -Mode DeveloperArchive`, or `.\axios.ps1 -Mode Network -View wifi -DeveloperCredentialView` (add `-DecryptCredentialFile` to decrypt).

> Never publish credentials or machine reports.

---

## Saving evidence

Without `-Save`, PowerShell keeps evidence for the session and CMD uses the one-day cache.

```powershell
.\axios.cmd -Mode User -Save
.\axios.cmd -Mode Network -NetworkFocus full -Save
.\axios.ps1 -Mode User -Save -OutputDirectory "$env:USERPROFILE\Downloads\AXIOS-Reports"
```

Reports save to Downloads by default; `-OutputDirectory` requires `-Save`.

**Before sharing a report, check it for:** usernames, hostnames, internal paths and IPs, installed software, browser details, and security configuration.

---

## Parameters

| Parameter | Applies to | Values / purpose |
|---|---|---|
| `-Mode` | all | Operation (default `Help`) |
| `-Focus` | `User` | `General`, `System`, `SystemQuick`, `SystemContext`, `Persistence`, `Software` |
| `-SystemFocus` | `System` | `overview`, `quick`, `context` |
| `-NetworkFocus` / `-View` | `Network` | Focus table above (legacy `targeted` also exists) |
| `-NetworkProfile` | `Network` | `auto`, `standard`, `administrator` (the last needs elevation) |
| `-Target`, `-Ports` | Network `connections` | Explicit hosts and ports |
| `-TimeoutMs` | `Network` | 50–10,000 ms (default 750) |
| `-AuditMode`, `-MaxFiles` | `Administrator` | `fast`/`smart`; 1–25,000 |
| `-Save` | assessment modes | Keep artifacts |
| `-OutputDirectory` | with `-Save` | Report location |

Mode-specific parameters are rejected with unrelated modes:

```powershell
.\axios.cmd -Mode User -NetworkFocus full      # invalid
.\axios.cmd -Mode Network -NetworkFocus full   # valid
```

---

## Reading results

**Collection status**

| Status | Meaning |
|---|---|
| `complete` | Finished with no reported gap |
| `partial` | Useful evidence, reduced visibility |
| `failed` | No valid result |
| `not_attempted` | Not requested, or prerequisites unavailable |
| `unknown` | Evidence can't support a truthful status |

**Finding tiers**

| Tier | Meaning |
|---|---|
| High priority / Medium | Verified conditions for review |
| Review item | Needs operator validation |
| Context | Relevant state, not proof of compromise |
| Visibility limitation | Evidence not fully collected |
| Collection error | Named collector or capability failure; investigate before trusting that area |

`partial` can come from access limits, missing Windows capabilities, or bounded limits (such as the file-audit cap). A finding alone doesn't prove compromise, and a completed run doesn't guarantee every artifact was visible.

---

## Troubleshooting

| Problem | What to do |
|---|---|
| **Administrator needs elevation** | Open an elevated PowerShell, `Set-Location` to the folder, rerun `.\axios.cmd -Mode Administrator`. |
| **Results finds nothing** | Run an assessment first, in the same terminal for `axios.ps1`, or via `axios.cmd` for the user cache. Add `-Save` for persistence. |
| **Package integrity failure** | Move the incomplete `Downloads\AXIOS` folder aside, check the published hash, and rerun the official CMD. Never run a partial package. |
| **Blocked by policy / Code Integrity** | Record the exact error and policy. Do not disable protections. Use the packaged CMD interface. |
| **Report is partial** | Read its visibility limitations and collection errors; they say exactly what couldn't be seen. |

---

## Quick start by goal

| Goal | Commands (from the extracted folder) |
|---|---|
| Standard user | `.\axios.cmd -Mode User` → `.\axios.cmd -Mode Results` |
| Network | `.\axios.cmd -Mode Network -NetworkFocus full` → `Results` |
| System | `.\axios.cmd -Mode User -Focus SystemQuick` → `Results` |
| Persistence | `.\axios.cmd -Mode User -Focus Persistence` → `Results` |
| Administrator | *(elevated)* `.\axios.cmd -Mode Administrator` → `Results` |

```text
Select a mode → optional focus → run → review coverage → save only if needed.
```

You never need to run the 46 native components yourself.
