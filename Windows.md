# Windows Requirements and Privileges

Setup, privileges, visibility, and common runtime problems for AXIOS on Windows. For every mode and parameter, see [Commands.md](Commands.md).

> **More privilege can increase visibility. It never makes incomplete evidence complete.**

## At a glance

| Question | Answer |
|---|---|
| Installation required? | No. Extract the release CMD into Downloads, then run `axios.cmd`. |
| Administrator required? | Only for `Administrator` mode and options that explicitly say so. |
| Works as a standard user? | Yes. Protected evidence is reported as unavailable. |
| Elevation guarantees full visibility? | No. Windows protections, missing APIs, and collection limits still apply. |

---

## Setup

**You need:** Windows with Windows PowerShell, permission to investigate the device, and the [v2026.11.23 CMD asset](https://github.com/Adam-dods/axios-windows-investigation/releases/tag/v2026.11.23). The GitHub source ZIP does **not** contain the packaged executables.

Save `axios-windows-investigation.cmd` in Downloads, then in a **standard PowerShell window**:

```powershell
$File = "$env:USERPROFILE\Downloads\axios-windows-investigation.cmd"
$Expected = '796bfdc914bfc29d06fa1ea335d87b89ed53011dcc5939f7636ce9b0bee7c1a7'
if ((Get-FileHash $File -Algorithm SHA256).Hash -ne $Expected) {
    throw 'AXIOS download checksum mismatch'
}
& $File
Set-Location "$env:USERPROFILE\Downloads\AXIOS\axios-windows-investigation"
.\axios.cmd -Mode Help
```

- The CMD shows extraction progress and returns **without starting an investigation**.
- The extracted folder holds `axios.cmd` (CMD or PowerShell) and `axios.ps1` (PowerShell). Keep it intact.
- In later sessions, go straight to that folder; no need to extract again.
- The checksum only compares your download with the published digest. It does not prove the program is safe.

---

## Privileges and visibility

Running a command and collecting every source are different things. A standard user can run most modes, but Windows may deny access to protected processes, firewall rules, system locations, or security configuration. AXIOS reports that limit instead of treating missing evidence as clean.

| Mode | Standard | Elevated | Purpose |
|---|:---:|:---:|---|
| `Help` | ✅ | ✅ | Commands and parameters |
| `User` | ✅ | ✅ | Evidence available to the current token |
| `System` | ✅ | ✅ | System and security posture |
| `Network` | ✅ | ✅ | Network state and exposure |
| `Persistence` | ✅ | ✅ | Accessible persistence evidence |
| `Software` | ✅ | ✅ | Inventory and updates |
| `Results` | ✅ | ✅ | Latest available assessment |
| `DeveloperExposure` | ✅ | ✅ | Advanced exposure assessment |
| `DeveloperCredential` | ✅ | ✅ | Wi-Fi credential view or archive decryption |
| `DeveloperArchive` | ✅ | ✅ | Legacy archive decryption |
| `Administrator` | ❌ | ✅ | Complete 42-stage investigation |

Some Network options need elevation even though plain `Network` mode doesn't; check [Commands.md](Commands.md) for the option you choose. Credential data appears only via an explicit developer command. Never share its output or encrypted archive publicly.

### What elevation adds

`Administrator` mode runs 42 bounded stages and can reach more system-wide persistence, processes, services, security controls, event evidence, drivers, and boot posture. Protected processes, endpoint products, missing APIs, and collection limits can still reduce coverage.

---

## Running an investigation

**Standard user** (from the extracted folder):

```powershell
.\axios.cmd -Mode User
.\axios.cmd -Mode Network
.\axios.cmd -Mode Results
```

**Narrower system review, no elevation:**

```powershell
.\axios.cmd -Mode User -Focus SystemQuick
```

**Complete investigation:** open **PowerShell as Administrator**, then:

```powershell
Set-Location "$env:USERPROFILE\Downloads\AXIOS\axios-windows-investigation"
.\axios.cmd -Mode Administrator
.\axios.cmd -Mode Results
```

---

## Reading collection status

| Status | Meaning |
|---|---|
| `complete` | Bounded collection finished with no reported gap |
| `partial` | Useful evidence, but visibility was limited |
| `failed` | No valid result |
| `not_attempted` | Not requested, or a prerequisite was unavailable |
| `unknown` | Evidence can't support a truthful status |

Example: firewall-rule evidence may show `not_attempted` with `administrator_required`. A `partial` report can come from denied access, a protected resource, an unavailable capability, or a time, file, or evidence limit. Read the visibility limitations and collection errors **before** interpreting findings.

A completed command means its bounded workflow finished. It does **not** mean every artifact was visible, or that the system is clean.

---

## Results and saved evidence

- `axios.cmd` caches the latest result per user across CMD sessions and deletes entries older than one day.
- `axios.ps1` keeps unsaved evidence in the current PowerShell session only; run `Results` in that same session.
- Running another assessment changes what `Results` opens.
- Add `-Save` to keep and compare evidence. Saved reports can contain sensitive machine data.

```powershell
.\axios.cmd -Mode User -Save
.\axios.cmd -Mode Results
```

---

## Compatibility and troubleshooting

Evidence varies by Windows version, edition, configuration, privilege level, security products, and available APIs. Validate a collector on the environment where you intend to rely on it. Unavailable capabilities stay visible as limitations.

| Problem | What to check |
|---|---|
| `Administrator` rejected | Open an elevated PowerShell and run it from the extracted folder. |
| Package validation fails | Compare the CMD hash, then extract the official package again into a clean folder. |
| Report is `partial` | Read its limits and collection errors. Partial is not automatically a software failure. |
| `Results` finds nothing | Run an assessment first. Use the same session for `axios.ps1`, or the `axios.cmd` cache. |
| Code Integrity or policy blocks a component | Record the exact error and component. **Do not disable Windows protections** to force execution. |

---

Use AXIOS only on systems you own or are authorized to investigate. Read [SECURITY.md](SECURITY.md) before sharing a vulnerability or investigation evidence.
