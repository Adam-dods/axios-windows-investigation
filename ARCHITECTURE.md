# AXIOS Architecture

> **Collection produces evidence. Validation establishes its quality. Correlation establishes its relationships. Reasoning evaluates supported explanations. Only then may the platform present a conclusion.**

No later layer is allowed to silently repair, hide, or overstate the uncertainty produced by an earlier layer.

---

## Contents

- [The big picture](#the-big-picture)
- [Five architectural boundaries](#five-architectural-boundaries)
- [Repository structure](#repository-structure)
- [Layer by layer](#layer-by-layer)
- [End-to-end flow](#end-to-end-flow)
- [Architectural guarantees](#architectural-guarantees)
- [Design rules for contributors](#design-rules-for-contributors)

---

## The big picture

```text
Operator command
      │
      ▼
Public parameter validation
      │
      ▼
Privilege and package checks
      │
      ▼
Bounded native collection
      │
      ▼
Evidence normalization
      │
      ▼
Collection-integrity review
      │
      ▼
Cross-source correlation
      │
      ▼
Reasoning Web
      │
      ▼
Response-plan generation
      │
      ▼
Console and structured results
```

Every layer asks one question and answers only that question:

| Layer | The question it answers |
|---|---|
| Public interface | What does the operator want, and is the request valid in this Windows context? |
| Orchestration | Which components must run, in what order, and how are results preserved? |
| Native collection | What evidence is directly observable on this system? |
| Normalization | Can evidence from different collectors and Windows environments be compared safely? |
| Trust and integrity | Which evidence is reliable enough for higher-level analysis? |
| Correlation | Which observations describe the same activity, and how does that change priority? |
| Reasoning Web | Which explanations fit the evidence, what conflicts, and what should be verified next? |
| Response planning | What should a human investigator verify first? |
| Results | How can the investigation be reviewed without losing the evidence behind it? |

---

## Five architectural boundaries

The repository holds many files, but they all follow five boundaries:

1. **PowerShell controls execution.**
2. **Rust collects and analyzes evidence.**
3. **Structured reports connect the layers.**
4. **Correlation operates only on validated evidence.**
5. **Results preserve both conclusions and visibility limitations.**

---

## Repository structure

The tree below shows architectural responsibilities, not every file.

```text
axios-windows-investigation
│
├── axios.ps1                  Stable public PowerShell entrypoint
├── Cargo.toml / Cargo.lock
├── README.md  CHANGELOG.md  CONTRIBUTING.md  SECURITY.md  LICENSE
│
├── docs
│   ├── ARCHITECTURE.md
│   └── images                 Sanitized Windows runtime demonstrations
│
├── installer
│   └── windows                Complete investigation coordinator
│                              Focused investigation runners
│                              Results and evidence rendering
│                              Portable-result generation
│                              Windows packaging resources
│
├── scripts
│   ├── Run-AXIOS.ps1
│   ├── Run-AXIOS-Layer.ps1
│   ├── Windows release builder
│   └── Source and package validation tooling
│
├── src
│   ├── main.rs                Primary axios-core executable
│   ├── lib.rs                 Shared library and internal modules
│   │
│   ├── bin                    Standalone investigation executables
│   │   ├── Process and application investigation
│   │   ├── Network exposure and service review
│   │   ├── File and artifact investigation
│   │   ├── Boot and Code Integrity review
│   │   ├── Kernel and driver trust review
│   │   ├── Defender and security-control review
│   │   ├── Identity and access review
│   │   ├── Platform-hardening review
│   │   ├── Collection-integrity review
│   │   ├── Cross-source observation review
│   │   ├── Investigation-state construction
│   │   ├── Reasoning and correlation
│   │   └── Response-plan generation
│   │
│   ├── analysis               Normalization, classification, risk and priority,
│   │                          event correlation, contradiction detection,
│   │                          evidence chains, bounded reasoning
│   ├── persistence            Run keys, startup folders, scheduled tasks,
│   │                          services, drivers, extended mechanisms
│   ├── processes              Live collection, path normalization,
│   │                          parent/child links, token and integrity context,
│   │                          trust analysis
│   ├── network                Adapters, DNS and routing, TCP/UDP activity,
│   │                          listeners, service correlation, firewall context,
│   │                          explicit bounded target checks
│   ├── security               Native Authenticode, access control, Defender,
│   │                          security controls, Code Integrity,
│   │                          trust-state normalization
│   ├── system                 Hardware trust, firmware, TPM and Secure Boot,
│   │                          BitLocker and VBS, kernel posture, driver trust,
│   │                          runtime resources, memory execution,
│   │                          browser extensions, software inventory, health
│   ├── telemetry              Event Log evidence, security-event correlation,
│   │                          timelines, runtime measurements
│   ├── storage                JSON reports, snapshots, portable results,
│   │                          manifests, SHA-256 integrity records
│   ├── runtime                Bounded scheduling, worker coordination,
│   │                          limits, performance measurements
│   └── watchers               File-policy evaluation, evidence routing,
│                              bounded file-watcher primitives
│
└── tests
    ├── Command-interface contracts
    ├── Privilege-boundary contracts
    ├── Evidence-precision contracts
    ├── Result-rendering contracts
    ├── Privacy and source-hygiene contracts
    ├── Windows-compatibility contracts
    ├── Package-integrity contracts
    ├── Runtime-parser contracts
    └── Complete-investigation contracts
```

---

## Layer by layer

### 1. Public interface

```text
axios.ps1
    ├── Help
    ├── User
    ├── Administrator
    ├── System
    ├── Network
    ├── Persistence
    ├── Software
    └── Results
```

`axios.ps1` is the stable public entrypoint. It accepts the mode, validates parameters, verifies the execution context, and forwards the request to the internal runner. Operators never need to call individual Rust executables.

**Why it matters:** internal collectors can evolve without breaking the public command interface.

---

### 2. Windows orchestration

```text
axios.ps1 → scripts/Run-AXIOS.ps1 → scripts/Run-AXIOS-Layer.ps1 → installer/windows runners
```

This layer connects the public command to the native components. It handles:

- Parameter and mode routing
- Privilege validation
- Package preflight checks
- Session initialization
- Working-directory management
- Native executable invocation
- Exit-code validation
- Report collection
- Human-readable output
- Session result retention

> It never decides that a system is compromised. It coordinates collectors and preserves their results.

---

### 3. Native collection

```text
Windows APIs and system sources → Rust collectors → Structured reports
```

Compiled Rust components collect evidence directly from Windows-native sources:

| Category | Evidence |
|---|---|
| Execution | Processes and executable paths, memory-execution indicators |
| Persistence | Services, scheduled tasks, registry persistence |
| Kernel | Drivers and kernel state |
| Network | Adapters, active endpoints, firewall configuration |
| Defenses | Security controls, Defender evidence |
| Telemetry | Event logs |
| Inventory | Software inventory |
| Platform | Boot and firmware state |
| Files | Metadata and hashes |
| Trust | Native signature-verification results, access-control information |

Each collector owns **one bounded area** and returns its own status, observations, findings, errors, and visibility limitations.

---

### 4. Evidence normalization

```text
Raw collector output → Schema and status validation → Normalized evidence
```

Windows doesn't return the same data format across versions, languages, privilege levels, or configurations. Normalization makes evidence comparable. It handles:

- Missing optional fields
- Localized Windows output
- Legacy Windows fallbacks
- Path normalization
- Status normalization
- Duplicate observations
- Structured collection errors
- Partial visibility
- Unsupported capabilities

> **Hard rule:** normalization never invents a value when the source didn't provide one.

---

### 5. Trust and integrity review

```text
Normalized evidence
    ├── Native signature verification
    ├── Package-integrity verification
    ├── Access-control inspection
    ├── Collection-status verification
    └── Contradiction detection
              │
              ▼
      Trusted evidence set
```

Before correlation, AXIOS checks whether the evidence is structurally valid and whether the investigation package itself is complete. It looks for:

- Missing required reports
- Failed collectors
- Partial reports
- Modified or missing package files
- Invalid evidence references
- Contradictory collector results
- Duplicate evidence
- Unavailable trust states
- Unsupported security claims

> An unavailable signature result is **not** converted into a trusted result. A missing report is **not** converted into an empty successful report.

---

### 6. Cross-layer correlation

```text
Files ────────────┐
Processes ────────┤
Persistence ──────┤
Network ──────────┤
Memory ───────────┼──▶ Correlation graph
Drivers ──────────┤
Boot integrity ───┤
Security controls ┤
Identity ─────────┤
Events ───────────┘
```

Correlation links related evidence **without destroying its provenance**.

```text
Executable file
    ├── Started by a persistence mechanism
    ├── Running as a live process
    ├── Listening on a network endpoint
    ├── Located in a user-writable directory
    └── Missing a verified trust result
```

Any one of these may be only context. Together, they can justify higher-priority review.

Correlation also **reduces noise**: something that first looks unusual can be reclassified when independent evidence shows it belongs to a trusted Windows or application context.

---

### 7. Reasoning Web

```text
Verified facts
     │
     ▼
Evidence relationships
     ├── Supporting facts
     ├── Contradictions
     ├── Alternative explanations
     └── Unresolved facts
                │
                ▼
      Bounded hypotheses
                │
                ▼
     Next-best verification steps
```

The Reasoning Web models the investigation as **connected facts**, not a flat list of alerts. Each branch looks like this:

```text
Observation
    │
    ▼
Candidate explanation
    ├── Supporting evidence
    ├── Conflicting evidence
    ├── Missing verification
    └── Confidence calculation
```

It can build several competing branches, but it can never claim more confidence than the evidence supports.

**Its rules**

1. Context does not equal compromise.
2. Repeated copies of the same observation are not independent support.
3. Missing evidence cannot support a positive conclusion.
4. Contradictions stay visible.
5. Independent evidence increases confidence.
6. Unsupported branches remain unresolved.
7. Confirmed-malware language requires stronger evidence than a configuration weakness or review item.

---

### 8. Response planning

```text
Supported findings + Unresolved evidence + Collection limitations
                         │
                         ▼
               Prioritized response plan
```

Turns results into ordered analyst actions:

- High-priority verification
- Medium-priority review
- Configuration review
- Evidence-preservation guidance
- Additional collection recommendations
- Explicitly unresolved items

> The plan is **advisory**. It never changes the system.

---

### 9. Results and evidence preservation

```text
Collector reports
    ├── Console summary
    ├── Portable result
    ├── Evidence manifest
    ├── Performance summary
    └── Saved investigation artifacts
```

The console renderer shows what a human needs while hiding internal temporary paths and machine receipts. Structured reports preserve:

- Evidence provenance
- Collector status
- Findings and context observations
- Errors and visibility limitations
- Correlation references
- Reasoning conclusions
- Response-plan items
- Performance measurements
- Integrity metadata

---

## End-to-end flow

| Step | Stage | What happens |
|---:|---|---|
| 1 | Request validation | Mode, parameters, execution context, target format, and package components are validated |
| 2 | Evidence collection | Rust collectors gather bounded evidence from Windows APIs and local sources |
| 3 | Status preservation | Each component records complete, partial, failed, unavailable, or not requested |
| 4 | Normalization | Values are normalized without hiding missing fields, localization differences, or access limits |
| 5 | Integrity review | Report structure, package integrity, references, duplicates, and contradictions are checked |
| 6 | Correlation | Related facts from independent sources are linked, keeping original references |
| 7 | Reasoning | Competing explanations, unresolved facts, and confidence are evaluated |
| 8 | Planning | Findings and gaps become prioritized analyst steps |
| 9 | Presentation | A concise console assessment, plus structured artifacts when requested |

---

## Architectural guarantees

| Guarantee | Meaning |
|---|---|
| Evidence provenance | Findings retain the sources that produced them |
| Failure visibility | Collector failures remain visible |
| Partial-state honesty | Limited collection is never presented as complete |
| Bounded execution | Collection operates under explicit limits |
| Privilege separation | Modes enforce their required execution context |
| Non-destructive behavior | Investigation never remediates the system |
| Correlation discipline | Context is not automatically promoted to a threat |
| Contradiction preservation | Conflicting evidence stays available for review |
| Package integrity | Required release components are verified |
| Stable public interface | Internals can evolve without breaking primary commands |

---

## Design rules for contributors

If you change any layer, you must keep these true:

1. Don't repair, hide, or overstate uncertainty that an earlier layer produced.
2. Don't invent values the source didn't provide.
3. Don't turn a failed or missing result into a clean one.
4. Don't count duplicate observations as independent evidence.
5. Don't present context as confirmed compromise.
6. Keep provenance attached to every finding.

---
