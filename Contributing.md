# Contributing to AXIOS

Thank you for your interest in improving AXIOS.

AXIOS is an independently developed Windows security investigation platform. It helps people identify weaknesses in their systems, understand the evidence behind them, and improve their security through **safe, bounded, and non-destructive** investigation.

The project is developed and maintained by one researcher. Contributions that improve accuracy, stability, security, compatibility, testing, performance, privacy, or documentation are welcome.

> **You do not need to write code to make a useful contribution.**

---

## Contents

- [Quick start for contributors](#quick-start-for-contributors)
- [Ways to contribute](#ways-to-contribute)
- [Before contributing](#before-contributing)
- [Reporting bugs](#reporting-bugs)
- [Proposing improvements](#proposing-improvements)
- [Code requirements](#code-requirements)
- [Evidence rules](#evidence-rules)
- [Testing requirements](#testing-requirements)
- [Windows runtime validation](#windows-runtime-validation)
- [Privacy requirements](#privacy-requirements)
- [Pull requests](#pull-requests)
- [Security vulnerabilities](#security-vulnerabilities)
- [Review expectations](#review-expectations)

---

## Quick start for contributors

```bash
# 1. Verify everything passes before you change anything
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
```

Then:

1. Keep your change focused on **one** objective.
2. Add a test that proves the behavior.
3. Sanitize any evidence you include.
4. Open a Pull Request using the template below.

---

## Ways to contribute

| Area | Examples |
|---|---|
| **Testing** | Try different Windows versions and configurations; measure collector performance |
| **Accuracy** | Report false positives and false negatives; flag unclear or misleading output |
| **Evidence** | Improve evidence classification; suggest relevant evidence sources |
| **Quality** | Add or improve tests; improve Windows compatibility |
| **Safety** | Review privacy boundaries; report vulnerabilities responsibly |
| **Docs** | Improve documentation |
| **Code** | Focused Rust, PowerShell, or shell changes |

---

## Before contributing

Before opening an Issue or Pull Request:

1. Read [README.md](README.md), [Architecture.md](Architecture.md), and [SECURITY.md](SECURITY.md).
2. Search existing Issues and Pull Requests for related work.
3. Test the latest supported release or current default branch.
4. Record the exact AXIOS command used.
5. Record whether PowerShell ran as a standard user or Administrator.
6. Separate observed facts from assumptions.
7. Remove credentials, personal information, and unrelated machine data.
8. Keep each report focused on one problem or improvement.

> Do not combine unrelated problems into one report.

---

## Reporting bugs

| Item | Description |
|---|---|
| **Summary** | A short explanation of the problem |
| **Version** | AXIOS release or commit tested |
| **Environment** | Windows version, architecture, and PowerShell version |
| **Execution context** | Standard user or Administrator |
| **Command** | The exact command used |
| **Expected behavior** | What should have happened |
| **Actual behavior** | What happened instead |
| **Reproduction steps** | Minimal ordered steps |
| **Evidence** | Sanitized output, logs, or screenshots |
| **Frequency** | Always, intermittent, or observed once |

Template:

```text
Title:

AXIOS release or commit:
Windows version:
System architecture:
PowerShell version:
Execution context:
Command:

Expected behavior:

Actual behavior:

Reproduction steps:
1.
2.
3.

Sanitized evidence:

Additional notes:
```

> A command returning exit code zero is **not** proof that the intended behavior worked. Verify the final state.

---

## Proposing improvements

Explain the **investigation problem** before proposing implementation details. Please answer:

1. What security question should AXIOS answer?
2. Which evidence source can answer it?
3. Does collection require a standard user or Administrator token?
4. Which Windows versions provide the evidence?
5. How should unavailable or restricted evidence be represented?
6. What runtime, memory, or evidence limits are required?
7. What may cause false positives or false negatives?
8. How will the behavior be tested?
9. How will the result help the investigator?

> A new feature should improve evidence quality or investigation capability, not simply produce more output.

---

## Code requirements

Changes must be:

- Focused on one technical objective
- Small enough to review safely
- Consistent with the AXIOS architecture
- Covered by relevant tests
- Non-destructive by default
- Honest about failure and partial visibility
- Compatible with the stable public command interface
- Free from unrelated formatting or renaming
- Free from personal or machine-specific data

Do not commit generated binaries, build directories, investigation archives, credentials, machine logs, or private evidence.

### Rust

Rust changes must:

- Use explicit error propagation
- Avoid unnecessary `unsafe`
- Keep Windows handles and resources correctly scoped
- Preserve bounded runtime and memory behavior
- Use structured evidence models
- Preserve evidence provenance
- Avoid converting errors into clean default values
- Pass formatting, tests, and linting

```bash
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
```

If `unsafe` is required, keep it minimal and explain why it is necessary.

### PowerShell

PowerShell changes must:

- Parse successfully
- Preserve the public command interface
- Validate mode-specific parameters
- Use explicit error handling
- Check native executable exit codes
- Restore working-directory and console state
- Avoid language-dependent parsing where possible
- Preserve structured objects until rendering
- Hide internal paths and machine receipts from normal console output
- Represent denied or unavailable collection truthfully

### Shell

Build and packaging changes must:

- Stop when a required command fails
- Avoid creating incomplete releases
- Exclude sensitive files and build artifacts
- Validate archive contents
- Preserve package structure
- Generate or verify integrity metadata
- Avoid destructive commands against broad or unresolved paths

---

## Evidence rules

Every contribution must preserve these rules.

| Rule | Meaning |
|---|---|
| **Evidence before conclusions** | A conclusion must be supported by collected evidence |
| **Missing evidence is not clean evidence** | Failed, denied, unavailable, or truncated collection must remain visible |
| **Context is not compromise** | An unusual process, unsigned file, open port, persistence entry, or configuration weakness is not automatically malicious |
| **Duplicates are not independent evidence** | Repeated copies of the same observation must not increase confidence |
| **Contradictions remain visible** | AXIOS must not hide disagreement between reliable sources |
| **Findings preserve provenance** | Every finding keeps its collector, evidence source, and verification state |
| **Confidence cannot exceed evidence** | Strength must reflect the quality, independence, and completeness of the supporting evidence |

---

## Testing requirements

Every behavioral change should include a test that proves the intended result and prevents regression.

Depending on the change, tests may include:

- Rust unit tests
- Integration contracts
- Command-interface contracts
- Parameter-routing tests
- Privilege-boundary tests
- Evidence-precision tests
- Failure-state tests
- Partial-visibility tests
- Privacy and source-hygiene tests
- PowerShell parser validation
- Windows compatibility tests
- Package-integrity tests
- Working-directory independence tests
- Windows runtime validation

> Tests must verify **final behavior**, not only successful process execution.

A collector test should check:

- Report success state
- Collection status
- Findings and observations
- Errors and visibility limitations
- Evidence references
- Behavior when access is denied
- Behavior when evidence is unavailable
- Behavior when collection limits are reached

---

## Windows runtime validation

Changes affecting Windows-native behavior, packaging, privileges, orchestration, or console output should be tested on Windows whenever possible.

Runtime evidence should include:

- Windows version and build
- AXIOS release or commit
- Standard-user or Administrator context
- Exact command
- Completion status
- Failed and partial collectors
- Sanitized relevant output
- Verification of the expected final state

> Do not describe a runtime test as passing when the intended result was not verified.

---

## Privacy requirements

**Never submit:**

- Passwords
- Wi-Fi credentials
- Tokens
- API keys
- Encryption keys
- Personal usernames
- Real machine names
- Private investigation evidence
- Browser-profile data
- Customer or employer information
- Unrelated personal file paths
- Unredacted investigation reports

Use synthetic values in examples and test fixtures:

```text
C:\Users\TestUser
C:\AXIOS\axios-windows-investigation
192.0.2.10
example.invalid
```

Screenshots must be sanitized before publication.

---

## Pull requests

```text
## Problem

## Why this belongs in AXIOS

## Implementation

## Evidence and behavior

## Tests performed

## Windows runtime validation

## Security and privacy considerations

## Compatibility considerations

## Known limitations
```

Keep Pull Requests focused. Submit unrelated changes separately.

**A contribution may be declined if it:**

- Weakens security or privacy boundaries
- Hides failures or incomplete visibility
- Adds unsupported security claims
- Breaks the stable public interface
- Expands scope without clear evidence value
- Cannot be tested or maintained reliably

---

## Security vulnerabilities

Do **not** report unresolved vulnerabilities through public Issues, Discussions, or Pull Requests.

Follow [SECURITY.md](SECURITY.md) and send the report directly to **adamouttassi3@gmail.com**.

---

## Review expectations

AXIOS is developed and maintained independently by one researcher, so reviews may not always be immediate.

Contributions are evaluated for:

| | | |
|---|---|---|
| Technical correctness | Security impact | Evidence quality |
| Architectural consistency | Test coverage | Windows compatibility |
| Privacy | Performance | Maintainability |
| Clarity for investigators | | |

Please be respectful, precise, and patient. Technical disagreement is welcome when it stays focused on evidence and engineering.

Thank you for helping make AXIOS safer, more stable, more precise, and more useful for everyone.

---
