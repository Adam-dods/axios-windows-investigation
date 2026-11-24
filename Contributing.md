# Contributing to AXIOS

AXIOS is an independently maintained Windows investigation project. Contributions to **accuracy, security, privacy, compatibility, performance, testing, and documentation** are welcome. You can help without writing code: report reproducible behavior, or test a different Windows environment.

Read [README.md](README.md), [Architecture.md](Architecture.md), and [SECURITY.md](SECURITY.md) first.

**Jump to:** [Start here](#start-here) · [Bug reports](#reporting-a-bug) · [Improvements](#proposing-an-improvement) · [Code](#code-requirements) · [Evidence rules](#evidence-rules) · [Testing](#testing) · [Privacy](#privacy) · [Pull requests](#pull-requests)

---

## Start here

1. Search existing Issues and Pull Requests.
2. Pick **one** focused problem or improvement.
3. Note the release tag or commit you tested.
4. Keep observations separate from assumptions.
5. Remove credentials and private machine data from anything you share.

Before and after a code change, run:

```bash
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
```

> A green Rust check does **not** replace Windows runtime validation for Windows-specific changes.

---

## Reporting a bug

Open a public Issue for an ordinary bug **after sanitizing evidence**. Copy this template:

```text
Title:
Release tag or commit:
Windows version/build and architecture:
PowerShell version:
Standard user or Administrator:
Exact command:
Steps to reproduce:
Expected behavior:
Actual behavior:
Collection status and errors:
Sanitized evidence:
Frequency:
```

An exit code of zero doesn't prove the intended behavior worked. Check the actual result and final state.

> **Vulnerability, privacy exposure, or unsafe security conclusion?** Don't open a public Issue. Follow [SECURITY.md](SECURITY.md) and report **privately**.

---

## Proposing an improvement

Start with the **investigation question**, then cover:

- the evidence source and required privilege
- relevant Windows versions
- expected limits, and possible false positives or negatives
- how the result helps an investigator
- how unavailable evidence should appear
- how the behavior can be verified

A feature should improve evidence quality or investigation capability, not merely increase output.

---

## Code requirements

Keep changes focused, reviewable, non-destructive, and compatible with the public interface. Preserve explicit errors, bounded work, evidence provenance, and truthful `partial`, `failed`, and unavailable states. Avoid unrelated formatting or renaming.

| Language | Requirements |
|---|---|
| **Rust** | Structured evidence and explicit error paths. Scope Windows resources. Avoid unnecessary `unsafe`, and explain any that is required. Never turn a collector error into a clean default. |
| **PowerShell** | Must parse. Validate options by mode. Check native exit codes. Restore working-directory and console state. Keep structured data until rendering. Avoid language-dependent parsing. Keep internal paths and machine receipts out of routine terminal output. |
| **Shell / packaging** | Stop on failed commands. Verify archive contents, package structure, and integrity metadata. Exclude private and generated data. No destructive operations on broad or unresolved paths. |

**Never commit:** generated executables, build directories, credentials, investigation archives, machine logs, or private evidence.

---

## Evidence rules

| Rule | Required behavior |
|---|---|
| Evidence before conclusions | Every conclusion points to collected evidence |
| Missing is not clean | Failed, denied, unavailable, or truncated collection stays visible |
| Context is not compromise | An unusual process, open port, or configuration alone proves no threat |
| Duplicates are not corroboration | Repeated records don't add independent support |
| Preserve contradictions | Reliable sources may disagree; show the disagreement |
| Keep provenance | Findings retain collector, source, and verification state |
| Bound confidence | A conclusion can't be stronger than its evidence |

---

## Testing

Write tests that prove the changed behavior and prevent a meaningful regression. Depending on the change, cover: Rust logic, parameter routing, privilege boundaries, evidence precision, failure and partial states, privacy, PowerShell parsing, package integrity, working-directory behavior, and Windows compatibility.

**For a collector,** verify its status, observations and findings, errors, visibility limits, and evidence references. Exercise denied access, unavailable capabilities, and reached limits. A matching implementation snapshot is not proof of correct behavior.

### Windows runtime evidence

For changes to native collection, packaging, privileges, orchestration, or terminal output, test on Windows when possible and record:

- [ ] Windows version and build; release tag or commit
- [ ] Exact command, and standard-user or Administrator context
- [ ] Completion state and any failed or partial collectors
- [ ] Sanitized relevant output and the expected final state
- [ ] What was **not** tested

If you didn't validate on Windows, say so. A successful process exit alone is not a passing runtime test.

---

## Privacy

Never post passwords, Wi-Fi credentials, tokens, keys, real usernames or hostnames, browser-profile data, private reports, customer information, or unrelated personal paths. Review screenshots and archives before sharing.

Use synthetic examples:

```text
C:\Users\TestUser
C:\AXIOS\axios-windows-investigation
192.0.2.10
example.invalid
```

---

## Pull requests

One objective per PR. Use this structure:

```text
## Problem and investigation value
## Implementation
## Evidence and expected behavior
## Tests run and results
## Windows runtime validation or its absence
## Privacy and compatibility impact
## Known limitations
```

A PR may be declined if it hides incomplete coverage, weakens privacy, overstates a security claim, breaks the stable interface, or can't be maintained reliably. Reviews may take time because AXIOS is maintained independently.
