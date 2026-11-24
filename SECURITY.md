# Security Policy

AXIOS investigates and reports evidence. It does **not** remove threats or change security settings, and a completed investigation does **not** prove a Windows system is clean. Collection limits and unavailable evidence are meant to stay visible in its results.

## Quick guide

| Your situation | Where to go |
|---|---|
| Vulnerability, credential or privacy exposure, unsafe behavior | **Report privately** (see below) |
| A security conclusion the evidence doesn't support | **Report privately** |
| Compatibility problem, feature request, documentation fix | Public [GitHub Issue](https://github.com/Adam-dods/axios-windows-investigation/issues), after removing private machine data |

> **Never** post an unresolved vulnerability or proof of concept in a public Issue, Discussion, or Pull Request.

## Supported releases

| Release | Status |
|---|---|
| [v2026.11.23](https://github.com/Adam-dods/axios-windows-investigation/releases/tag/v2026.11.23) | ✅ Current stable release |
| [v2026.9.27](https://github.com/Adam-dods/axios-windows-investigation/releases/tag/v2026.9.27) | ⚠️ Previous release; security fixes not guaranteed |

Always report the **GitHub release tag or exact commit** you tested. The Rust package metadata may read `2026.9.27` inside the `v2026.11.23` distribution, so that value alone does not identify what you downloaded.

## Report privately

Email [adamouttassi3@gmail.com](mailto:adamouttassi3@gmail.com) with this subject:

```text
AXIOS Security Report: [brief title]
```

Please give the maintainer time to investigate before publishing details.

## What to include

- [ ] Release tag or commit
- [ ] Windows version, and whether you ran as a standard user or Administrator
- [ ] The exact AXIOS command and minimal steps to reproduce
- [ ] Expected behavior, observed behavior, and security impact
- [ ] Relevant collection status, errors, and **sanitized** evidence

A successful exit code alone doesn't show the expected behavior happened. Include the actual output you saw.

## Protect investigation data

Before sending logs, screenshots, reports, or archives, remove:

- passwords, Wi-Fi credentials, tokens, and keys
- personal identifiers and hostnames
- unrelated machine data

Do **not** attach an encrypted credential archive or its password unless a secure exchange has been agreed separately. Not sure whether something is safe to share? Send a short description first.

## Response expectations

AXIOS is maintained independently, so **no fixed response or resolution deadline is promised.** Reports are handled in good faith, and a clear, reproducible report with sanitized evidence will always be easier to act on.

## Scope

AXIOS is intended only for authorized investigation of systems you own or are permitted to assess. Reports about using it on systems without authorization are out of scope.
