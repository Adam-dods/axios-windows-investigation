# Security Policy

> No security software is perfect, and AXIOS is not presented as an exception.

---

## Contents

- [Security philosophy](#security-philosophy)
- [Reporting a security vulnerability](#reporting-a-security-vulnerability)
- [What to include in a report](#what-to-include-in-a-report)
- [Protect sensitive data](#protect-sensitive-data)
- [Response expectations](#response-expectations)
- [Responsible disclosure](#responsible-disclosure)
- [Supported version](#supported-version)

---

## Security philosophy

AXIOS was created from a practical idea: investigation work that may take hours of manual collection, verification, and correlation should be completed in minutes, **without sacrificing evidence quality, system safety, or honesty about visibility.**

AXIOS is developed independently by one researcher. Time, hardware, testing environments, and development resources are limited. Even with extensive automated testing and real Windows runtime validation, the following may still exist:

- Defects
- Compatibility problems
- Incomplete coverage
- Unexpected behavior

Open-source participation is not simply help for one developer. Every responsible report and contribution makes AXIOS safer, more stable, and more useful for everyone.

The goal is not to claim that AXIOS is perfect. The goal is to keep improving it through **careful engineering, honest testing, and collaboration** with its users and the security community.

---

## Reporting a security vulnerability

If you discover any of the following, please contact me directly:

- A vulnerability
- Unsafe behavior
- An incorrect security conclusion
- A privacy issue
- A compatibility problem
- Anything else that could improve AXIOS

**Contact:** [adamouttassi3@gmail.com](mailto:adamouttassi3@gmail.com)

You may also use this address for technical questions, test results, improvement suggestions, or anything you'd like to discuss about AXIOS.

**For security reports, use this subject line:**

```text
AXIOS Security Report: [brief vulnerability title]
```

---

## What to include in a report

When possible, please include:

| Item | Description |
|---|---|
| **Description** | A clear explanation of the issue |
| **Affected component** | The AXIOS component or command involved |
| **Version** | The tested release or commit |
| **Environment** | Windows version and execution context (standard user or Administrator) |
| **Reproduction steps** | Exactly how to trigger it |
| **Expected vs. actual behavior** | What should happen, and what happened instead |
| **Security impact** | What an attacker or user could gain or lose |
| **Supporting material** | Relevant logs, screenshots, or proof-of-concept |

A useful template:

```text
Subject: AXIOS Security Report: <brief title>

Description:
Affected component / command:
Release or commit tested:
Windows version and context:
Reproduction steps:
  1.
  2.
  3.
Expected behavior:
Actual behavior:
Security impact:
Attachments (logs / screenshots / PoC):
```

---

## Protect sensitive data

Before sending evidence, **remove**:

- Passwords
- Credentials
- Encryption keys
- Personal information
- Unrelated machine data

---

## Response expectations

I'm always happy to receive your emails and will answer as soon as my available time allows.

Because AXIOS is independently developed and maintained by one person, **replies may not always be immediate**. Every serious report, question, and constructive contribution will be read and appreciated.

---

## Responsible disclosure

Please **do not** publicly disclose an unresolved vulnerability through:

- GitHub Issues
- GitHub Discussions
- Pull Requests

before there has been reasonable time to investigate it.

---

## Supported version

| Version | Status |
|---|---|
| `2026.9.27` (October 2026, Stable) | Supported |
