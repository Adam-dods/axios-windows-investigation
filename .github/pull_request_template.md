<!--
Thank you for improving AXIOS.
Keep each pull request focused on ONE change.
Do not include passwords, credentials, encryption keys, personal paths,
host names, or unrelated machine data.

Unresolved security vulnerabilities must NOT be reported in a pull request.
Follow SECURITY.md and email the report privately.
-->

## Summary

What does this pull request change, and why?

## Related issue

Closes #

## Change type

- [ ] Bug fix
- [ ] New investigation capability
- [ ] Evidence or classification improvement
- [ ] Performance improvement
- [ ] Documentation
- [ ] Test coverage
- [ ] Other

## Evidence and safety

- **What evidence does this change collect, validate, or render?**

- **How does it distinguish observed evidence, unavailable evidence, and an unsupported conclusion?**

- **Does the change alter a privilege boundary, collection limit, or output classification?**

## Scope

- **Relevant AXIOS mode or component:**
- **Windows version or environment tested:**
- **Execution context tested:** Standard user / Administrator

## Validation performed

List the commands you ran and their outcomes.

```bash
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
```

If the change affects PowerShell:

```bash
cargo test --test powershell_runtime_parser_contract
```

If the change affects the Windows package, describe the runtime validation performed after extracting the release ZIP.

## Output or evidence example

Add a redacted console sample, test result, or screenshot when it makes review easier.

## Known limitations

Describe anything not validated, any bounded coverage, or any remaining uncertainty.

## Checklist

- [ ] This pull request is focused on one change.
- [ ] I added or updated relevant tests.
- [ ] Formatting, tests, and lint checks pass locally.
- [ ] I did not add credentials, secrets, personal paths, host names, or unrelated machine data.
- [ ] I did not add compiled binaries, build output, or generated investigation evidence.
- [ ] The documentation is updated if the public behavior or command interface changed.
- [ ] The change does not treat inaccessible evidence as clean evidence.
