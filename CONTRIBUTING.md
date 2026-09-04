# Contributing to Archive Ledger

Thank you for helping improve Archive Ledger. The CLI handles information about users' archives,
so changes should favor data safety, explicit behavior, and verifiable recovery.

## Propose a change

Search the GitHub issues before starting. Open an issue first for substantial changes to user
workflows, canonical events, persistence, archive identity, integrity evaluation, or storage
safety. Small fixes and documentation improvements can go directly to a pull request.

## Development setup

Archive Ledger requires Git, the stable Rust toolchain, `findmnt` from util-linux, and a
POSIX-compatible `install` command. The repository's `rust-toolchain.toml` selects Rust and the
formatting and linting components.

Run the same checks used by continuous integration:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
make test
```

The 100,000-file scale gate is intentionally excluded from routine testing. Run
`make test-scale` only for changes to traversal, batching, projection scale, or memory behavior.

## Safety expectations

- Exercise scanning, copying, repair, deletion, rebuild, and migration behavior only against
  disposable fixtures unless a test has an explicit recovery plan.
- Preserve archive contents and catalog history by default.
- Add behavioral coverage for new logic and regression coverage for bug fixes when practical.
- Keep changes focused and update user documentation when commands or behavior change.
- Do not include credentials, private archive metadata, personal paths, or other sensitive data in
  commits, fixtures, issues, or logs.

## Pull requests

Explain the user-visible outcome, important design choices, and how the change was verified. Note
any checks that could not be run. Prefer focused semantic commits and avoid unrelated formatting or
refactoring.

By submitting a contribution, you agree that it may be distributed under the repository's
[GNU General Public License, version 3 only](LICENSE).
