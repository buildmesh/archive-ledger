# Security policy

## Supported versions

Archive Ledger is currently pre-release software. Security fixes are made on the `main` branch;
older commits and unpublished builds are not separately supported.

## Report a vulnerability

Do not disclose suspected vulnerabilities in a public issue. Use GitHub's private vulnerability
reporting from the repository's **Security** tab, under **Advisories**, and select
**Report a vulnerability**.

Include enough information to reproduce and assess the problem safely:

- the affected commit or version;
- operating system and relevant storage setup;
- expected and observed behavior;
- a minimal reproduction using disposable data; and
- the potential effect on confidentiality, integrity, availability, or user data.

Do not include real archive contents, catalog data, credentials, private keys, or personal paths.
We will coordinate remediation and disclosure through the private advisory.

Particularly relevant reports include unintended content mutation or deletion, path or symlink
escapes, unsafe identity or signature acceptance, integrity checks that fail open, and disclosure
of archive metadata or local credentials.
