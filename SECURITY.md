# Security policy

## Supported versions

Only the latest release gets security fixes. Fixes ship as a new patch release; published releases are immutable and are never replaced.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: [open a private report](https://github.com/jfagoagas/ctq/security/advisories/new). Please don't open a public issue or pull request for a security problem.

Include what you can of:

- the affected version (`ctq version`) and platform
- steps to reproduce, or a proof of concept
- the impact you expect

You'll get an acknowledgement within 7 days. This is a one-person project, so a fix can take longer; you'll get updates in the report as it moves. Once a fix is released, the advisory is published with credit to you, unless you'd rather stay anonymous.

## Scope

In scope:

- the `ctq` code in this repository
- the release pipeline: workflows, build provenance, SBOMs and their attestations

Out of scope, please report these to their owners:

- [crt.sh](https://crt.sh), [Cert Spotter](https://sslmate.com/certspotter/) and the CT logs themselves
- vulnerabilities in dependencies that don't affect ctq (the weekly grype scan already tracks known ones)

## Verifying releases

Every release archive has a signed SLSA build provenance attestation and an SBOM attestation. See [Verify a release](README.md#verify-a-release) for the commands.
