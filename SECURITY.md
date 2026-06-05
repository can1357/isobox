# Security Policy

isobox confines untrusted commands, so a confinement bypass is a security issue.
Examples worth reporting:

- A spec that should deny network, writes, or reads, but the command reaches
  them anyway on a supported backend.
- Host filesystem, IPC, or credential exposure that the compiled plan claims to
  prevent.
- A capability reported as enforced (`isobox --caps`) that is not actually
  enforced, without a corresponding caveat in the plan.
- Escape from a backend (gVisor, Seatbelt, AppContainer) attributable to how
  isobox builds or launches it.

Enforcement gaps that isobox already reports as **caveats** in `--print` output
are documented limitations, not vulnerabilities. Check the plan first.

## Reporting

Report privately through GitHub's
[private vulnerability reporting](https://github.com/can1357/isobox/security/advisories/new).
Please do not open a public issue for a suspected bypass.

Include the isobox version (`isobox --version`), host OS and backend, the spec or
flags used, and a minimal reproduction. A failing `cmd/isobox-testkit-*` probe
or a small command that demonstrates the gap is ideal.

We aim to acknowledge a report within a few days and will coordinate a fix and
disclosure timeline with you.

## Supported versions

isobox is pre-1.0. Fixes land on `main` and in the next tagged release; there is
no backporting to older tags yet.
