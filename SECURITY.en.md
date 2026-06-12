# Security Policy

> **한국어**: [SECURITY.md](SECURITY.md)

BomLens is a software supply-chain security tool, so the security of the tool itself matters too. If you find a vulnerability, please report it responsibly.

## Supported versions

Security fixes are provided for the latest release. The `ghcr.io/sktelecom/bomlens:latest` Docker image tag (legacy alias: `sbom-scanner:latest`) reflects the latest security patches.

| Version | Supported |
|---------|-----------|
| Latest release (`:latest`) | ✅ |
| Older versions | ❌ |

If you are on an older version, please upgrade to the latest release first and check whether the issue still reproduces.

## Reporting a vulnerability

Please do **not** open a public issue. Report privately through one of the two channels below.

### 1. GitHub Private Vulnerability Reporting

In this repository's **Security** tab, click **Report a vulnerability** to submit a private advisory draft. It is visible only to maintainers, and the fix and disclosure schedule can be coordinated in the same place.

### 2. Email

You may also email [opensource@sktelecom.com](mailto:opensource@sktelecom.com).

### What to include

- The type of vulnerability and its impact
- The affected file path or code location
- Reproduction steps or a proof of concept (PoC)
- If possible, the affected version and environment (OS, Docker version)

## Process

When we receive a report, we respond along the following lines. This is a volunteer-based project, so the timelines below are targets and may vary.

- Acknowledge receipt within 3 business days.
- Review, determine whether it is a vulnerability and its severity, and inform the reporter.
- If a fix is needed, prepare a patch and coordinate the disclosure timing with the reporter.
- Once the fix is released, publish the security advisory and, if desired, credit the reporter.

Private reports are not shared externally until the fix and coordination are complete.
