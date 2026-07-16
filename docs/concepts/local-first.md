---
description: Why BomLens runs locally by design — what stays on your machine, how it works offline, and where governance is handled instead.
---

# Local-first by design

## Nothing leaves your machine

BomLens runs locally, with no SaaS backend. What you analyze — source code, firmware, or an SBOM someone handed you — is never sent to an external service. The scan happens inside a local Docker container and ends there. The outputs are written only to the directory you ran it from.

## Works in closed and offline networks

BomLens runs on air-gapped and offline networks. The few features that need an external lookup can be turned off, and everything else is still produced. The security report's EPSS and CISA KEV enrichment is the main case: set `SECURITY_ENRICH=false` to skip it and still generate the rest of the report. License lookups can likewise be skipped with `FETCH_LICENSE=false`.

## Standard, portable outputs

The outputs use standard formats — the SBOM is CycloneDX 1.6. They are not tied to any single vendor, so you can verify and reuse them anywhere. When you need a byte-for-byte identical SBOM for the same input, use `--byte-stable`.

## One scanner behind every entry point

The three entry points — the CLI, the web UI, and the desktop app — all use the same local scanner container. Only the way you drive the tool differs; the behavior and the outputs are the same.

## BomLens generates; TRUSCA governs

BomLens focuses on generation. Governance — organization-wide project management, vulnerability triage, license policy gates — is delegated to the sister project TRUSCA (formerly TrustedOSS Portal, <https://github.com/trustedoss/trusca>). The two tools exchange CycloneDX outputs directly.

## Related

For how the two-stage pipeline works, see [How BomLens works](architecture.md). For the kinds of outputs, see the [artifacts reference](../reference/artifacts.md).
