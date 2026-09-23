---
description: Why BomLens runs locally by design — what stays on your machine, how it works offline, and where governance is handled instead.
---

# Local-first by design

## Nothing leaves your machine

BomLens runs locally, with no SaaS backend. What you analyze — source code, firmware, or an SBOM someone handed you — is never sent to an external service by default. The scan happens inside a local Docker container and ends there. The outputs are written only to the directory you ran it from. The one option that sends anything about your files is `--identify-vendored`: it sends file fingerprints (hashes), never the files themselves, to the SCANOSS OSSKB service. It is off unless you turn it on, and [Identify bundled open source (C/C++)](../guides/identify-vendored.md) explains what is sent and how to point it at your own endpoint.

## Works in closed and offline networks

BomLens runs on air-gapped and offline networks. The few features that need an external lookup can be turned off, and everything else is still produced. The security report's EPSS and CISA KEV enrichment is the main case: set `SECURITY_ENRICH=false` to skip it and still generate the rest of the report. License lookups can likewise be skipped with `FETCH_LICENSE=false`. The web UI's CVE/package lookup screen is different in kind from these: it runs nothing during a scan, only when someone visits it and types an id or a package name, sending that identifier (and the package name, for a package lookup — worth knowing before typing an internal-only name) to osv.dev on demand. Set `EXTERNAL_LOOKUP=false` to remove the screen and every link to it, and the server refuses the request even if one is made directly. The security report needs one more thing offline. The image does not include the Trivy vulnerability database, so with no network the Trivy step cannot download it and the report comes out with no findings and a `ScanError` entry that records the failure, not a clean result. Everything else in the scan is still produced. Going the other way, three checks that sound like they need the network do not: end-of-life flagging, the malicious-package check and the outbound-license conflict check all read data baked into the image at build time, so they keep working with no connection at all.

## Standard, portable outputs

The outputs use standard formats — the SBOM is CycloneDX 1.6. They are not tied to any single vendor, so you can verify and reuse them anywhere. When you need a byte-for-byte identical SBOM for the same input, use `--byte-stable`.

## One scanner behind every entry point

The three entry points — the CLI, the web UI, and the desktop app — all use the same local scanner container. Only the way you drive the tool differs; the behavior and the outputs are the same.

## BomLens generates; TRUSCA governs

BomLens focuses on generation. Governance — organization-wide project management, vulnerability triage, license policy gates — is delegated to the sister project TRUSCA (formerly TrustedOSS Portal, <https://github.com/trustedoss/trusca>). The two tools exchange CycloneDX outputs directly.

## Related

For how the two-stage pipeline works, see [How BomLens works](architecture.md). For the kinds of outputs, see the [artifacts reference](../reference/artifacts.md).
