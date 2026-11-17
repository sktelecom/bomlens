---
description: Why BomLens runs locally by design — what stays on your machine, how it works offline, and where governance is handled instead.
---

# Local-first by design

## Nothing leaves your machine

BomLens runs locally, with no SaaS backend. It does not send your source code, firmware, SBOMs or scan results to any server of this project, and it has no telemetry. The scan happens inside a local Docker container, and the outputs are written only to the directory you ran it from. BomLens does make some requests to public services by default: downloading the scanner image from ghcr.io, downloading the Trivy vulnerability database for the security report, looking up the CVE ids it found at FIRST.org (EPSS) and CISA (KEV), and, in the desktop app, checking the GitHub releases API for a newer version. These carry no source code or SBOM. The web UI's CVE and package lookup, which asks osv.dev, runs only when someone uses it. The options that send identifiers about your components are off unless you turn them on. `--identify-vendored` sends file fingerprints (hashes), never the files themselves, to the SCANOSS OSSKB service, and `--license-registry` and `--resolve-purl` send package identifiers to deps.dev. [Identify bundled open source (C/C++)](../guides/identify-vendored.md) explains what the first one sends and how to point it at your own endpoint, and the [code signing policy](../reference/code-signing-policy.md) lists every request.

## Works in closed and offline networks

BomLens runs on air-gapped and offline networks. The few features that need an external lookup can be turned off, and everything else is still produced. The security report's EPSS and CISA KEV enrichment is the main case: set `SECURITY_ENRICH=false` to skip it and still generate the rest of the report. License lookups can likewise be skipped with `FETCH_LICENSE=false`. A source scan pulls the cdxgen images from ghcr.io; on a network that reaches only a registry mirror, point `CDXGEN_IMAGE_PREFIX` at it. The web UI's CVE/package lookup screen is different in kind from these: it runs nothing during a scan, only when someone visits it and types an id or a package name, sending that identifier (and the package name, for a package lookup — worth knowing before typing an internal-only name) to osv.dev on demand. Set `EXTERNAL_LOOKUP=false` to remove the screen and every link to it, and the server refuses the request even if one is made directly. The security report needs one more thing offline. The image does not include the Trivy vulnerability database, so with no network the Trivy step cannot download it and the report comes out with no findings and a `ScanError` entry that records the failure, not a clean result. Everything else in the scan is still produced. Going the other way, three checks that sound like they need the network do not: end-of-life flagging, the malicious-package check and the outbound-license conflict check all read data baked into the image at build time, so they keep working with no connection at all.

## Standard, portable outputs

The outputs use standard formats: the SBOM is CycloneDX 1.6 by default, or 1.7 with `--spec-version 1.7`. They are not tied to any single vendor, so you can verify and reuse them anywhere. When you need a byte-for-byte identical SBOM for the same input, use `--byte-stable`.

## One scanner behind every entry point

The three entry points — the CLI, the web UI, and the desktop app — all use the same local scanner container. Only the way you drive the tool differs; the behavior and the outputs are the same.

## BomLens generates; TRUSCA governs

BomLens focuses on generation. Governance — organization-wide project management, vulnerability triage, license policy gates — is delegated to the sister project TRUSCA (formerly TrustedOSS Portal, <https://github.com/trustedoss/trusca>). The two tools exchange CycloneDX outputs directly.

## Related

For how the two-stage pipeline works, see [How BomLens works](architecture.md). For the kinds of outputs, see the [artifacts reference](../reference/artifacts.md).
