---
description: Check that a BomLens release file or container image is the one the project built, with cosign, and read the SBOM that ships with the image.
---

# Verify a release

A tool that reports on supply chains should have a supply chain you can check. Every release is built by the project's own GitHub Actions workflows and signed with keyless [cosign](https://docs.sigstore.dev/cosign/overview/) (Sigstore), so you can confirm that what you downloaded was built from this repository, without trusting a key that someone could hand you.

The commands below were run against v1.13.6. Replace the version with the one you downloaded. They need `cosign` v2 and, for the checksum step, `sha256sum` (`shasum -a 256` on macOS).

## Release files (installers, CLI, source bundles)

One signature covers the checksum file, and the checksum file covers every asset, so you verify one file and then the checksums.

```bash
VERSION=v1.13.6
gh release download "$VERSION" --repo sktelecom/bomlens \
  --pattern 'SHA256SUMS.txt*' --pattern 'BomLens-Setup.exe'

cosign verify-blob SHA256SUMS.txt \
  --signature SHA256SUMS.txt.sig \
  --certificate SHA256SUMS.txt.pem \
  --certificate-identity-regexp '^https://github.com/sktelecom/bomlens/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Verified OK

sha256sum -c SHA256SUMS.txt --ignore-missing
# BomLens-Setup.exe: OK
```

`Verified OK` means the checksum file was signed by a workflow of the `sktelecom/bomlens` repository. The `OK` line then says your file matches the checksum in it. The desktop installers are not code-signed yet (the first run shows a SmartScreen or Gatekeeper warning, see [first scan](../start/first-scan.md)); this check is how you confirm one is the project's build.

## Container image

The images are signed by digest, and each one carries its own SBOM as a signed attestation.

```bash
cosign verify ghcr.io/sktelecom/bomlens:1.13.6 \
  --certificate-identity-regexp '^https://github.com/sktelecom/bomlens/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

To read the image's SBOM (CycloneDX) from the attestation:

```bash
cosign verify-attestation --type cyclonedx ghcr.io/sktelecom/bomlens:1.13.6 \
  --certificate-identity-regexp '^https://github.com/sktelecom/bomlens/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | head -1 | jq -r '.payload | @base64d | fromjson | .predicate' > bomlens-image.cdx.json
```

You can then run BomLens on its own image's SBOM: `scan-sbom.sh --analyze bomlens-image.cdx.json --project bomlens-image --version 1.13.6`.

## The project's own SBOM

Each release also attaches `bomlens-source-<version>.cdx.json`, the SBOM of every manifest the repository ships (the desktop app's and the web UI's dependencies). It is covered by the same checksum file.

## What this does not tell you

A valid signature says who built the file, not that the code is free of defects. The scanner image is scanned by Trivy every night and the findings are public in the repository's Security tab, and the [limitations](../concepts/limitations.md) page lists what the tool does not do.
