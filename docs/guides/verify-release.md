---
description: Check that a BomLens release file or container image is the one the project built, with cosign, and read the SBOM that ships with the image.
---

# Verify a release

A tool that reports on supply chains should have a supply chain you can check. Every release is built by the project's own GitHub Actions workflows and signed with keyless [cosign](https://docs.sigstore.dev/cosign/overview/) (Sigstore), so you can confirm that what you downloaded was built from this repository, without trusting a key that someone could hand you.

The commands below were run against v1.13.7. Replace the version with the one you downloaded. They need `cosign` v2 and, for the checksum step, `sha256sum` (`shasum -a 256` on macOS).

## Release files (installers, CLI, source bundles)

One signature covers the checksum file, and the checksum file covers every asset, so you verify one file and then the checksums.

```bash
VERSION=v1.13.7
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

### On Windows

You need no `gh`, `sha256sum` or `jq` for this check. Download `cosign-windows-amd64` from the [cosign releases page](https://github.com/sigstore/cosign/releases/latest) into the folder you work in, rename it to `cosign.exe`, then run this in PowerShell. It downloads the installer and its checksum files, verifies the signature on the checksum file, and compares the installer's hash with the one listed.

```powershell
$v = "v1.13.7"
$base = "https://github.com/sktelecom/bomlens/releases/download/$v"
foreach ($f in "SHA256SUMS.txt","SHA256SUMS.txt.sig","SHA256SUMS.txt.pem","BomLens-Setup.exe") {
  Invoke-WebRequest "$base/$f" -OutFile $f
}

.\cosign.exe verify-blob SHA256SUMS.txt `
  --signature SHA256SUMS.txt.sig `
  --certificate SHA256SUMS.txt.pem `
  --certificate-identity-regexp '^https://github.com/sktelecom/bomlens/' `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Verified OK

$want = ((Select-String -Path SHA256SUMS.txt -Pattern 'BomLens-Setup.exe').Line -split '\s+')[0]
$got = (Get-FileHash BomLens-Setup.exe -Algorithm SHA256).Hash
if ($want -ieq $got) { "OK: BomLens-Setup.exe matches" } else { "MISMATCH" }
```

If the last line prints `MISMATCH`, do not run the installer.

## Container image

The images are signed by digest, and each one carries its own SBOM as a signed attestation.

```bash
cosign verify ghcr.io/sktelecom/bomlens:1.13.7 \
  --certificate-identity-regexp '^https://github.com/sktelecom/bomlens/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

To read the image's SBOM (CycloneDX) from the attestation:

```bash
cosign verify-attestation --type cyclonedx ghcr.io/sktelecom/bomlens:1.13.7 \
  --certificate-identity-regexp '^https://github.com/sktelecom/bomlens/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | head -1 | jq -r '.payload | @base64d | fromjson | .predicate' > bomlens-image.cdx.json
```

You can then run BomLens on its own image's SBOM: `scan-sbom.sh --analyze bomlens-image.cdx.json --project bomlens-image --version 1.13.7`.

## The project's own SBOM

Each release also attaches `bomlens-source-<version>.cdx.json`, the SBOM of every manifest the repository ships (the desktop app's and the web UI's dependencies). It is covered by the same checksum file.

## What this does not tell you

A valid signature says who built the file, not that the code is free of defects. The scanner image is scanned by Trivy every night and the findings are public in the repository's Security tab, and the [limitations](../concepts/limitations.md) page lists what the tool does not do.
