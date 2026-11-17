---
description: The code signing policy for the BomLens Windows installer, the people who approve a signing request, and what BomLens sends over the network.
---

# Code signing policy

Free code signing provided by SignPath.io, certificate by SignPath Foundation

Releases of the Windows installer are signed under the following policy. The file that is signed is `BomLens-Setup.exe`. Each release is built from this repository by a workflow that runs on GitHub-hosted runners, and every signing request needs an approver's manual approval before the file is signed.

## Team roles

- Committers and reviewers: [haksungjang](https://github.com/haksungjang)
- Approvers: [haksungjang](https://github.com/haksungjang)

Committers can change the source without a separate review. Changes proposed by anyone who is not a committer are reviewed by a team member before they are merged. An approver decides, for each release, whether the installer is signed.

## Privacy policy

BomLens runs on your machine. No feature of BomLens sends your source code, SBOMs or scan results to a server operated by this project, and BomLens has no telemetry or usage analytics. The scanner container reads what you point it at and writes its results to the folder you chose.

BomLens does contact other services, listed below. Where a request carries identifiers, the list says which ones.

### Requests made by default

- Update check (desktop app). When it starts, the installed desktop app asks the GitHub releases API (`api.github.com`) for the latest release and compares the version number. The request carries no data about you or your scans. GitHub receives it like any other web request, so it sees your IP address. A failed request is ignored, and the packaged app has no setting to turn the check off.
- Scanner image. The scanner image is downloaded from `ghcr.io` the first time, and an image that is already present is refreshed in the background. A source scan also pulls the language images it needs from `ghcr.io`. `SBOM_PULL=never` stops the downloads, and `SBOM_IMAGE_TAR` installs the image from a file.
- Vulnerability database. The security report uses Trivy, which downloads its vulnerability database (about 1.5 GB) during a scan and keeps it in the cache folder (`SBOM_TRIVY_CACHE`). The matching against it runs inside the container. `TRIVY_SKIP_DB_UPDATE=true` and a mounted database let a scan run offline, and `TRIVY_DB_REPOSITORY` points to a mirror.
- Exploit signals. The security report looks up the CVE ids it found at FIRST.org (EPSS) and downloads the CISA known exploited vulnerabilities list (KEV). The CVE ids of the findings are the only identifiers sent. `SECURITY_ENRICH=false` turns both lookups off.
- Go vulnerability database. The image holds a snapshot. A scan downloads a newer one from `vuln.go.dev` only when the snapshot is older than 7 days (`BOMLENS_GO_VULNDB_MAX_AGE_DAYS`) and the scan is not offline.
- Dependency resolution in source scans. Resolving the dependencies of a source project and reading crate licenses make the scan container request packages and package metadata from the package registries your project already uses. `FETCH_LICENSE=false` turns off the license lookups, and `--detection static` reads lock files instead of building.
- Web UI lookup. The CVE and package lookup screen in the web UI and the desktop app asks OSV.dev when you use it. It sends the advisory id, or the ecosystem, package name and version you typed. `EXTERNAL_LOOKUP=false` turns it off.

### Requests made only when you turn a feature on

- `--license-registry` and `STALENESS_ENRICH=true` send the ecosystem, name and version of components to deps.dev.
- `--resolve-purl` sends the package identifiers found in the SBOM you submitted for checking to deps.dev. Namespaces listed in `PURL_RESOLVE_IGNORE` are left out.
- `--identify-vendored` sends file fingerprints (hashes) of C and C++ source files to the SCANOSS OSSKB service. The files themselves are not sent. `SCANOSS_API_URL` points to another endpoint.
- `--model <owner/name>` and `--resolve-models` read model metadata from the Hugging Face hub, and `--model` with a Figshare item reads the item from the Figshare API. The web UI clones a repository address you enter for a source scan.
- `--upload-target`, `--trusca` and the web UI upload step send the finished SBOM to the Dependency-Track or TRUSCA server whose address (`API_URL`) you give.
- `--deep-cve`, `--deep-license` and the other opt-in images are pulled from `ghcr.io`. `SECURITY_NVD_VERIFY=true` also queries the NVD API.

For the full option list, see the [CLI reference](cli.md), and for the design behind it, see [Local-first by design](../concepts/local-first.md).

## Installation and removal

The Windows installer lets you choose the installation folder. The repository defines no custom installer steps, so BomLens makes no firewall or registry changes of its own. To remove BomLens, uninstall it from Windows Settings, then delete the settings folder `%APPDATA%\sbom-generator-desktop` if you want to remove the data the app kept. The scanner images stay in Docker until you remove them. For the commands, see the uninstall steps in the [no-CLI quick start](../start/no-cli.md).
