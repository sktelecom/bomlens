# Architecture

> **한국어**: [아키텍처](architecture.md) · **Related**: [Getting started](getting-started.en.md) | [Usage guide](usage-guide.en.md) | [Use the Docker image directly](docker-image.en.md)

This document describes the overall system structure of BomLens and explains which tool runs at which step of the scan pipeline, and in what order.

> This document reflects the 2-stage architecture as currently implemented. The Stage 1 routing in the source code (detect the language, then run the official cdxgen language image) is implemented and working in `scripts/scan-sbom.sh`.

## At a glance

BomLens is a 2-stage pipeline in which two kinds of Docker images work together.

- **Stage 1 — Generation**: for source code, the official per-language cdxgen images generate the SBOM (CycloneDX 1.6); for container images, binaries, and directories, syft does.
- **Stage 2 — Post-processing**: the lightweight `sbom-scanner` image takes the SBOM and runs normalization, (deep license detection), notice generation, the security report, signing, and upload in order.

```mermaid
flowchart LR
    subgraph S1["① Stage 1 — Generation (build the SBOM)"]
        direction TB
        SRC["Source code"] --> CDX["cdxgen<br/>(official per-language image)"]
        IMG["Image / binary / directory"] --> SYFT["syft"]
        CDX --> BOM[("bom.json<br/>CycloneDX 1.6")]
        SYFT --> BOM
    end

    subgraph S2["② Stage 2 — Post-processing (sbom-scanner image)"]
        direction TB
        BOM --> NORM["normalize (jq)"]
        NORM --> SCAN["scancode<br/>(opt-in)"]
        SCAN --> NOTICE["notice (jq)"]
        NOTICE --> TRIVY["Trivy<br/>(security)"]
        TRIVY --> SIGN["cosign<br/>(signing)"]
    end

    SIGN --> OUT["Host artifacts"]
    SIGN -.upload (optional).-> DT["Dependency-Track"]

    style S1 fill:#e3f2fd,stroke:#1976d2
    style S2 fill:#f1f8e9,stroke:#689f38
    style BOM fill:#fff9c4,stroke:#fbc02d
```

The single entry point for orchestration is `scripts/scan-sbom.sh` (`scan-sbom.bat` on Windows); this is the only script users invoke.

---

## Why two stages

Previously, every language runtime plus every analysis tool lived in a single huge image. The redesigned pipeline splits the responsibilities in two (see the maintainer-facing [direction study report](https://github.com/sktelecom/sbom-tools/blob/main/docs/internal/direction-study.md) (Korean) §1 and §5 for the rationale).

| | Stage 1 image | Stage 2 image (`sbom-scanner`) |
|---|---|---|
| **Role** | **Generates** the SBOM from source | SBOM **post-processing** (normalization, notice, security, signing, upload) plus syft scans |
| **Contents** | Official **per-language** cdxgen images (java, python, node, ...) | **No** language toolchain — lightweight `debian:12-slim` |
| **Acquisition** | Pulled **on demand** after detecting the project language | Pulled once and reused |
| **Benefit** | cdxgen maintains up-to-date per-language toolchains | Small image; pinned tool versions ensure reproducibility |

> For the five mainstream languages (java, python, node, dotnet, php), detection with the official cdxgen images is identical, and for go, ruby, and rust the toolchain preparation (`build-prep.sh`) is decisively better. For the measurement data, see [README "Why a Docker image?"](https://github.com/sktelecom/sbom-tools#why-a-docker-image-vs-plain-cdxgen) and the [direction study report](https://github.com/sktelecom/sbom-tools/blob/main/docs/internal/direction-study.md) (Korean) §1.

---

## Tool inventory

The tools invoked by the pipeline and their **version pinning** status (supply chain hygiene).

| Tool | Version | Stage | Role | Enabled when |
|------|------|------|------|-----------|
| **cdxgen** | bundled in the language image | Stage 1 | Generates the SBOM from source code (`--spec-version 1.6`) | `MODE=SOURCE` |
| **build-prep.sh** | — | Stage 1 | Dependency preparation right before cdxgen (cargo, go, bundle, mvn, pip) | `MODE=SOURCE` |
| **syft** | `v1.18.1` | Stage 1 | Scans images, binaries, and root filesystems | `MODE=IMAGE/BINARY/ROOTFS` |
| **jq** (`normalize-sbom.sh`) | — | Stage 2 | Normalizes and sorts the SBOM | Always |
| **ScanCode Toolkit** | `32.3.0` | Stage 2 | Precise license detection on first-party source | `--deep-license` (opt-in build) |
| **jq** (`generate-notice.sh`) | — | Stage 2 | Generates the open source notice (NOTICE) | `--notice` / `--all` |
| **Trivy** | `v0.70.0` | Stage 2 | Vulnerability (CVE) security report | `--security` / `--all` |
| **Cosign** | `v2.4.1` | Stage 2 | Detached SBOM signature | `--sign` |
| **curl** | — | Stage 2 | Upload to Dependency-Track | Default (unless `--generate-only`) |

> Versions are pinned as `ARG`s in `docker/Dockerfile`. To keep the image from bloating, ScanCode is **opt-in**: it is included only when the image is built with `--build-arg SBOM_DEEP_LICENSE=true`.

---

## Full pipeline flow

The **order** in which tools are invoked, in one diagram. Dashed boxes are optional steps enabled by flags.

```mermaid
flowchart TD
    Start([Run scan-sbom.sh]) --> Detect{Detect target type}

    %% ---- Stage 1 ----
    Detect -->|directory = source| Lang["Detect language → pull image"]
    Detect -->|image/file/RootFS| Syft

    Lang --> Prep["1 build-prep.sh<br/>cargo·go·bundle·mvn·pip"]
    Prep --> Cdxgen["2 cdxgen --spec-version 1.6"]
    Syft["syft -o cyclonedx-json"] --> Bom
    Cdxgen --> Bom[("bom.json")]

    %% ---- Stage 2 ----
    Bom --> Norm["3 normalize-sbom.sh (jq)<br/>· always runs"]
    Norm --> DeepQ{--deep-license?}
    DeepQ -->|yes| Scancode["4 scancode<br/>1st-party licenses"]
    DeepQ -->|no| NoticeQ
    Scancode --> NoticeQ{--notice / --all?}
    NoticeQ -->|yes| Notice["5 generate-notice.sh (jq)<br/>NOTICE.txt / .html"]
    NoticeQ -->|no| SecQ
    Notice --> SecQ{--security / --all?}
    SecQ -->|yes| Trivy["6 scan-security.sh<br/>Trivy → json/md/html"]
    SecQ -->|no| SignQ
    Trivy --> SignQ{--sign?}
    SignQ -->|yes| Cosign["7 cosign sign-blob<br/>bom.json.sig"]
    SignQ -->|no| Copy
    Cosign --> Copy["8 Copy artifacts to host<br/>· always runs"]

    Copy --> UploadQ{Upload?}
    UploadQ -->|default| Upload["9 curl → Dependency-Track"]
    UploadQ -->|--generate-only| Done
    Upload --> Done([Done])

    style Prep fill:#e3f2fd
    style Cdxgen fill:#e3f2fd
    style Syft fill:#e3f2fd
    style Bom fill:#fff9c4
    style Scancode stroke-dasharray: 4 4
    style Notice stroke-dasharray: 4 4
    style Trivy stroke-dasharray: 4 4
    style Cosign stroke-dasharray: 4 4
    style Upload stroke-dasharray: 4 4
```

The sequence from the user's invocation through post-processing:

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant S as scan-sbom.sh
    participant D as Docker
    participant L as Stage 1 language image
    participant P as sbom-scanner (run-scan)

    U->>S: scan-sbom.sh --project App --version 1.0 --all
    S->>S: Parse arguments, detect target type
    rect rgb(227,242,253)
    note over S,L: Stage 1 — Generation
    S->>D: (source) docker run the language image
    D->>L: build-prep.sh → cdxgen
    L-->>S: bom.json
    end
    rect rgb(241,248,233)
    note over S,P: Stage 2 — Post-processing
    S->>D: sbom-scanner docker run (MODE=POSTPROCESS)
    D->>P: run-scan (entrypoint)
    P->>P: normalize → scancode → notice → Trivy → cosign
    P->>P: Copy artifacts to host
    P-->>U: (optional) upload to Dependency-Track
    end
```

---

## Stage 1 — SBOM generation

The generation tool depends on the target type.

### Source code (`MODE=SOURCE`) — cdxgen language image

`scan-sbom.sh` detects the project language with `detect_lang()`, picks the matching **official cdxgen language image** with `img_for_lang()`, pulls it, and runs `build-prep.sh` inside that image (`scripts/scan-sbom.sh:138-208`). The lightweight post-processing image has no language toolchain, so generation is handled entirely by the language image.

The per-language cdxgen image mapping is as follows (`scan-sbom.sh:158-177`; the tag is pinned via `CDXGEN_TAG`).

| Detected language | Image |
|-----------|--------|
| rust | `cdxgen-debian-rust` |
| go | `cdxgen-debian-golang124` |
| ruby | `cdxgen-debian-ruby34` |
| java | `cdxgen-temurin-java21` |
| python | `cdxgen-python312` |
| node | `cdxgen-node20` |
| php | `cdxgen-debian-php84` |
| dotnet | `cdxgen-debian-dotnet9` |
| android | self-built `sbom-scanner-android-sdk<API>` (compileSdk extracted automatically) |
| mixed / unknown | cdxgen all-in-one (`CDXGEN_ALLINONE`) |

Two steps run inside the image:

1. **`build-prep.sh`** (`docker/lib/build-prep.sh`) — dependency preparation **right before** cdxgen. It creates lockfiles for ecosystems cdxgen cannot resolve on its own (notably Rust and Go), exposing transitive dependencies. POSIX `sh`, best-effort (it never fails the scan).

   | Ecosystem | Action | Notes |
   |--------|------|------|
   | Rust | `cargo generate-lockfile` | cdxgen does not run cargo automatically — **required** |
   | Go | `go mod download` (`-mod=mod`) | Resolves the module graph |
   | Ruby | `bundle lock` / `install` | Only when no lockfile exists |
   | Maven | `mvn dependency:resolve` | Lightweight safety net |
   | Python | `pip install -r requirements.txt` | Exposes transitive dependencies when no lockfile exists |

2. **Run cdxgen** — `build-prep.sh` auto-detects the cdxgen binary path, which differs per image, and runs `cdxgen -r --spec-version 1.6 -o bom.json` (`build-prep.sh:60-73`). The generated SBOM is then handed to the Stage 2 (`MODE=POSTPROCESS`) post-processing image.

### Image / binary / directory — syft

**syft**, included in the `sbom-scanner` image, generates the SBOM directly. (`docker/entrypoint.sh`)

| MODE | Input | syft invocation |
|------|------|-----------|
| `IMAGE` | Docker image | `syft <image> -o cyclonedx-json` (requires the docker.sock mount) |
| `BINARY` | Single file | `syft file:<path> -o cyclonedx-json` (falls back to a minimal SBOM on failure) |
| `ROOTFS` | Directory | `syft dir:<path> -o cyclonedx-json` |

---

## Stage 2 — post-processing pipeline

The `sbom-scanner` image's entry point `run-scan` (`docker/entrypoint.sh`) takes the SBOM and runs the steps in a **fixed order**. Each step is enabled by an environment variable (equivalent to a CLI flag), and outputs accumulate in the `ARTIFACTS` list.

```mermaid
flowchart TD
    A["Obtain SBOM<br/>(POSTPROCESS: Stage 1 output / otherwise: syft)"] --> B
    B["① normalize-sbom.sh (jq) — always<br/>--stable when BYTE_STABLE"] --> C
    C{"② DEEP_LICENSE<br/>&& /src exists"} -->|yes| C1["scancode → _scancode.json"]
    C -->|no| D
    C1 --> D
    D{"③ GENERATE_NOTICE"} -->|yes| D1["generate-notice.sh →<br/>_NOTICE.txt / .html"]
    D -->|no| E
    D1 --> E
    E{"④ GENERATE_SECURITY"} -->|yes| E1["scan-security.sh (Trivy) →<br/>_security.json / .md / .html"]
    E -->|no| F
    E1 --> F
    F{"⑤ SIGN_SBOM<br/>&& COSIGN_KEY"} -->|yes| F1["cosign sign-blob →<br/>bom.json.sig"]
    F -->|no| R
    F1 --> R
    R{"⑥ GENERATE_REPORT<br/>(on by default)"} -->|yes| R1["generate-risk-report.sh →<br/>_risk-report.md / .html"]
    R -->|--no-report| G
    R1 --> G
    G["⑦ Copy artifacts to host — always"] --> H
    H{"⑧ UPLOAD_ENABLED"} -->|default| H1["curl → trustedoss-portal"]
    H -->|"false (--generate-only)"| Z([End])
    H1 --> Z

    style B fill:#f1f8e9
    style G fill:#f1f8e9
```

Step details:

| # | Step | Script / tool | Condition | Output |
|---|------|-----------------|------|--------|
| ① | **Normalize** | `normalize-sbom.sh` (jq) | Always (deterministic mode with `--byte-stable`) | Updates `bom.json` |
| ② | **Deep license** | `scancode` | `--deep-license` and `/src` exists | `_scancode.json` |
| ③ | **Notice** | `generate-notice.sh` (jq) | `--notice` / `--all` | `_NOTICE.txt`, `_NOTICE.html` |
| ④ | **Security report** | `scan-security.sh` (Trivy) | `--security` / `--all` | `_security.{json,md,html}` |
| ⑤ | **Signing** | `cosign sign-blob` | `--sign` and `COSIGN_KEY` | `bom.json.sig` |
| ⑥ | **Risk report** | `generate-risk-report.sh` | Default (skip with `--no-report`) | `_risk-report.{md,html}` (plus `_conformance.*` in ANALYZE mode) |
| ⑦ | **Copy to host** | `cp` | Always | Copied to `HOST_OUTPUT_DIR` |
| ⑧ | **Upload** | `curl` | Default (skipped with `--generate-only`) | Registered with trustedoss-portal (Dependency-Track compatible) |

> **Why the order is fixed**: normalization stabilizes the input for every later step, so it runs first; signing must target the final `bom.json`, so it runs last. Each step is best-effort — failures are handled with `|| true` or a warning and do not abort the whole scan (signing and upload excepted).

---

## Branching by input type

`scan-sbom.sh` determines the mode automatically from `--git`/`--analyze`/`--firmware` and the `--target` value.

The checks run top to bottom; the first matching branch wins.

```mermaid
flowchart TD
    D1{"--git URL<br/>or URL-like target?"} -->|yes| R1["clone → MODE=SOURCE"]
    D1 -->|no| D2{"--target<br/>*.zip / *.tar.gz?"}
    D2 -->|yes| R2["extract → MODE=SOURCE"]
    D2 -->|no| D3{"--analyze sbom?"}
    D3 -->|yes| R3["MODE=ANALYZE<br/>validate + convert to CDX"]
    D3 -->|no| D4{"target omitted?"}
    D4 -->|yes| R4["MODE=SOURCE<br/>current directory → cdxgen"]
    D4 -->|no| D5{"existing file?"}
    D5 -->|"yes · --firmware/extension"| R5["MODE=FIRMWARE<br/>opt-in firmware image"]
    D5 -->|"yes · otherwise"| R6["MODE=BINARY → syft"]
    D5 -->|no| D6{"existing directory?"}
    D6 -->|yes| R7["MODE=ROOTFS → syft"]
    D6 -->|no| R8["MODE=IMAGE → syft"]
```

> Independently of the branching above, `--ui` starts `MODE=UI` (the web server `server.py`) and runs subsequent scans through the form or file upload.

| Mode | Trigger | Generation tool | Notes |
|------|--------|-----------|------|
| `SOURCE` | No target, `--git <url>`, or `--target *.zip/*.tar.gz` | cdxgen | Language detection selects the per-language image. Git targets are cloned; archives are extracted and treated as source. (The web UI's SOURCE uses `syft dir:` inside the container) |
| `ANALYZE` | `--analyze <sbom>` (alias `--sbom`) | — | Validates a supplier SBOM (CycloneDX/SPDX), converts it to CDX, and re-aggregates. Produces `_conformance.*` |
| `FIRMWARE` | `--target <file> --firmware`, or a firmware file extension | unblob + syft + cve-bin-tool | **Opt-in image** `sbom-scanner-firmware`. Details in the [firmware analysis guide](firmware-analysis-guide.en.md) |
| `BINARY` | `--target <file>` | syft | `file:` scheme |
| `ROOTFS` | `--target <directory>` | syft | `dir:` scheme |
| `IMAGE` | `--target <image name>` | syft | docker.sock mount |
| `UI` | `--ui` | — | Browser UI; runs all six scan target types through the form or file upload |

---

## Flag-to-step mapping

How CLI flags translate into environment variables and which steps they enable (`scan-sbom.sh` converts them and passes them to `entrypoint.sh`).

| Flag | Environment variable | Steps enabled |
|--------|----------|-------------|
| (default) | `GENERATE_REPORT=true` (plus notice and security) | normalize + **risk report** + upload |
| `--no-report` | `GENERATE_REPORT=false` | Does not force-enable the risk report, notice, or security steps |
| `--notice` | `GENERATE_NOTICE=true` | ③ notice |
| `--security` | `GENERATE_SECURITY=true` | ④ security report |
| `--all` | Both of the above | ③ + ④ |
| `--git <url>` / `--branch` | (cloned on the host) | SOURCE input collection |
| `--analyze <sbom>` | `MODE=ANALYZE` | Supplier SBOM validation, conversion, and report |
| `--firmware` | `MODE=FIRMWARE` (firmware image) | Unpack, then syft + cve-bin-tool |
| `--deep-license` | `DEEP_LICENSE=true` | ② scancode |
| `--byte-stable` | `BYTE_STABLE=true` | ① deterministic normalization (CLI only) |
| `--sign` | `SIGN_SBOM=true` (plus `COSIGN_KEY`/`COSIGN_PASSWORD`) | ⑤ signing |
| `--generate-only` | `UPLOAD_ENABLED=false` | ⑦ skips the upload |
| `--ui` | `MODE=UI` | Web UI |

> The **risk report** (`_risk-report.{md,html}`) is generated **by default** in every mode (it aggregates licenses and vulnerabilities). To support it, the notice and security scans are turned on automatically alongside it; disable with `--no-report`.

For how to use each feature, see the [notice and security report guide](notice-and-security.en.md).

---

## Artifacts

`{P}` is the project name, `{V}` the version (special characters are normalized to `_`).

| File | Generated when |
|------|-----------|
| `{P}_{V}_bom.json` | Always (CycloneDX 1.6) |
| `{P}_{V}_NOTICE.txt` / `.html` | `--notice` / `--all` / default risk report generation |
| `{P}_{V}_security.json` / `.md` / `.html` | `--security` / `--all` / default risk report generation |
| `{P}_{V}_risk-report.md` / `.html` | Default (all modes) — skip with `--no-report` |
| `{P}_{V}_conformance.json` / `.md` / `.html` | `--analyze` (supplier SBOM validation) |
| `{P}_{V}_scancode.json` | `--deep-license` |
| `{P}_{V}_bom.json.sig` | `--sign` |

---

## Extension points

### Adding support for a new language
1. Check whether an official cdxgen image exists for the language — if so, add it to the routing table.
2. If cdxgen cannot resolve transitive dependencies automatically, add preparation logic to `docker/lib/build-prep.sh`.
3. Add an example project under `examples/{language}/` and a test case in `tests/cases/test-{language}.sh`.

For the full procedure, see the [package manager guide](contributing/package-manager-guide.en.md).

### Adding a new post-processing step
Add a helper script under `docker/lib/`, call it from the shared pipeline section of `entrypoint.sh` (after normalization) behind an environment variable guard, and append its outputs to `ARTIFACTS`. Place it **before** the signing step so its outputs are covered by the signature.

---

## Design principles

- **Isolation** — all analysis runs in Docker containers; the host environment stays untouched.
- **Separation of concerns** — generation (Stage 1) and post-processing (Stage 2) are split, keeping the post-processing image small.
- **Reproducibility** — tool versions are pinned via `ARG`; `--byte-stable` produces byte-identical output.
- **Standards compliance** — conforms to the CycloneDX 1.6 specification.
- **Robustness** — post-processing steps are best-effort and do not easily abort the whole scan.
- **Single interface** — every language and mode is invoked through the one `scan-sbom.sh`.

---

## Division of roles (trustedoss-portal)

BomLens specializes in **generation**. **Governance** — company-wide project management, vulnerability triage, and license policy gates — is delegated to the sister project [`trustedoss-portal`](https://github.com/sktelecom/trustedoss-portal). Both tools share cdxgen and Trivy, so the artifacts (CycloneDX) are directly compatible.

```mermaid
flowchart LR
    subgraph dev["Developer · single project"]
        A["Source / image / binary"] --> B["sbom-tools"]
        B --> C["SBOM"]
        B --> D["Notice"]
        B --> E["Security report"]
    end
    subgraph org["Organization · central management"]
        C -. upload .-> F["trustedoss-portal"]
        F --> G["Vulnerability triage"]
        F --> H["License policy gate"]
        F --> I["Project dashboard"]
    end
```
