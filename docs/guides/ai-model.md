---
description: Generate a CycloneDX ML-BOM for a HuggingFace AI model with BomLens — from the model id, with G7 minimum-element conformance — and read the model card and datasets. No source code or model download needed.
---

# AI model SBOM guide

How to generate a CycloneDX ML-BOM (machine-learning bill of materials) for a HuggingFace model and read the result. You give a model id; BomLens fetches the model-card metadata over the network — no source code and no model-weight download.

For the design background and regulatory context (EU AI Act, G7), see the maintainer doc [AI SBOM readiness](https://github.com/sktelecom/sbom-tools/blob/main/docs/internal/ai-sbom-readiness.md) (Korean).

## How it works

An AI model's "bill of materials" is its model card: identifier, architecture, task, license, supplier, datasets, and the integrity of its files. BomLens uses the [OWASP AIBOM Generator](https://github.com/GenAI-Security-Project/aibom-generator) to read a HuggingFace model card and build a **CycloneDX 1.7 ML-BOM** centered on the model and the datasets it references. It then adds a **G7 minimum-element conformance** check (advisory). Because a model has no package dependencies, there is no security (CVE) report.

The full tool flow is in [Pipeline by input type](../concepts/pipeline-by-input.md#ai-model).

## Preparing the image

AI model SBOM generation needs a separate image that bundles the OWASP AIBOM Generator. It is opt-in and reaches the network (HuggingFace), so it ships as its own image rather than in the base one.

```bash
docker pull ghcr.io/sktelecom/bomlens-aibom:latest
```

This image is the default for AI-model scans, so `--model` pulls it without any extra setting. To use a different tag, set the environment variable `SBOM_AIBOM_IMAGE`.

## Running it

### From the web UI

Launch the UI from the aibom image — that is what enables the AI model tile — then enter the model id and run:

```bash
SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/bomlens-aibom:latest ./scripts/scan-sbom.sh --ui
#   Windows: set SBOM_SCANNER_IMAGE before double-clicking sbom-ui.bat
```

Choose **AI model** under the New scan source tiles, enter the HuggingFace model id as `org/model` (for example `google-bert/bert-base-uncased` or `Qwen/Qwen2.5-0.5B` — not a collection name or a full URL), and run.

### From the CLI

Pass the model id to `--model`:

```bash
./scripts/scan-sbom.sh --project bert-base --version 1.0.0 \
  --model "google-bert/bert-base-uncased" --generate-only
```

`--model` is mutually exclusive with `--target`, `--analyze`, `--git`, and `--merge`. It pulls the `bomlens-aibom` image automatically, produces the notice and the risk report, and skips the security report (a model has no package CVEs).

## Reading the result

In the web UI, an AI/ML SBOM adds two sections to the left rail.

**Models & datasets** — each model card's identifier, architecture, task, license, supplier and integrity, a four-axis disclosure panel (weights / architecture / training data / training process, as documented in the BOM), and the datasets the model references.

![Models & datasets — model card and disclosure axes](../images/web-ui-models.png)

**G7 conformance** — the G7 minimum-element checks for AI (all advisory) with an "N of 6 present" headline, separate from the base format-conformance checks. Each element shows what it is and how to satisfy it.

![G7 conformance — present/advisory split](../images/web-ui-g7.png)

The same data is in the artifacts: the ML-BOM (`_bom.json`, CycloneDX 1.7) and the conformance report (`_conformance.*`).

## Limits

- The result is only as complete as the HuggingFace model card. A sparse card yields a sparse ML-BOM, and the G7 checks reflect what the card documents — not an audit of the model.
- It fetches metadata over the network; private or gated models need access (a HuggingFace token in the environment), and offline use is not supported.
- The model id must be `org/model`. A collection name or a full URL will not resolve.

---

> **Related**: [Pipeline by input type](../concepts/pipeline-by-input.md) | [Web UI reference](../reference/ui.md) | [CLI reference](../reference/cli.md)
