---
description: Generate an AI SBOM (CycloneDX ML-BOM) for a HuggingFace model with BomLens and check it against the G7 minimum elements for AI — the 50-element checklist whose clusters overlap with the EU AI Act's Annex IV technical documentation. From the model id, no source code or model download needed.
---

# AI model SBOM guide

How to generate a CycloneDX ML-BOM (machine-learning bill of materials) for a HuggingFace model and read the result. You give a model id; BomLens fetches the model-card metadata over the network — no source code and no model-weight download.

## How it works

An AI model's "bill of materials" is its model card: identifier, architecture, task, license, supplier, datasets, and the integrity of its files. BomLens uses the [OWASP AIBOM Generator](https://github.com/GenAI-Security-Project/aibom-generator) to read a HuggingFace model card and build a **CycloneDX 1.7 ML-BOM** centered on the model and the datasets it references. It then adds a **G7 minimum-element conformance** check (advisory). Because a model has no package dependencies, there is no security (CVE) report.

A model card names its training datasets and stops there. BomLens looks each one up on HuggingFace and records what it finds — the declared license, the upstream datasets it derives from, and a content digest — as its own entry in the SBOM, linked to the model as a dependency. A dataset that cannot be read (withdrawn, renamed, or private to someone else) is kept in the SBOM as a name marked unreadable; no license is invented for it. This is also what decides the training-data disclosure axis: `open-data` needs at least one dataset that actually opened, and a card naming datasets nobody can retrieve reads `declared-unverified` instead.

The full tool flow is in [Pipeline by input type](../concepts/pipeline-by-input.md#ai-model).

## Before you start

You need two things.

- **A Docker engine, installed and running.** If you have none, start with the requirements in [Getting started](../start/first-scan.md).
- **A way to run BomLens.** The desktop app needs no commands; for the command line, [Getting started](../start/first-scan.md) covers cloning the repository. AI model scans need a separate image that bundles the OWASP AIBOM Generator. It is opt-in and reaches the network (HuggingFace), so it ships separately from the base image.

```bash
docker pull ghcr.io/sktelecom/bomlens-aibom:latest
```

That image is about 3.5 GB to download, far larger than the base scanner image (about 250 MB). The first pull can take tens of minutes depending on your connection, so start it with time to spare. It is downloaded once.

Pulling ahead of time is optional. `--model` uses this image by default and fetches it when missing, and the web UI and desktop app fetch it on the first AI-model scan while showing progress. To use a different tag, set `SBOM_AIBOM_IMAGE`.

## Running it

### From the web UI

Use the desktop app, or the web UI you already run. Where Docker is reachable the AI model tile is enabled, and the aibom image runs as a separate container fetched on the first scan — which makes that first run slow to start.

```bash
./scripts/scan-sbom.sh --ui
```

Launching the UI from the aibom image itself handles the scan in-process, with no second container. This is what you need where the Docker socket is unavailable.

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

### Private and gated models

A public model id resolves anonymously. A private repository, or a gated one you have been granted access to, needs a HuggingFace access token with read scope in `HF_TOKEN`:

```bash
HF_TOKEN=hf_... ./scripts/scan-sbom.sh --project my-llm --version 0.9.0 \
  --model "my-org/my-llm" --generate-only
```

`HUGGING_FACE_HUB_TOKEN` is accepted as well. The value is passed to the container by name, never as a command-line argument, so it does not appear in the process list, and it is not written to the SBOM or any report.

This is what lets you review a model before you publish it: push it to a private repository, generate the ML-BOM, close the gaps the conformance report shows, and only then make the repository public. For a gated repository, the token's account also needs its access request approved — a token alone is not enough. The same token is what resolves the model's training datasets, so a model whose data sits in a private repository needs it too.

The web UI reads the same variable from the environment that launched it, so start it with `HF_TOKEN=hf_... ./scripts/scan-sbom.sh --ui`. There is no token field in the interface: the server keeps no credentials, and a token sent over HTTP would linger in its logs.

## Reading the result

In the web UI, an AI/ML SBOM adds two sections to the left rail.

**Models & datasets** — each model card's identifier, architecture, task, license, supplier and integrity, a four-axis disclosure panel (weights / architecture / training data / training process, as documented in the BOM), and a table of the datasets the model references with each one's license, content digest and upstream.

![Models & datasets — model card and disclosure axes](../images/web-ui-models.png)

**Conformance** — for an AI-model SBOM this section adds the G7 minimum-element checks (all advisory), grouped by the seven G7 clusters, alongside the base format-conformance checks. Each element shows what it is and how to satisfy it. The next section explains what the numbers and badges mean.

![Conformance — the G7 advisory sub-block for an AI SBOM](../images/web-ui-g7.png)

The same data is in the artifacts: the ML-BOM (`_bom.json`, CycloneDX 1.7) and the conformance report (`_conformance.*`).

## Reading the conformance report

The G7 block leads with a headline such as "N / 41 present". The denominator counts only the checks that have an automated source — 41 of the 51 — so the number states what the tool could verify on its own. The 10 review-only elements appear next to it as a separate "need review" count, and any automated check that found nothing is counted as advisory.

Each check has one of three statuses. Pass means the element is present in the ML-BOM. Warn means it is missing or could not be confirmed; the 10 review-only elements always show this status, labeled as requiring human review. Fail does not occur for G7 checks in practice: every G7 element is advisory, so a missing one never fails the SBOM as a whole. An overall fail verdict can only come from the base format checks — the required CycloneDX ones.

A source badge on each row says where a satisfied value comes from:

- Auto (22 checks) — read directly from a field of the ML-BOM.
- Inferred (15) — derived from signals in the BOM rather than a single dedicated field.
- Declared (4) — present only when a person or a manifest supplied the value.
- Review needed (10) — no automated source exists; a person has to confirm it. The same result ships in three formats: `{Project}_{Version}_conformance.json` for machines (CI gates, diffing), `_conformance.md` as a readable table, and `_conformance.html` as a visual summary. Each format also carries the [regulatory crosswalk](#regulatory-crosswalk); in JSON it is the `regulatoryCrosswalk` object, present only when at least one mapped check was evaluated.

The report shows how to close a gap, not only that one exists. Every advisory element with an automated source that is still absent carries a CycloneDX fragment and a link to the authoritative documentation — in the HTML, behind the "Evidence / how to fill" cell on that row; in the Markdown, gathered under "How to fill the gaps". Passing and review-only elements are left out, so a well-documented model shows none of this.

## A worked example

A concrete run helps read the rest. `FINAL-Bench/Aether-7B-5Attn` is a foundation model published on HuggingFace under Apache-2.0 with its weights, architecture, training data and training process all disclosed, so it shows what a well-documented card produces.

```bash
./scripts/scan-sbom.sh --project Aether-7B-5Attn --version 1.0 \
  --model "FINAL-Bench/Aether-7B-5Attn" --generate-only
```

The run reports `result=pass` with 33 of 41 G7 elements present. All 14 Models-cluster checks pass, and the disclosure panel reads open on every axis:

| Axis | Value |
| --- | --- |
| Weights | open-weight |
| Architecture | open-architecture |
| Training data | open-data |
| Training process | open-training |

Because the card lists its datasets, BomLens looks up all seven the model was trained on (FineWeb-Edu, the SmolLM corpus, FineMath, open-web-math, an OpenCoder code corpus, and two Korean sets from HAERAE-HUB) and records what each one declares. Eight of the ten Dataset-properties elements come back present. The two that remain are the statistical properties of the data and whether it contains personal or copyrighted material; neither can be read from a repository, so the report asks a person rather than guessing.

The lookup is what makes the next part visible. Three of the seven datasets carry a license — `odc-by` on the FineWeb-Edu family, MIT on the OpenCoder corpus — and three declare none at all: both HAERAE-HUB sets and open-web-math. Counting dataset names would have called this model's training data fully open. Reading the datasets shows a model published under Apache-2.0 whose training corpus is, in part, of unstated license. That is not a finding the tool judges; it is the one a reviewer needs before release, and it only appears once each dataset is looked up.

The report this run produced is here to open as-is: the [conformance report](../samples/aether-7b-5attn_conformance.html) for the base model, which opens with the same G7 rollup the AI compliance profile carries in JSON and Markdown. Add `--lang ko` for the same reports in Korean; the SBOM and the JSON reports stay English either way.

## Next steps

A report is not a finished review. Some elements a tool can fill; others only a person can.

1. Fill the elements that have an automated source but came back empty, then scan again. The shape that satisfies each one sits on its own row in the report.
2. Answer the 10 review-only elements yourself — things like training-data sensitivity or the intended application area, which no model card field can prove.
3. Check separately what this tool does not look at, such as training dataset licensing and personal data.

If you are preparing a model for release inside a company, the approval steps and the pre-release checks live alongside this: see [Releasing an AI model](https://sktelecom.github.io/guide/release/ai-model/) in the SK Telecom open source guide.

## The G7 checklist

"G7 Software Bill of Materials for AI — Minimum Elements" is a guideline published in May 2026 under the G7, led by Germany's BSI and Italy's ACN. It defines 50 minimum elements, grouped into seven clusters, that an SBOM for an AI model should carry: who made the model, what it is, what data it was trained on, how it is secured, and how it performs. It is a non-binding recommendation, not a regulation.

It still matters for regulation. The EU AI Act's high-risk and transparency obligations apply from 2 August 2026, and the technical documentation its Annex IV asks for overlaps substantially with the G7 clusters. BomLens does not certify compliance with either text. What the conformance report gives you is visibility: element by element, it shows what your model's documentation already covers and what a person still has to supply — a concrete way to prepare, not a compliance verdict.

BomLens shows the 50 elements as 51 checks. Model openness (whether weights, architecture, training data and training process are disclosed) is one facet of the Model license element in the G7 text, but it is worth seeing on its own, so it gets a separate row.

| Cluster | Checks | Of which need human review |
| --- | --- | --- |
| Metadata | 10 | 0 |
| System-level properties | 9 | 4 |
| Models | 14 | 0 |
| Dataset properties | 10 | 2 |
| Infrastructure | 2 | 0 |
| Security properties | 4 | 3 |
| Key performance indicators | 2 | 1 |

Ten elements have no automated source — things like the intended application area or dataset sensitivity, which no model-card field can prove. BomLens lists them as requiring human review instead of guessing.

## Regulatory crosswalk

The conformance report links each check that maps to a regulation to the specific documentation obligation it touches. It answers a reviewer's question: when a check comes back short, which regulatory requirement does that gap concern? The reference sits under the requirement it belongs to in the check tables, and a crosswalk section above the detail rolls the coverage up — one row per framework, counting how many mapped checks are present, a gap, or review-only.

Two frameworks cover every analyzed SBOM, AI or not:

- EU Cyber Resilience Act — via BSI TR-03183-2, the German technical guideline written for CRA compliance and the most detailed public SBOM field specification (the CRA itself names no data fields). TR-03183-2 is a national guideline, and the European harmonized standard that will carry the binding wording is still a draft.
- NTIA minimum elements — the seven SBOM data fields published under US Executive Order 14028 (2021). Federal SBOM collection has since been narrowed to agency-level, risk-based decisions, but the fields remain the practical baseline that individual agencies ask for.

For an AI SBOM, two more frameworks map onto the G7 elements:

- EU AI Act — the technical-documentation sections of Annex IV (Regulation (EU) 2024/1689, Article 11(1)).
- AI Framework Act (Korea) — the Act's articles on transparency (제31조), safety and risk management (제32조), high-impact AI (제33·34조), and impact assessment (제35조). The Act sets framework-level duties, so these links are coarser than the EU ones.

The crosswalk is a preparation aid, not a compliance verdict. BomLens does not certify compliance with any of these texts, and the report says so in the section itself. Each mapping carries the interpretive basis for the link so a person can judge it, and the crosswalk never changes a check's status or the overall result — it only regroups findings the checks already produced.

The mapping lives in `docker/lib/regulation-crosswalk.json`, keyed by check id — the G7 element ids for the AI checks and the plain CycloneDX check ids for the base format checks. It is deliberately conservative: only checks with a defensible correspondence are mapped (38 today), and a test validates every mapped id against the registry so the crosswalk cannot drift silently when a check is renamed.

## AI compliance profile

For an AI SBOM, BomLens also writes a one-page AI compliance profile (`_ai-profile.{json,md,html}`) that gathers into one place what otherwise lives across separate artifacts: the G7 status by cluster, the regulatory crosswalk, and the components whose license is flagged for review (AI behavioral-use or non-commercial). It runs no scan and makes no compliance determination — it regroups findings the pipeline already produced, so a reviewer can read the whole picture at a glance. It is written for the AI-model (`--model`) and supplier-SBOM (`--analyze`) paths, and is a no-op for a plain (non-AI) SBOM.

## Limits

- A model the tool cannot read produces no SBOM at all. The generator fills the card with generic defaults when a fetch fails, so BomLens checks its log and refuses the run rather than handing back an inventory of placeholders that would read as a pass.
- The result is only as complete as the HuggingFace model card. A sparse card yields a sparse ML-BOM, and the G7 checks reflect what the card documents — not an audit of the model.
- Dataset entries record what a dataset declares about itself. Whether the declared license is the right one, and whether a derived dataset is compatible with the ones it came from, is a judgement the report leaves to a reviewer.
- The conformance report does not certify compliance with the EU AI Act or any other regulation. It makes documentation gaps visible so a person can close them.
- It fetches metadata over the network, so offline use is not supported. Private and gated models need `HF_TOKEN` (see [Private and gated models](#private-and-gated-models)).
- The model id must be `org/model`. A collection name or a full URL will not resolve. ---

> **Related**: [Pipeline by input type](../concepts/pipeline-by-input.md) | [Web UI reference](../reference/ui.md) | [CLI reference](../reference/cli.md)
