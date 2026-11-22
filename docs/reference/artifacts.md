---
description: The output files BomLens produces — file list, when each is generated, naming rules, and the SBOM structure summary.
---

# Artifacts reference

The generated SBOM is CycloneDX 1.6 JSON, or 1.7 with `--spec-version 1.7`; AI model and dataset SBOMs are always 1.7. An SPDX 2.3 JSON copy, converted from the final CycloneDX BOM, is produced by `--spdx` during a CLI scan or on demand from the results screen in the UI. AI model and dataset scans also write an SPDX 3.0.1 document with the AI and Dataset profiles (`_bom.spdx3.json`, below). Both paths run the same conversion and give the same file. CycloneDX remains the primary format, and CycloneDX-only data (vulnerabilities, `bomlens:*` properties, and the `services[]` a [declared AI service](#the-declared-ai-service) adds) is not carried over.

The filename is `{Project}_{Version}_bom.json` (e.g. `MyApp_1.0.0_bom.json`).

## Output files

| File | When generated | Description |
|------|----------------|-------------|
| `{Project}_{Version}_bom.json` | always | SBOM (CycloneDX 1.6, or 1.7 with `--spec-version 1.7`) |
| `{Project}_{Version}_bom.refused.json` | a source scan or Yocto build directory scan whose declaration file (`--components`, or `sbom-declared.cdx.json` at the scan target root) is refused | the SBOM written up to the point the scan stopped, without the declared components. It takes the place of `_bom.json`, which is not written, so a step that picks up `_bom.json` cannot take the incomplete SBOM; the scan prints the reasons and exits 1. Not normalized, signed or uploaded, and no report is made from it. The web UI's failed scan offers it to view or download. The next scan of the same project and version removes it. See [What is refused, and why?](../guides/declared-components.md#what-is-refused-and-why) |
| `{Project}_{Version}_bom.spdx.json` | `--spdx` / `--all`, or Export as SPDX 2.3 in the UI | SBOM (SPDX 2.3, converted from the CycloneDX output) |
| `{Project}_{Version}_bom.spdx3.json` | AI model and dataset scans (`--model`, `--model-file`, a dataset), unless `--no-spdx3` | the AI SBOM as an SPDX 3.0.1 document with the AI and Dataset profiles (JSON-LD). Fields come from the CycloneDX output, from fixed rules over it, or from the publisher's declaration (`--ai-declare`); nothing is estimated. Required fields SPDX gives no "unknown" value (who supplied and who made the model and data, release and build dates, the download address, the document's author) stay empty until declared, and the document says it is a draft until then. Base models are identified by id and licence only. The weights scope is carried as `bomlens:weights:scope` (`full`, `adapter`, `quantized`, `merged`) in a CycloneDX properties extension. Not an input for `--analyze` |
| `{Project}_{Version}_spdx3-check.json` / `.md` | with the SPDX 3.0.1 document | which field of each element came from the scan, from the declaration, or from nothing, which required fields are open, and what needs a decision by the publisher (personal data, safety risk, autonomy). `service.state` says whether the CycloneDX SBOM carries the declared service and model values: `none` (nothing declared, nothing in the SBOM), `applied` (the SBOM matches the declaration) or `pendingScan` (they differ; a new scan writes them). Guidance, not legal advice |
| `{Project}_{Version}_ai-declaration.template.json` | with the SPDX 3.0.1 document | an empty declaration for this scan: the fields a person fills, for the model, its datasets and the base models the scan found. Fill it and pass it back with `--ai-declare` |
| `{Project}_{Version}_ai-declaration.json` | `--ai-declare <file>` (the accepted file), or the declaration saved in the web UI | what the model's publisher declared. Like `_vex.json`, it is not removed by re-scanning the same project and version, and a re-scan applies it again. A file that names a dataset or base model the new scan does not have is refused, and the document stays a draft. A dataset entry can list `sources[]`: `{"ref": "huggingface:<id>", "relation": "extended"}` for a hub dataset (read from the hub at the next scan and judged with the dataset), or `{"name": "...", "license": "<hub licence tag or SPDX id>", "relation": "other"}` for one named in words (written to the SPDX 3.0.1 document only, marked as not verified; a licence that is not an SPDX id is kept in words). Data the hub does not hold takes sources named in words only. `model.license` (a hub licence tag or SPDX id) is the model's own licence: it fills the SPDX document when the scan read none or only `other` (as an SPDX expression only when it is a hub tag naming one SPDX licence, or a `LicenseRef-`), and a model described from the declaration alone carries it in its SBOM and is judged on it. A declaration can also describe the service the model runs in (`service`) and give the model's input and output kinds and regulatory values; see [The declared AI service](#the-declared-ai-service) |
| `{Project}_{Version}_component-versions.template.csv` | a firmware, root filesystem or binary scan that found components without a version | the names of those components in the `--component-versions` format (CSV with the header `name,version,reason`) with the versions left empty, and comment lines explaining the three reasons. A component that already carries a reason is not listed. Fill in a version, or a reason when there is none, and pass it back with `--component-versions` |
| `{Project}_{Version}_NOTICE.txt` / `.html` | `--notice` / `--all` / risk report default | open-source notice |
| `{Project}_{Version}_NOTICE.pdf` | same as above, when a PDF renderer is built into the image (`--build-arg SBOM_PDF=true`) | the notice rendered to PDF; skipped with a log line otherwise |
| `{Project}_{Version}_security.json` / `.md` / `.html` | `--security` / `--all` / risk report default | Trivy security report |
| `{Project}_{Version}_risk-report.md` / `.html` | default (all modes) — omit with `--no-report` | open-source risk report |
| `{Project}_{Version}_conformance.json` / `.md` / `.html` | every scan that generates an SBOM, also with `--no-report` (which skips only the risk report); `--analyze` produces it too, since that is what it measures | conformance check report, with a regulatory crosswalk roll-up for every SBOM (EU CRA via BSI TR-03183-2, the US SBOM minimum elements of 2026; reference only, no compliance determination). For an AI SBOM it also carries the G7 checks and, for each advisory element still missing, the CycloneDX fragment that would satisfy it. For an AI BOM another tool wrote, a G7 element read from that tool's property says so in its detail ("also read from ...") and in a `via` field. Names any best-effort post-process step that failed during the scan, including those that run after the check (NOTICE, the security scan, the risk report), so a pass is not read as proof every step ran cleanly; does not affect the pass/fail result or any individual check. See a [rendered example](../samples/aether-7b-5attn_conformance.html) |
| `{Project}_{Version}_ai-profile.json` / `.md` | AI SBOM (`--model`, or `--analyze` on an SBOM with a model component) | AI compliance profile: G7 rollup, the closable gaps with their reference links, license-flagged components, regulatory crosswalk, and the model risk assessment (`riskAssessment`: per-model ok/conditional/caution/review verdicts with conditions, reasons and the usage scenario; guidance, not legal advice). The same rollup opens the conformance HTML, so there is no separate HTML profile |
| `{Project}_{Version}_scancode.json` | `--deep-license` | raw scancode result |
| `{Project}_{Version}_files.json` | a source-having scan (a firmware scan always; other modes when `--deep-license` did not already produce `_scancode.json`) | ScanCode-shaped file-tree inventory (structure only, no licenses) backing the source-tree view |
| `{Project}_{Version}_source.json` | a source-having scan | snapshot of the scanned tree's file content, backing the file viewer (the scanned tree itself does not outlive the container). Credentials in file content, such as registry tokens and passwords in URLs and configuration files, are masked; a file with masked values has `"masked": true`, and `totals.maskedFiles` counts them |
| `{Project}_{Version}_input.json` | `--analyze` | the supplier SBOM's own format, spec version, tool and authorship, captured before the CycloneDX conversion rewrites all of it |
| `{Project}_{Version}_yocto_vex.json` | a Yocto build (a build directory named directly, or `--analyze` on one) | how many CVEs the build already patched or judged not applicable — numbers not recoverable from the CycloneDX output or the security report, which list only what is still unresolved |
| `{Project}_{Version}_vex.json` | web UI only, saved when a judgement (affected / not affected / fixed / under investigation, with an optional note) is recorded against a CVE on the Vulnerabilities screen | the judgements recorded for this scan, keyed by component and CVE. Not produced by the CLI, and absent until the first judgement is saved for a given scan. Unlike every other file here, it is not regenerated by a scan and is not removed by re-scanning the same project and version: a judgement recorded against an earlier scan survives scanning it again |
| `{Project}_{Version}_vex.cdx.json` | web UI only, built when you press **Export VEX** on the Vulnerabilities screen (needs at least one recorded judgement) | the judgements from `_vex.json` as a standalone CycloneDX VEX document that another tool can read, at 1.7 when the scan's SBOM is 1.7 and at 1.6 otherwise. The four states map to CycloneDX `analysis.state` values (affected to `exploitable`, not affected to `not_affected`, fixed to `resolved`, under investigation to `in_triage`), and the note goes into `analysis.detail`. No `justification` is written, because the screen collects free text and CycloneDX allows only a fixed list. Each entry points at a copy of its component (name, version, PURL) held in the document itself, so the file stands alone. A judgement whose component is not in the SBOM is left out, and the screen says how many; firmware findings are the usual case, since their name and version come from the binary. It is rebuilt on every export and removed when the same project and version is scanned again, so export again afterwards |
| `{Project}_{Version}_vex_imported.json` | `--vex <file>` on the CLI, or **Import VEX** on the Vulnerabilities screen in the web UI, with a CycloneDX VEX document | the statements from a supplier's VEX document that apply to a component of this scan's SBOM, with the product the document describes. Kept apart from your own judgements in `_vex.json`: a received statement never overwrites one, and the screen labels the two separately. The four states are mapped from CycloneDX `analysis.state` (`exploitable` to affected, `not_affected` and `false_positive` to not affected, `resolved` and `resolved_with_pedigree` to fixed, `in_triage` to under investigation); any other state is ignored. A document whose product or version differs from the scanned SBOM's root is refused and nothing is saved. A successful import replaces this file; a refused or empty one leaves the previous file as it was. A statement that names the product itself is stored once, without a component, and applies to every finding of that CVE that has none of its own. Like `_vex.json`, it is not removed by re-scanning the same project and version |
| `{Project}_{Version}_reachability.cdx.json` | `--reachability` on a Go source or Go executable scan, when govulncheck could read the Go vulnerability database | govulncheck's judgement of each Go advisory against a component of the SBOM (same module and version), as a standalone CycloneDX 1.6 VEX document. `analysis.state` is `not_affected` when the affected code is not reached, with `justification` `code_not_present` when the module is required but no affected package is in the build, or `code_not_reachable` when the package is there but no affected function is called (or linked in an executable). It is `exploitable` when the code is reached. `analysis.detail` says which, with the call path or the symbol. `id` is the advisory's CVE when it has one, with its Go and other ids in `references`. In a source scan, `metadata.properties` record what was covered: `bomlens:reachability:goos`, `goarch`, `build-tags` and `modules`. The security report reads it: each finding it covers carries `bomlens:reachability` (`state`, `justification`, `detail`, `level`, `mode`) in `_security.json`, and the document has a `Reachability` summary |
| `{Project}_{Version}_vendored.cdx.json` | `--identify-vendored` on a source scan, with the opt-in SCANOSS image | vendored open-source components identified inside the source tree (SCANOSS) |
| `{Project}_{Version}_security_trivy.json` | with the security report, when another engine (grype, cve-bin-tool, Yocto) added results to it | Trivy's own result, kept apart before the merge into `_security.json` |
| `{Project}_{Version}_cdxgen.log` | a CLI source scan where a dependency preparation step failed (the SBOM records it in `bomlens:pipeline-step-failed`) | the stage 1 log (the preparation steps and cdxgen), kept for finding the cause. A diagnostic file, not meant for distribution: credentials in URLs (`scheme://user:pass@` becomes `scheme://***@`) and Authorization, token, password, secret and API key values are masked, but internal host names stay. Removed before the next scan of the same project and version |
| `{Project}_{Version}_scan.log` | every CLI scan | every line the scan container printed, including the processing details a terminal run hides unless `--verbose` or `VERBOSE=true` is given. Credentials are masked as in the cdxgen log; a diagnostic file, not meant for distribution. Removed before the next scan of the same project and version |
| `bomlens-events.jsonl` | `BOMLENS_EVENTS=file` | progress events, one JSON object per line. See [Engine contract](engine-contract.md#progress-events) |
| `bomlens-result.json` | always | the run's result manifest: how it ended, each step's outcome, and the role of each output file. See [Engine contract](engine-contract.md) |
| `{Project}_{Version}_security_epss.json` | whenever the security report is generated | EPSS score and KEV status per vulnerability (null/false when generated offline), used to prioritize the security report |
| `{Project}_{Version}_completeness.json` | every SBOM scan | how complete the result is (`complete`, `partial` or `unreliable`) and the reasons when it is not. The Overview banner and the reports read it. A security scan that was asked for and did not run or failed (a Trivy error, an empty trivy-db mount, Trivy missing) makes the result `partial` with the reason `vulnerability-check-failed` and the SBOM property `bomlens:vulnerability-check-failed`; a Trivy database that is only old does not, and a scan with the security check off never carries it |
| `{Project}_{Version}_bom.json.sig` | `--sign` | cosign signature (with `--spdx`, a `_bom.spdx.json.sig` is produced too, and an AI scan adds `_bom.spdx3.json.sig`; a draft is signed too, since the signature says where the file came from, not that it is complete) |
| `{new}_model-diff.json` | `--diff <old.json> <new.json>` | AI-model drift report comparing two already-generated SBOMs: matched model verdict/license/hash changes, plus any component present in only one of the two files. Named after the newer input (`<new>_bom.json` → `<new>_model-diff.json`), not `{Project}_{Version}` — `--diff` takes no project or version of its own |

`{P}` = project name, `{V}` = version (special characters are normalized to `_`).

The conditions above are the CLI flags. In the web UI and the desktop app the same choices are the generation options on the New scan screen — Notice and Security report — and every file produced is listed in the Artifacts section of the results, downloadable per format or as one ZIP. SPDX is not a scan option there: the SBOM row in that section has an **Export as SPDX 2.3** button that converts the finished BOM whenever you need it, and the converted file joins the artifact list and the ZIP. The UI has no signing, so an SPDX exported that way is unsigned; use `--spdx --sign` in the CLI when you need a signature. See [Web UI and desktop app](ui.md).

## The declared AI service

An AI declaration (`--ai-declare`, or the declaration saved in the web UI) can describe the service the model runs in with a top-level `service` object, and give the model a few values a scan cannot read. A `service` is accepted only when the document describes a model, not a dataset, and one that holds no value at all counts as not declared. The [AI model guide](../guides/ai-model.md#the-service-a-model-runs-in) explains what these are for.

A `service` object looks like this:

```json
"service": {
  "name": "Acme Support Assistant",
  "packageVersion": "2.3.0",
  "downloadLocation": "https://support.acme.example/assistant",
  "suppliedBy": {"type": "Organization", "name": "Acme Corp"},
  "releaseTime": "2025-06-01T00:00:00Z",
  "informationAboutApplication": "Answers customer support questions in the web chat.",
  "domain": ["customer support"],
  "autonomyType": "no",
  "inputModality": ["text"],
  "outputModality": ["text"],
  "dataFlows": [
    {"flow": "inbound", "classification": "personal data",
     "description": "Customer questions typed in the chat window.",
     "source": ["https://support.acme.example/chat"]}
  ],
  "standardCompliance": ["ISO/IEC 42001:2023"],
  "disclosureUrl": "https://support.acme.example/ai-disclosure"
}
```

| Key | Value |
|-----|-------|
| `name` | the service's name. Required |
| `packageVersion` | its version. Required |
| `downloadLocation` | the address where the service is offered (a URI). Required |
| `suppliedBy` | the organization that provides it, `{"type": "Organization", "name": "..."}`. Required |
| `releaseTime` | when it was released, `YYYY-MM-DDThh:mm:ssZ`. Required |
| `informationAboutApplication` | what the service is for, in words |
| `domain[]` | the fields it serves, in words |
| `autonomyType` | whether a person is involved in its decisions: `yes` (fully automatic, no person involved), `no` (a person is involved) or `noAssertion` (not known) |
| `inputModality[]`, `outputModality[]` | the kinds of input and output: `text`, `image`, `audio`, `video`, `timeseries`, `structured`, `code`, `other` |
| `dataFlows[]` | the data going in and out, each `{flow, classification, name, description, source[], destination[]}`. `flow` is `inbound`, `outbound`, `bi-directional` or `unknown`. `classification` is required (up to 200 characters) and says what the data is, such as personal data. `name` and `description` are optional words; the description says what the service does with the data. `source[]` and `destination[]` are addresses (URIs) |
| `standardCompliance[]` | the standards the service follows, by name |
| `disclosureUrl` | a public page about the service's use of AI (a URI) |
| `externalModels[]` | AI models the service calls through an API, each `{key, name, suppliedBy, packageVersion, endpoint}`. `key` (lowercase letters, digits, `.`, `_` and `-`, up to 64, unique in the list) and `name` are required, and `endpoint` is a URI |

The required keys are the ones SPDX requires of the service; the document stays a draft until they are given. The declaration's `model` takes five more keys:

| Key | Value |
|-----|-------|
| `inputModality[]`, `outputModality[]` | the model's input and output kinds, with the same values as the service's |
| `trainingComputeFlops` | the compute used to train the model in floating-point operations, a positive decimal number written as a string, such as `"3.2e24"` or `"1500000"` |
| `trainingComputeBasis` | how that figure was counted, in words |
| `adversarialTesting` | whether adversarial testing was done: `yes`, `no` or `noAssertion` |

In the SPDX 3.0.1 document the service is an `ai_AIPackage` with `software_primaryPurpose` `application`, linked to the model by a `dependsOn` relationship with the scope `runtime`, and each external model is a `software_Package` with the purpose `model`. The data flows, the input and output kinds and the model's regulatory values are CycloneDX property extensions: `bomlens:service:dataFlow` (one per flow, holding it as compact serviceData JSON), `bomlens:service:input` and `:output`, `bomlens:model:input` and `:output`, and `bomlens:regulatory:*`.

A scan also writes them into the CycloneDX SBOM, in a step that runs after the declared dataset sources are read and before the risk assessment and the G7 checks:

| Location | Content |
|----------|---------|
| `services[]`, bom-ref `service:declared/<name>` | the service: `name`, `version`, `provider.name`, `endpoints[0]` (its address), `description` (what it is for), `data[]` (the data flows as serviceData), an `externalReferences` entry of type `documentation` (the disclosure page), and the properties `bomlens:service:domain`, `:autonomyType`, `:input`, `:output` and `:releaseTime` |
| `services[]`, bom-ref `service:declared-external/<key>` | each external model: `name`, `version`, `provider.name`, `endpoints` and `bomlens:service:declarationKey` |
| `dependencies[]` | the service depends on the model's bom-ref and on each external model |
| `declarations.claims[]` | one claim per standard, with the service as target, the standard's name as predicate, and the reasoning "publisher's declaration, not verified by BomLens" |
| the model component | the properties `bomlens:regulatory:trainingComputeFlops`, `:trainingComputeBasis` and `:adversarialTesting`, and the input and output kinds as `modelCard.modelParameters.inputs[]` and `outputs[]` (`{"format": "text"}`) |

Every service written this way carries `bomlens:origin=declared-input` and `bomlens:service:kind` (`application` or `external-model`), and the application service carries `bomlens:service:declarationDigest`. On the model component, a `bomlens:declared` property names each location filled from the declaration (a property name, or a `modelCard` path; `modelCard` and `modelCard.modelParameters` themselves when the step created them). Where the scan had already recorded inputs or outputs, those are kept and a `bomlens:declared:observedKept` property names them. `bomlens:model:declarationDigest` records which declaration the model values came from. A `modelCard.modelParameters` created only to hold declared formats does not count as a model card in the G7 checks. The step can run again on the same SBOM: what an earlier run wrote is removed first, so a declaration without a service removes the old one, and a declaration the SPDX converter refuses is not applied at all.

The G7 system-level elements read the declared service, and an element met by it reports "present (publisher's declaration, not verified by BomLens)". The SPDX 2.3 export and `--diff` do not carry services. BomLens v1.13 and earlier refuse a declaration that has a `service` or one of the new model keys, with "unknown key(s)".

## AI usage in a source scan

A source scan also records the AI the scanned code uses. This is separate from `--model`: it reads no model card, and lists what the code calls and how the project is set up to work with AI tools. It runs by default.

| What | Where it goes | Example |
| --- | --- | --- |
| A model the code references | `components[]`, type `machine-learning-model` | `gpt-4o` as `pkg:generic/openai/gpt-4o`, `meta-llama/Llama-3.1-8B-Instruct` as `pkg:huggingface/...` |
| An AI service the code calls | `services[]`, with the models it is called with in `dependencies[]` | OpenAI API |
| An MCP server in a configuration file | `services[]` | a server from `.vscode/mcp.json` or `.cursor/mcp.json` |
| The MCP configuration file | `components[]`, type `file` | `.vscode/mcp.json` |
| An agent instruction file | `components[]`, type `file`, with its SHA-256 | `AGENTS.md`, GitHub Copilot `copilot-instructions.md`, `.cursor/rules/*.mdc` |

Each item carries `bomlens:ai:usage` (`model`, `ai-service`, `mcp-server`, `mcp-config` or `instruction-file`) and `bomlens:ai:scope`: `runtime` for what the code calls, `development` for editor and agent configuration.

An MCP server that needs a look gets one or more `bomlens:ai:reviewReason` values:

- `broad-filesystem-access`: it is given the filesystem root or the home folder.
- `unpinned-package`: it runs with `npx` or `uvx` and no version, so a new release runs without review.
- `unencrypted-transport`: it is reached over plain `http` on another host.

Some things are never copied: the environment values and headers an MCP server is given (tokens, for example) and prompt texts. An endpoint keeps no user info, query or fragment.

These items are listed, not measured. The conformance check and the NOTICE leave them out, and so does the model risk assessment unless the model was looked up on the hub (below), and a model the code only calls gets no G7 checks, because it has no card here to check. To check a model itself, scan it with `--model`.

The findings come from cdxgen's `ai` and `mcp` analyses, which match text. BomLens keeps a model only when its id looks like one and it appears in code that is neither a test nor documentation, and keeps an AI service only when such a model is left under it. A model a project lists in a data structure can still be missed, and a string shaped like a model id can still be reported. Set `BOMLENS_NO_AI_USAGE=1` to turn the step off.

### Looking the models up on Hugging Face

A model the code references is listed by name and purl only. With `--resolve-models` (or the option on the new-scan form), the scan asks the Hugging Face hub about each `pkg:huggingface/...` model and adds a summary to its entry:

- the licence the model card declares, as written (`llama3.1`, not a guess at an SPDX id), and the model risk assessment's verdict on it, which also reads the base models' licences,
- the weight file formats, how many are pickle files (they can run code when loaded), and each weight file's SHA-256 where the hub holds one. These are recorded, not judged: the verdict does not read them,
- whether the repository is gated (the hub describes a gated repository without a token), and the hub's current revision and its time (not necessarily what the code loads),
- the chain of base models the card names, with each one's licence.

A model the hub answers an error for is marked `unreadable` with the HTTP status. That is a private repository or one that does not exist, which the hub answers the same way (401); set `HF_TOKEN` for a private one you can read. A model the hub did not answer for, answered 429 or a 5xx status for, or ran out of time for is marked `unreachable` or `not-attempted`, and the step is recorded as failed (the SBOM is still written). Nothing is filled in by guessing. `MODEL_RESOLVE_MAX` (20) bounds the models looked up and `MODEL_RESOLVE_BUDGET` (240) the seconds all lookups, base models included, may take; the rest are marked `not-attempted`. A hosted model with no hub page, such as `gpt-4o`, is left as it was.

The summary is not the model's own SBOM, which needs the model card and the checks `--model` runs. To get it and tie it to the source SBOM, scan the model and pass the file:

```bash
./scripts/scan-sbom.sh --project my-llm --version 1.0 --model "meta-llama/Llama-3.1-8B-Instruct"
./scripts/scan-sbom.sh --project my-app --version 1.0 --target ./my-app \
  --model-sbom my-llm_1.0/my-llm_1.0_bom.json
```

The model is then linked to the file with a CycloneDX BOM-Link (`externalReferences` of type `bom`, `urn:cdx:<serial number>/<version>#<bom-ref>`), so a reader of the source SBOM can find the full one. The link points at the document by its serial number, so keep the model SBOM with the source SBOM when you pass them on. A file with no serial number, or one that matches no model the code references, is reported and left out. The summary's licence and weight files are read from the hub at scan time; the linked SBOM is the one to rely on for a complete picture.

## SBOM structure

```
bomFormat          "CycloneDX"
specVersion        "1.6" ("1.7" with --spec-version 1.7)
metadata
  ├── timestamp    generation time (ISO 8601)
  └── component    project info (name, version, type)
components[]
  ├── type         "library" | "framework" | "application"
  ├── name         component name
  ├── version      version
  ├── purl         Package URL (unique identifier)
  ├── supplier     who supplied the component (when the package metadata names one)
  └── licenses[]   license info (SPDX ID)
compositions[]     dependency-graph completeness (see below)
```

For the per-language PURL format, see [Supported ecosystems](ecosystems.md).

A component's `supplier.name` comes from what its package metadata already says, and from nothing else: the `publisher` the generator read (a Maven POM's `<organization>`, an npm publisher), the `authors` it read (PyPI, RubyGems, Composer), or the older `author` field, in that order. Anything in angle brackets is dropped, and so is a pair of parentheses or square brackets that holds only an email address or a URL, which removes the email address and URL of an npm-style `Name <email> (url)`. Other parentheses stay, so `Example (Holdings), Inc.` is kept as it is. An email address or a URL (`http://`, `https://`, `ftp://`, `www.`) elsewhere in the value is dropped too, along with an unclosed parenthesis in front of it, so `Alice <a@x.org>, Bob <b@y.org>` gives `Alice, Bob`, `Jane Doe jane@example.org` gives `Jane Doe` and `Bob <b@x.org>; Carol <c@y.org>` gives `Bob; Carol`. A value that is only an email address or only a URL is not used, and several authors are joined with commas. The property `bomlens:supplierSource` names the field used (`publisher`, `authors` or `author`). A component with none of these has no supplier, and one that already has a supplier keeps it. Nested components follow the same rule. Distribution and firmware packages (`pkg:deb`, `pkg:rpm`, `pkg:apk`, `pkg:alpm`, `pkg:opkg`, `pkg:generic`) and `operating-system` components are not given a supplier: the publisher a generator reads for them is the package's maintainer, usually one person, and the distribution's name is not filled in by guess. A supplier's own SBOM under `--analyze` is left as it was written, and so is the output of `--merge`.

A source scan also records on `metadata.component.properties` whether the project pinned its versions: `bomlens:source:versionPinning` is `pinned` when a lock file exists, or every line of `requirements.txt` has an exact version, and `unpinned` when a `requirements.txt`, `package.json`, `pyproject.toml`, `setup.py` or `setup.cfg` has no lock file next to it and does not fix every version. For `unpinned`, the versions in the SBOM are what a fresh install resolved on the day of the scan, not necessarily the ones you ran. The web UI shows a notice, and the risk report states it under the vulnerability counts. Neither says so when the versions were read from what is installed: an installed Python environment (`bomlens:python-environment`) or the lock file npm or pnpm wrote at install at the scan root (`bomlens:node-lock-source`). When an offline npm install resolved every dependency from npm's cache (`npm-offline-cache` in `bomlens:prep-step-applied`), the web UI notice says the versions came from that cache instead. The property is absent when the scan could not tell.

A Maven source scan that read your own Maven local repository records two properties on `metadata.properties`: `bomlens:maven-user-repository` is `read-only`, and `bomlens:maven-offline` is `probe` when the repository Maven would download from did not answer and BomLens added `-o`, `settings` when your own settings already ran Maven offline (`<offline>true</offline>` or `-o`), and `false` otherwise. Both are absent when the repository was not mounted or was empty, when the tree has no `pom.xml`, or when `BOMLENS_MAVEN_USER_REPOSITORY=false` was set ([Java (Maven)](ecosystems.md#java-maven)).

A Gradle source scan that read your own Gradle cache records `bomlens:gradle-user-cache` on `metadata.properties`: `online` when a repository the build names answered and Gradle ran as usual, `offline` when none did and Gradle ran `--offline` from the caches. The property is absent when the cache was not mounted, not a Gradle build, or `BOMLENS_GRADLE_USER_CACHE=false` was set ([Java (Gradle)](ecosystems.md#java-gradle)).

A Python source scan that read the project's installed virtual environment, because the package index did not answer or `pip install` failed, records on `metadata.properties` `bomlens:python-environment`, the environment folder relative to the scan root (for example `.venv`), and `bomlens:python-environment-reason`, `index-unreachable` or `pip-install-failed`. `bomlens:python-environment-unsure` is added only when something could not be settled, and says what (an environment marker that could not be decided, a declared package that is not installed, an installed version that differs from a declared pin); the result is then partial with the reason `installed-environment-unsure`, and `compositions[0].aggregate` is `incomplete`. All three are absent when the environment was not read, or `BOMLENS_PYTHON_VENV=false` was set ([Python](ecosystems.md#python)). The environment folder itself is left out of the scan's search whether or not it was read, and its pattern (`.venv/**`) is in `bomlens:excluded-paths`, also with `BOMLENS_INCLUDE_NON_SHIPPED=1`.

A Node.js source scan that read the lock file npm or pnpm wrote at install, in place of a committed one, records `bomlens:node-lock-source` on `metadata.properties`, one per file read, with the path relative to the scan root (for example `node_modules/.package-lock.json` or `web/node_modules/.pnpm/lock.yaml`). `bomlens:prep-step-applied` then lists `npm-installed-lock` or `pnpm-installed-lock`. The property is absent when every folder had its own lock file, when the lock was not read, or when `BOMLENS_NODE_INSTALLED_LOCK=false` was set ([Node.js](ecosystems.md#nodejs)).

A source scan whose dependency analysis wrote an SBOM although the package registry refused the login for some downloads (HTTP 401 or 403) records `bomlens:registry-refused` with the value `registry-auth` on `metadata.properties`. Some dependencies may be missing, so `compositions[0].aggregate` is `incomplete`. The result completeness grade does not change for it, because the scan cannot tell whether a refusal found in the log left a dependency out. The web UI shows a notice on the Overview ([Company network](../guides/company-network.md)). When the dependency analysis failed outright, `bomlens:sbom-tool-degraded` records `registry-auth` instead.

## Dependency-graph completeness

A generated SBOM carries a `compositions[0].aggregate` entry stating how complete its dependency graph is:

| Value | Meaning |
|-------|---------|
| `complete` | The scan found positive evidence the graph was fully resolved: an ecosystem's lock/resolve step succeeded, or a lockfile was already committed, plus at least one dependency edge. |
| `incomplete` | A known failure affected the scan: the syft fallback ran instead of cdxgen, a firmware package-cataloging step failed, a Poetry project with no `poetry.lock` was converted only in part or its dependencies could not be resolved, an installed Python environment was read with something it could not settle (`bomlens:python-environment-unsure`), or the package registry refused some downloads (`bomlens:registry-refused`). |
| `unknown` | Nothing in the SBOM confirms the graph is complete. This is the default whenever there is no positive evidence either way, for example an image/rootfs/firmware/binary scan (syft alone cannot see inter-package dependencies), an AI-model, dataset or merged SBOM, or a Maven source scan (no reliable signal tells a resolved graph apart from a degraded one). `unknown` is not a defect; it means the tool found no basis to judge, not that something went wrong. |

An analyzed supplier SBOM's own `compositions` declaration, if it has one, is never overwritten.

The conformance check report's transitive-dependency check notes the declared value in its detail text (e.g. "12 edge(s), declared complete"), without changing the check's pass/fail status.

A preprocessing label that ran, or was satisfied by an already-committed lockfile, is recorded in the `bomlens:prep-step-applied` property regardless of success or failure; `bomlens:pipeline-step-failed` records only the failures. `aggregate` above is decided from both together. `license-fetch` in `bomlens:pipeline-step-failed` means the registry license lookup was turned off for this scan because the registry did not answer, so only the licenses in lock files and package manifests are in the SBOM. It leaves no dependency out and does not change the completeness grade: the CLI reports it as one `[INFO]` line, and the web UI shows it as an information note, not as incomplete data. `cocoapods-licenses` means the CocoaPods trunk did not answer (or the lookup ran out of time), so some pods have no license. It does not change the completeness grade either, and the closing summary lists it among the steps that failed.

A failed step can carry what the build tool reported, in `bomlens:pipeline-step-cause` (`<step>: <sentence>`, for example the first line of Gradle's `What went wrong` text), and a known cause with a fix of its own, in `bomlens:resolution-hint`: `maven-parent-outside-scan` (a Maven module scanned without the folder of its parent POM), `android-useandroidx-missing` (an Android build without `android.useAndroidX=true`) and `android-release-classpath-unresolved` (the Android build failed before its release runtime classpath was read, so the build tooling of its other configurations was left out). The completeness result quotes the cause and gives the hint's fix in place of the general one; `android-release-classpath-unresolved` makes the grade unreliable. Its own fix (fix the Gradle error and scan again) is given only when no other hint names a specific fix, so with `android-useandroidx-missing` the fix names the property alone; both messages stay.

## Conformance check report

The rows and their verdicts per profile are summarized in [Reading the conformance check report](../guides/supplier-sbom.md#reading-the-conformance-check-report). This section has the rules behind them.

- Namespace. Every type whose namespace purl-spec marks required is checked, not only OS packages: a `pkg:maven` identifier without its groupId, or a `pkg:rpm` identifier that carries the distribution only as a `?distro=` qualifier, is well formed and resolves to nothing. `pkg:golang` and `pkg:huggingface` are reported on a separate advisory row, because a Go module path can be a bare host and a model published outside an organization has no owner segment.
- Top-level component name. Some generators write a fixed value in place of the product name (`.`, `..`, `/` or `/scan`), and SBOMs for different products then collide. Whether the name collides with another submission is for the intake system to decide; this check cannot see it.
- PURL type. The types come from `docker/lib/purl-types.json`. A generator that rebuilds identifiers from a display name can invent one (`pkg:applications/java@11.0.25`). `skt-submission` also accepts `pkg:sourceforge` and `pkg:gnu`, which name a project at its release on SourceForge or the GNU site.
- OS package namespace value. The namespace of an `rpm`, `deb` or `apk` identifier carries the distribution id the package repository uses (`rhel`, `debian`, `ubuntu`, `alpine`); a company name such as `pkg:rpm/examplevendor/glibc@…` is not one. Values not in `docker/lib/os-distros.json` are reported with how many identifiers carry them. A namespace is also accepted when it equals the name of the SBOM's operating-system component or the distribution id in the same identifier's `distro=` qualifier, which covers a custom distribution that declares itself. A missing namespace is counted by the namespace row, not here.
- Version value. A version with whitespace, a `key: value` shape (a manifest line such as `Specification-Vendor: The Apache Software Foundation` read as a version), a control character, or more than 128 characters is reported, up to 50 as `name@version`.
- Suggested fixes. A "Suggested fixes" section (`suggestions` in the JSON) gives a candidate for a component that fails the namespace rows or the version row when one rule gives exactly one answer: the distribution named by a `distro=` qualifier or by the single operating-system component, a Maven `group` field, or a version with only leading or trailing whitespace. The distribution must fit the package type (`alpine` for `apk`, `debian` for `deb`); an unrecognized `distro=` qualifier gives no candidate and no fallback; the `group` field is a medium-confidence hint, dropped when the purl name has a colon or starts with the group. Each candidate states its basis and confidence, and an ambiguous case gets no candidate but a note of what is needed, such as the base distribution. Suggestions come from the file alone, without a network lookup, and the submitted file is not changed: the supplier corrects the SBOM and submits it again. The `.md` and `.html` reports show the first 50.
- Version needed and No upstream purl (`skt-submission` only). "Version needed" fails only on components that have neither a version nor a reason. A component the supplier explained with a reason (`own-code`, `not-open-source` or `version-unknown`) is listed under "Explained by the supplier" (`explained` in the JSON), and the row can pass while that list is not empty; under `--analyze` the reasons come from the `bomlens:versionReason` properties in the SBOM. "No upstream purl" lists components that have a version but no purl naming their source repository. It is a warning, not for the supplier to fix, and SK Telecom checks those components separately. Under `--analyze` the first row says to ask the supplier for a corrected SBOM and the second to ask for a rescan with a current BomLens. A supplier who scans firmware, a root filesystem or a binary fills the versions or reasons in `{Project}_{Version}_component-versions.template.csv` and scans again with `--component-versions` ([firmware guide](../guides/firmware.md#supplying-the-versions-the-scan-could-not-read)). For a scan BomLens ran itself, the summary says that `{Project}_{Version}_bom.json` is the one file to submit.
- Firmware, root filesystem, binary and Yocto build scans under `skt-submission`. The namespace value row and the version row warn instead of failing, because those scans take the values from the files they found. The general rows also do not fail on what the two rows above already cover, and each says why in its detail: name and version coverage warns when every component missing a version has a reason; PURL coverage warns when every component missing a purl is explained or versioned; "Traceable PURL (no pkg:generic)" warns when every `pkg:generic` component has a version or a reason; transitive dependencies warns, because such a scan records the packages found, not a dependency graph. None of this applies while any component has neither a version nor a reason, or when the SBOM lists no package. Such a scan records `bomlens:scanMode` (`FIRMWARE`, `ROOTFS`, `BINARY` or `YOCTO`) in `metadata.properties`, and `--analyze` judges an SBOM that carries it the same way and says so in the summary. A source scan, and any other SBOM under `--analyze`, keeps these rows as measured. The default profile is unchanged.
- First-party components. Your own build outputs have no package repository and so no purl. Listed in a declaration file (`--components`, or `sbom-declared.cdx.json` at the scan root) with `bomlens:origin` `first-party`, a supplier and a build output in `bomlens:artifact` (which gives them a SHA-512), they are left out of PURL coverage, "Traceable PURL (no pkg:generic)" and "No upstream purl", and listed on the advisory row "First-party components identified by supplier and SHA-512 instead of a purl". This holds only in the scan that read the declaration file: a `first-party` component in an SBOM checked with `--analyze` still needs a purl, and so does a `third-party` component in the declaration file.
- Package and file components. Name, version and PURL coverage count package components only. A binary or firmware SBOM also lists delivered files, which have no package version or PURL type; the file identifier row measures how many of them have a hash. An SBOM that lists files and no packages at all fails, because vulnerability matching keys on package identifiers.
- Recommended rows. Besides license and hash coverage: SHA-512 checksum coverage, component creator, component filename, source or distribution URI, the delivered-file properties (review when no scan can see the artifact), and file component identifier coverage. One of the 2026 minimum elements asks the SBOM to say why a field is empty; an SBOM BomLens generated says so for the whole document, and a received SBOM that says nothing is reported as a gap.
- `--resolve-purl` adds one advisory row, the only part of the check that uses the network. It asks each package repository whether the identifiers name packages that exist, which catches identifiers that are well formed and resolve to nothing, such as `pkg:maven/org.drools/org.drools.drools-core-dynamic@…` (the groupId repeated in the artifactId) or `pkg:maven/The%2BApache%2BSoftware%2BFoundation/poi@…` (a vendor display name in place of the groupId). It never fails the SBOM, because a package published only to an internal repository answers the same way; set `PURL_RESOLVE_IGNORE` to your internal namespaces. The coordinate is checked, not the version, since a vendor rebuild version is legitimate and absent from the public repository.
- Not checked: that a server delivery includes its OS packages, that an OS package's purl names the distribution actually installed (a `pkg:deb/debian/...` purl on a RHEL server passes), and the file basics (extension, size, JSON syntax). Check those with the [validation checklist](https://sktelecom.github.io/guide/supply-chain/for-suppliers/checklist/).
- Regulatory references. A row that corresponds to a regulatory baseline carries the reference under it, and a crosswalk section rolls the coverage up per framework: BSI TR-03183-2 (the German technical guideline for the EU Cyber Resilience Act) and the US SBOM minimum elements (2026). The crosswalk is reference material and makes no compliance determination; [Regulatory crosswalk](#regulatory-crosswalk) below describes how it works. The cards at the top of the HTML report show the verdict and the missing items.

### Regulatory crosswalk

Two frameworks cover every analyzed SBOM, AI or not:

- EU Cyber Resilience Act, via BSI TR-03183-2, the German technical guideline written for CRA compliance and the most detailed public SBOM field specification (the CRA itself names no data fields). TR-03183-2 is a national guideline, and the European harmonized standard that will carry the binding wording is still a draft.
- US SBOM minimum elements: the 17 data fields and 6 practices of the 2026 minimum elements, published by CISA, the NSA and the FBI with fifteen international partners and replacing the NTIA elements of 2021. Federal SBOM collection has since been narrowed to agency-level, risk-based decisions, but the fields remain the practical baseline that individual agencies ask for.

The crosswalk above covers SBOM data fields only. For the broader CRA readiness process those fields sit inside (governance, vulnerability handling, the technical file, security updates), see the community-maintained [OpenChain CRA Compliance Requirements & Checklist](https://github.com/OpenChain-Project/CRA-Compliance).

For an AI SBOM, the EU AI Act and the Korean AI Framework Act also map onto the G7 elements; the [AI model SBOM guide](../guides/ai-model.md#regulatory-crosswalk) lists their sections.

The mapping lives in `docker/lib/regulation-crosswalk.json`, keyed by check id: the G7 element ids for the AI checks and the plain CycloneDX check ids for the base format checks. It is deliberately conservative: only checks with a defensible correspondence are mapped. Today that is 74 check ids with 84 links across the four frameworks, since one check can point at more than one framework. A test validates every mapped id against the registry so the crosswalk cannot drift silently when a check is renamed.

### AI BOMs from other tools

`--analyze` reads an AI BOM that another tool wrote and runs the same G7 check and risk assessment on it. Samples of four tools were checked: the k8s-aibom CycloneDX output, AIsbom, Cisco AI BOM and AIBoMGen CLI. None of them fills most of the G7 elements, so the report shows many of them as missing. That is the content of the file, not a fault of the reading.

A few values sit where the G7 check did not look before, and are read now. The detail line of such an element says `also read from` and names the source, and the result carries it in `via`.

| Element | Read from | Tool |
|---|---|---|
| Model identifier | `aisbom:hf:repo_id` | AIsbom |
| Model licence | `aisbom:hf:license` | AIsbom |
| Model version | `aisbom:hf:revision`, `k8s-aibom:model:revision` | AIsbom, k8s-aibom |
| SBOM generation context | `metadata.lifecycles` (a CycloneDX field) | k8s-aibom, AIBoMGen CLI |

AIsbom leaves the hub's licence out of `licenses[]` on purpose, so that a licence verdict does not change on its own. BomLens counts it as present and passes it to the risk assessment only while `licenses[]` is empty; `licenses[]` wins when both exist. The value is what the hub page declares, and BomLens does not check it.

The rest of what these tools write has no G7 element to land on: Cisco AI BOM lists agents and MCP servers as `application` components, and k8s-aibom records the workload that runs the model. They stay in the file and in the component list.
