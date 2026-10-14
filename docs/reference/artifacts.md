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
| `{Project}_{Version}_bom.spdx.json` | `--spdx` / `--all`, or Export as SPDX 2.3 in the UI | SBOM (SPDX 2.3, converted from the CycloneDX output) |
| `{Project}_{Version}_bom.spdx3.json` | AI model and dataset scans (`--model`, `--model-file`, a dataset), unless `--no-spdx3` | the AI SBOM as an SPDX 3.0.1 document with the AI and Dataset profiles (JSON-LD). Fields come from the CycloneDX output, from fixed rules over it, or from the publisher's declaration (`--ai-declare`); nothing is estimated. Required fields SPDX gives no "unknown" value (who supplied and who made the model and data, release and build dates, the download address, the document's author) stay empty until declared, and the document says it is a draft until then. Base models are identified by id and licence only. The weights scope is carried as `bomlens:weights:scope` (`full`, `adapter`, `quantized`, `merged`) in a CycloneDX properties extension. Not an input for `--analyze` |
| `{Project}_{Version}_spdx3-check.json` / `.md` | with the SPDX 3.0.1 document | which field of each element came from the scan, from the declaration, or from nothing, which required fields are open, and what needs a decision by the publisher (personal data, safety risk, autonomy). `service.state` says whether the CycloneDX SBOM carries the declared service and model values: `none` (nothing declared, nothing in the SBOM), `applied` (the SBOM matches the declaration) or `pendingScan` (they differ; a new scan writes them). Guidance, not legal advice |
| `{Project}_{Version}_ai-declaration.template.json` | with the SPDX 3.0.1 document | an empty declaration for this scan: the fields a person fills, for the model, its datasets and the base models the scan found. Fill it and pass it back with `--ai-declare` |
| `{Project}_{Version}_ai-declaration.json` | `--ai-declare <file>` (the accepted file), or the declaration saved in the web UI | what the model's publisher declared. Like `_vex.json`, it is not removed by re-scanning the same project and version, and a re-scan applies it again. A file that names a dataset or base model the new scan does not have is refused, and the document stays a draft. A dataset entry can list `sources[]`: `{"ref": "huggingface:<id>", "relation": "extended"}` for a hub dataset (read from the hub at the next scan and judged with the dataset), or `{"name": "...", "license": "<hub licence tag or SPDX id>", "relation": "other"}` for one named in words (written to the SPDX 3.0.1 document only, marked as not verified; a licence that is not an SPDX id is kept in words). Data the hub does not hold takes sources named in words only. `model.license` (a hub licence tag or SPDX id) is the model's own licence: it fills the SPDX document when the scan read none or only `other` (as an SPDX expression only when it is a hub tag naming one SPDX licence, or a `LicenseRef-`), and a model described from the declaration alone carries it in its SBOM and is judged on it. A declaration can also describe the service the model runs in (`service`) and give the model's input and output kinds and regulatory values; see [The declared AI service](#the-declared-ai-service) |
| `{Project}_{Version}_component-versions.template.csv` | a firmware, root filesystem or binary scan that found components without a version | the names of those components in the `--component-versions` format (CSV, `name,version`) with the versions left empty. Fill it and pass it back with `--component-versions` |
| `{Project}_{Version}_NOTICE.txt` / `.html` | `--notice` / `--all` / risk report default | open-source notice |
| `{Project}_{Version}_NOTICE.pdf` | same as above, when a PDF renderer is built into the image (`--build-arg SBOM_PDF=true`) | the notice rendered to PDF; skipped with a log line otherwise |
| `{Project}_{Version}_security.json` / `.md` / `.html` | `--security` / `--all` / risk report default | Trivy security report |
| `{Project}_{Version}_risk-report.md` / `.html` | default (all modes) — omit with `--no-report` | open-source risk report |
| `{Project}_{Version}_conformance.json` / `.md` / `.html` | every scan that generates an SBOM, also with `--no-report` (which skips only the risk report); `--analyze` produces it too, since that is what it measures | format conformance report, with a regulatory crosswalk roll-up for every SBOM (EU CRA via BSI TR-03183-2, the US SBOM minimum elements of 2026 — reference only, no compliance determination). For an AI SBOM it also carries the G7 checks and, for each advisory element still missing, the CycloneDX fragment that would satisfy it. Names any best-effort post-process step that failed while the report was generated, so a pass is not read as proof every step ran cleanly; does not affect the pass/fail result or any individual check. See a [rendered example](../samples/aether-7b-5attn_conformance.html) |
| `{Project}_{Version}_ai-profile.json` / `.md` | AI SBOM (`--model`, or `--analyze` on an SBOM with a model component) | AI compliance profile: G7 rollup, the closable gaps with their reference links, license-flagged components, regulatory crosswalk, and the model risk assessment (`riskAssessment`: per-model ok/conditional/caution/review verdicts with conditions, reasons and the usage scenario; guidance, not legal advice). The same rollup opens the conformance HTML, so there is no separate HTML profile |
| `{Project}_{Version}_scancode.json` | `--deep-license` | raw scancode result |
| `{Project}_{Version}_files.json` | a source-having scan (a firmware scan always; other modes when `--deep-license` did not already produce `_scancode.json`) | ScanCode-shaped file-tree inventory (structure only, no licenses) backing the source-tree view |
| `{Project}_{Version}_source.json` | a source-having scan | snapshot of the scanned tree's file content, backing the file viewer (the scanned tree itself does not outlive the container) |
| `{Project}_{Version}_input.json` | `--analyze` | the supplier SBOM's own format, spec version, tool and authorship, captured before the CycloneDX conversion rewrites all of it |
| `{Project}_{Version}_yocto_vex.json` | a Yocto build (a build directory named directly, or `--analyze` on one) | how many CVEs the build already patched or judged not applicable — numbers not recoverable from the CycloneDX output or the security report, which list only what is still unresolved |
| `{Project}_{Version}_vex.json` | web UI only, saved when a judgement (affected / not affected / fixed / under investigation, with an optional note) is recorded against a CVE on the Vulnerabilities screen | the judgements recorded for this scan, keyed by component and CVE. Not produced by the CLI, and absent until the first judgement is saved for a given scan. Unlike every other file here, it is not regenerated by a scan and is not removed by re-scanning the same project and version: a judgement recorded against an earlier scan survives scanning it again |
| `{Project}_{Version}_vex.cdx.json` | web UI only, built when you press **Export VEX** on the Vulnerabilities screen (needs at least one recorded judgement) | the judgements from `_vex.json` as a standalone CycloneDX VEX document that another tool can read, at 1.7 when the scan's SBOM is 1.7 and at 1.6 otherwise. The four states map to CycloneDX `analysis.state` values (affected to `exploitable`, not affected to `not_affected`, fixed to `resolved`, under investigation to `in_triage`), and the note goes into `analysis.detail`. No `justification` is written, because the screen collects free text and CycloneDX allows only a fixed list. Each entry points at a copy of its component (name, version, PURL) held in the document itself, so the file stands alone. A judgement whose component is not in the SBOM is left out, and the screen says how many; firmware findings are the usual case, since their name and version come from the binary. It is rebuilt on every export and removed when the same project and version is scanned again, so export again afterwards |
| `{Project}_{Version}_vex_imported.json` | `--vex <file>` on the CLI, or **Import VEX** on the Vulnerabilities screen in the web UI, with a CycloneDX VEX document | the statements from a supplier's VEX document that apply to a component of this scan's SBOM, with the product the document describes. Kept apart from your own judgements in `_vex.json`: a received statement never overwrites one, and the screen labels the two separately. The four states are mapped from CycloneDX `analysis.state` (`exploitable` to affected, `not_affected` and `false_positive` to not affected, `resolved` and `resolved_with_pedigree` to fixed, `in_triage` to under investigation); any other state is ignored. A document whose product or version differs from the scanned SBOM's root is refused and nothing is saved. A successful import replaces this file; a refused or empty one leaves the previous file as it was. A statement that names the product itself is stored once, without a component, and applies to every finding of that CVE that has none of its own. Like `_vex.json`, it is not removed by re-scanning the same project and version |
| `{Project}_{Version}_reachability.cdx.json` | `--reachability` on a Go source or Go executable scan, when govulncheck could read the Go vulnerability database | govulncheck's judgement of each Go advisory against a component of the SBOM (same module and version), as a standalone CycloneDX 1.6 VEX document. `analysis.state` is `not_affected` when the affected code is not reached, with `justification` `code_not_present` when the module is required but no affected package is in the build, or `code_not_reachable` when the package is there but no affected function is called (or linked in an executable). It is `exploitable` when the code is reached. `analysis.detail` says which, with the call path or the symbol. `id` is the advisory's CVE when it has one, with its Go and other ids in `references`. The security report reads it: each finding it covers carries `bomlens:reachability` (`state`, `justification`, `detail`, `level`, `mode`) in `_security.json`, and the document has a `Reachability` summary |
| `{Project}_{Version}_vendored.cdx.json` | `--identify-vendored` on a source scan, with the opt-in SCANOSS image | vendored open-source components identified inside the source tree (SCANOSS) |
| `{Project}_{Version}_security_trivy.json` | with the security report, when another engine (grype, cve-bin-tool, Yocto) added results to it | Trivy's own result, kept apart before the merge into `_security.json` |
| `bomlens-events.jsonl` | `BOMLENS_EVENTS=file` | progress events, one JSON object per line. See [Engine contract](engine-contract.md#progress-events) |
| `bomlens-result.json` | always | the run's result manifest: how it ended, each step's outcome, and the role of each output file. See [Engine contract](engine-contract.md) |
| `{Project}_{Version}_security_epss.json` | whenever the security report is generated | EPSS score and KEV status per vulnerability (null/false when generated offline), used to prioritize the security report |
| `{Project}_{Version}_bom.json.sig` | `--sign` | cosign signature (with `--spdx`, a `_bom.spdx.json.sig` is produced too, and an AI scan adds `_bom.spdx3.json.sig`; a draft is signed too, since the signature says where the file came from, not that it is complete) |
| `{new}_model-diff.json` | `--diff <old.json> <new.json>` | AI-model drift report comparing two already-generated SBOMs: matched model verdict/license/hash changes, plus any component present in only one of the two files. Named after the newer input (`<new>_bom.json` → `<new>_model-diff.json`), not `{Project}_{Version}` — `--diff` takes no project or version of its own |

`{P}` = project name, `{V}` = version (special characters are normalized to `_`).

The conditions above are the CLI flags. In the web UI and the desktop app the same choices are the generation options on the New scan screen — Notice and Security report — and every file produced is listed in the Artifacts section of the results, downloadable per format or as one ZIP. SPDX is not a scan option there: the SBOM card in that section has an **Export as SPDX 2.3** button that converts the finished BOM whenever you need it, and the converted file joins the artifact list and the ZIP. The UI has no signing, so an SPDX exported that way is unsigned; use `--spdx --sign` in the CLI when you need a signature. See [Web UI and desktop app](ui.md).

## The declared AI service

An AI declaration (`--ai-declare`, or the declaration saved in the web UI) can describe the service the model runs in with a top-level `service` object, and give the model a few values a scan cannot read. A `service` is accepted only when the document describes a model, not a dataset, and one that holds no value at all counts as not declared. The [AI model guide](../guides/ai-model.md#the-service-a-model-runs-in) explains what these are for.

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

## Dependency-graph completeness

A generated SBOM carries a `compositions[0].aggregate` entry stating how complete its dependency graph is:

| Value | Meaning |
|-------|---------|
| `complete` | The scan found positive evidence the graph was fully resolved: an ecosystem's lock/resolve step succeeded, or a lockfile was already committed, plus at least one dependency edge. |
| `incomplete` | A known failure affected the scan: the syft fallback ran instead of cdxgen, a firmware package-cataloging step failed, or a Poetry project with no `poetry.lock` was converted only in part or its dependencies could not be resolved. |
| `unknown` | Nothing in the SBOM confirms the graph is complete. This is the default whenever there is no positive evidence either way, for example an image/rootfs/firmware/binary scan (syft alone cannot see inter-package dependencies), an AI-model, dataset or merged SBOM, or a Maven source scan (no reliable signal tells a resolved graph apart from a degraded one). `unknown` is not a defect; it means the tool found no basis to judge, not that something went wrong. |

An analyzed supplier SBOM's own `compositions` declaration, if it has one, is never overwritten.

The conformance report's transitive-dependency check notes the declared value in its detail text (e.g. "12 edge(s), declared complete"), without changing the check's pass/fail status.

A preprocessing label that ran, or was satisfied by an already-committed lockfile, is recorded in the `bomlens:prep-step-applied` property regardless of success or failure; `bomlens:pipeline-step-failed` records only the failures. `aggregate` above is decided from both together.
