# SBOM Conformance — FlaskDataService

- Generated: 2026-07-28T00:24:40Z
- Format: CycloneDX
- Result: **PASS** (mandatory failures: 0, warnings: 2, needs review: 1)

## Regulatory crosswalk

| Framework | Present | Gap | Review | Total |
|-----------|:-------:|:---:|:------:|:-----:|
| BSI TR-03183-2 — SBOM data fields (EU CRA) | 11 | 2 | 1 | 14 |
| US SBOM minimum elements | 8 | 0 | 0 | 8 |

- BSI TR-03183-2 — SBOM data fields (EU CRA) — Regulation (EU) 2024/2847 Annex I Part II(1); BSI TR-03183-2 v2.1.0 (2025-08-20)
- US SBOM minimum elements — Executive Order 14028 §4; NTIA "The Minimum Elements For a Software Bill of Materials" (2021-07-12)

BomLens does not certify or determine compliance with the EU AI Act, the Korean AI Framework Act, the EU Cyber Resilience Act, or any other regulation. This crosswalk covers only the documentation elements an SBOM can carry; obligations that an SBOM cannot express — bias and fairness assessment, risk management, human oversight — are out of its scope and must be met through separate documents. It makes documentation gaps visible so a person can prepare; interpreting it against a specific product's legal obligations is a person's job.

## SBOM format requirements

What the SBOM itself has to carry. The same bar applies however the SBOM was produced, and a single mandatory failure makes the overall result a failure.

| Status | Requirement | Required | Detail | Evidence / how |
|--------|-------------|:--------:|--------|----------|
| ✅ | Spec version (CycloneDX 1.3/1.4/1.5/1.6) — BSI TR-03183-2 Section 4 · NTIA Automation Support | yes | CycloneDX 1.6 |  |
| ✅ | Timestamp (metadata.timestamp) — BSI TR-03183-2 Section 5.2.1 · NTIA Timestamp | yes | 2026-07-28T00:10:55Z |  |
| ✅ | Tool info (metadata.tools) — BSI TR-03183-2 Section 5.2.1 · NTIA Author of SBOM Data | yes | 1 tool(s) |  |
| ✅ | Top-level component name+version — BSI TR-03183-2 Section 5.1 | yes | FlaskDataService@3.2.0 |  |
| ✅ | Component name+version coverage (100%) — BSI TR-03183-2 Section 5.2.2 · NTIA Component Name / Version | yes | 39/39 |  |
| ✅ | PURL coverage (>= 90%) — BSI TR-03183-2 Section 5.2.4 · NTIA Other Unique Identifiers | yes | 100% (39/39) |  |
| ✅ | Traceable PURL (no pkg:generic, advisory) | no | 0 untraceable |  |
| ✅ | PURL syntax (pkg:type/name@version) — NTIA Other Unique Identifiers | yes | 0 malformed |  |
| ✅ | Transitive dependencies (graph edges) — BSI TR-03183-2 Section 5.1; 5.2.2 · NTIA Dependency Relationship | yes | 52 edge(s) |  |
| ✅ | License coverage (>= 80%, recommended) — BSI TR-03183-2 Section 5.2.2 | no | 97% (38/39) |  |
| ✅ | Hash coverage (>= 50%, recommended) — BSI TR-03183-2 Section 5.2.2 | no | 100% (39/39) |  |
| ⚠️ | SHA-512 checksum coverage (>= 80%, recommended) — BSI TR-03183-2 Section 5.2.2 | no | 0% (0/39) |  |
| ✅ | Component creator coverage (>= 80%, recommended) — BSI TR-03183-2 Section 5.2.2 · NTIA Supplier Name | no | 82% (32/39) |  |
| ⚠️ | Component filename coverage (>= 80%, recommended) — BSI TR-03183-2 Section 5.2.2 | no | 0% (0/39) |  |
| ✅ | Source or distribution URI coverage (>= 80%, recommended) — BSI TR-03183-2 Section 5.2.4 | no | 100% (39/39) |  |
| 🔍 | Delivered-file properties (executable/archive/structured) — BSI TR-03183-2 Section 5.2.2 | no | requires inspecting the delivered files (no automated source in this scan) |  |

