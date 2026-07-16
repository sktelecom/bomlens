---
description: How to read and interpret the open-source notice, the security report, and the open-source risk report that BomLens produces.
---

# What the reports mean

This page explains how to read and interpret BomLens reports after a scan. For how to produce them, see [Generating reports](../guides/reports.md).

## What the notice handles

The open-source notice (NOTICE) groups components by license. Beyond that grouping, it also handles the following.

- It normalizes license names to SPDX identifiers. For example, "Apache License, version 2.0" is normalized to `Apache-2.0`. Entries that were duplicated because the same license was written differently are merged into one.
- If the SBOM has a copyright value, it is shown per component.
- The full SPDX standard texts of 21 major open-source licenses (`Apache-2.0`, `MIT`, `BSD-3-Clause`, the `GPL`/`LGPL` families, and so on) are bundled at the end of the notice. This satisfies the obligation of licenses that require the full text, without separate collection. The bundled originals are in `docker/lib/licenses/*.txt`.

## Priority signals (CVSS, EPSS, CISA KEV)

Severity alone makes it hard to decide what to fix first. To help with that, the security report shows three more signals beyond severity. The Markdown and HTML table columns are `Severity | KEV | CVSS | EPSS | CVE | Package | Installed | Fixed`.

- **CVSS** — the technical severity score of the vulnerability (0–10). The V3 score is used first, falling back to V2 if absent.
- **EPSS** — the probability of real-world exploitation within the next 30 days (0–1). Queried from FIRST.org; a higher score means a greater chance of being used in an attack.
- **CISA KEV** — whether it is on the "known exploited vulnerabilities" list maintained by the US CISA. If it is, the HTML report marks it with a ⚠️ badge.

The table puts KEV-listed items at the top, then sorts by severity, and finally by EPSS descending. Working top-down naturally addresses the highest-risk items first.

EPSS and KEV require external API lookups. On an air-gapped network, set `SECURITY_ENRICH=false` to omit the two columns and still generate the rest of the report.

## Component end-of-life (EOL)

BomLens also flags whether each component's release cycle has reached its upstream end-of-life. This is a supply-chain risk separate from CVEs: a runtime or framework past its support date gets no more upstream security fixes, so a Critical or High reported later has no patch to apply.

- The dates come from a snapshot of endoflife.date bundled into the scanner image, so the check runs offline with no network call and works air-gapped. The source and snapshot date are recorded on each flagged component (`bomlens:eol:source`).
- Coverage follows endoflife.date, which tracks runtimes, major frameworks, operating systems and databases (spring-boot, express, django, nodejs, python, php, nginx, openssl, ubuntu, debian, and so on). Most smaller libraries are not tracked, and a component with no mapping is left unknown rather than guessed.
- In the web UI, the Overview shows an "End of life" count tile, with the components that are also vulnerable highlighted in the risk colour — an EOL component gets no upstream patch for its CVEs, so that is the set to act on. The Components table adds an "End of life" badge, with the EOL date where known, and an "End of life" filter.
- It is on by default and adds no delay because it is offline. To turn it off, set `ENRICH_EOL=false`. AI/ML model scans skip it, since they have no runtime or framework components.

## Version currency

Sitting on a supported release cycle is not the same as running its latest version, so BomLens also flags whether a component has fallen behind. This works in two layers.

- The offline layer is on by default, alongside the EOL check. The same endoflife.date snapshot records the latest patch of each release cycle, so BomLens can tell offline whether the installed version trails the newest patch within its own cycle. That is a safe, in-cycle upgrade found with no network call, exactly like the EOL check. A component that is behind carries `bomlens:currency:outdated=true`, with the target patch in `bomlens:currency:latestPatch`. It runs inside the EOL step, so `ENRICH_EOL=false` turns it off as well, and AI/ML model scans skip it.
- The deps.dev layer is opt-in. Set `STALENESS_ENRICH=true` to look each component up on deps.dev, Google's public package metadata, and record the absolute newest version (`bomlens:staleness:latest`), how many releases the installed one is behind (`bomlens:staleness:releasesBehind`), and when the newest version shipped (`bomlens:staleness:lastReleased`). This makes one network call per component, so it trades the scan's offline determinism for freshness. It does not suit an air-gapped run, which is why it is off by default. It is best-effort and time-bounded, so a failed lookup never aborts the scan. The supported ecosystems are npm, PyPI, Maven, Go, Cargo, NuGet and RubyGems. Whether a project is still actively maintained is not part of this release; it is planned for a later release.
- In the web UI, the Overview adds a count tile for components behind their latest version, and the Components table marks a component that is not on its latest version and adds an "Outdated" filter. With the deps.dev layer on, each such component also shows how many releases it is behind and its last-release date.

## Interpreting results & follow-up

| Severity | Meaning | Recommended action |
|----------|---------|--------------------|
| **Critical** | immediately exploitable, severe | upgrade to the `Fixed` version as the top priority |
| **High** | high risk | plan a patch in the short term |
| **Medium / Low** | limited impact | handle during regular maintenance |
| **Unknown** | severity not assessed | check the CVE directly and classify |

- If the report's `Fixed` column has a version, raising the dependency to that version or higher resolves it. This is the fastest first response.
- CI gate example. Fail the build if there is even one Critical:
  ```bash
  crit=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' *_security.json)
  [ "$crit" -gt 0 ] && { echo "${crit} Critical vulnerabilities"; exit 1; }
  ```
- Triage — judging false positives (no real impact) and approving exceptions — and history management are beyond the scope of BomLens. Upload the SBOM to a vulnerability management system (Dependency-Track, TRUSCA, etc.) to handle it.

## The open-source risk report

The open-source risk report aggregates vulnerabilities by severity with recommended response deadlines (Critical 7 days, High 30 days). It includes a license summary, and for a supplier SBOM it adds the format conformance result.

The license summary also classifies components by copyleft strength, with the same rules the web UI uses. Each component in the SBOM carries a `bomlens:licenseClass` property holding one of `network-copyleft`, `strong-copyleft`, `weak-copyleft`, `permissive` or `uncategorized`, and the report shows a per-class count plus the components that drive the copyleft exposure. A license the tool does not recognize is never assumed permissive; it stays `uncategorized` for a human to review.

## Related

- [Generating reports](../guides/reports.md)
- [Artifacts reference](../reference/artifacts.md)
- [How BomLens works](architecture.md)
