---
description: BomLens is a local-first SBOM generator and open-source risk assessor. From source code, containers, binaries, firmware, or an SBOM you received, it produces a CycloneDX SBOM, an open-source notice, and a security and license risk report — CLI or web UI, no SaaS.
hide:
  - toc
---

# Generate SBOMs and assess open-source risk, all locally

A local-first SBOM generator and open-source risk assessor for a single project — no SaaS, no account. From source code, a container image, a binary, firmware, an SBOM you received, or a HuggingFace AI model, it produces an [SBOM](concepts/what-is-sbom.md) (CycloneDX 1.6), an open-source notice, and a security risk report in one run. For an AI model it builds a CycloneDX ML-BOM and checks it against the [G7 minimum elements for AI](guides/ai-model.md), whose clusters overlap with the EU AI Act's Annex IV.

[Get started](start/first-scan.md){ .md-button .md-button--primary }
[Download for Windows (.exe)](https://github.com/sktelecom/bomlens/releases/latest/download/BomLens-Setup.exe){ .md-button }

Prefer no command line? Download the installer and double-click it. A Docker engine is required; the free [Rancher Desktop](https://rancherdesktop.io/) works well on Windows. A step-by-step walkthrough is in the [no-CLI quick start](start/no-cli.md).

![BomLens web UI showing a scan result: the Overview with counts and a severity/license summary, the Components table with filters, the Vulnerabilities list, the Dependencies as a graph and tree, and the Licenses section](images/web-ui-demo.gif){ .home-shot }

## Where to go next

<div class="grid cards" markdown>

-   :material-rocket-launch: __Getting started__

    Install through your first SBOM (desktop app, web UI, and CLI).

    [:octicons-arrow-right-24: Getting started](start/first-scan.md)

-   :material-cursor-default-click: __No-CLI quick start__

    Make an SBOM and a notice with the desktop app — no command line.

    [:octicons-arrow-right-24: Quick start](start/no-cli.md)

-   :material-format-list-bulleted: __Input scenarios__

    GitHub URL, ZIP, local source, an existing SBOM, firmware.

    [:octicons-arrow-right-24: Scenarios guide](guides/by-input.md)

-   :material-file-document-check: __Supplier SBOM__

    Validate an SBOM you received and issue a risk report.

    [:octicons-arrow-right-24: Supplier SBOM](guides/supplier-sbom.md)

-   :material-robot-outline: __AI model SBOM__

    An ML-BOM for a HuggingFace model, checked against the G7 minimum elements and mapped to the EU AI Act.

    [:octicons-arrow-right-24: AI model SBOM](guides/ai-model.md)

-   :material-shield-check: __Notice & security report__

    Generate and read the outputs, plus using the web UI.

    [:octicons-arrow-right-24: Reports](guides/reports.md)

-   :material-cog: __CLI reference__

    Every option, analysis modes, CI/CD.

    [:octicons-arrow-right-24: CLI reference](reference/cli.md)

</div>
