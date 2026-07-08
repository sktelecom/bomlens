---
description: What an SBOM (Software Bill of Materials) is, why open-source notices and vulnerability response depend on one, and what CycloneDX, PURL, and ML-BOM mean — a five-minute primer before your first scan.
---

# What is an SBOM

An SBOM (Software Bill of Materials) is a list of the components inside a piece of software: every open-source library and package it ships with, each with its name, version, and license. It plays the same role for software that a list of ingredients plays for packaged food — you can see what is inside without taking the product apart.

Most software today is assembled largely from open source. A typical web application directly declares a few dozen packages, and those pull in hundreds more. Nobody can keep that inventory in their head, so the SBOM is generated from the project by a tool — that is what BomLens does.

## Why you need one

Two everyday jobs depend on knowing exactly what is inside your software.

**Meeting license obligations.** Most open-source licenses (MIT, Apache-2.0, BSD, and others) require you to ship a copyright notice and the license text along with your product. To write that open-source notice you first need the component list — the SBOM. BomLens generates the notice from the SBOM in the same run.

**Responding to vulnerabilities.** When a vulnerability is announced in a library, the first question is "do we ship it, and in which version?". With an SBOM per product, that answer is a lookup instead of an investigation. This is also why customers and regulators increasingly ask suppliers to hand over an SBOM with each delivery.

## Terms you will meet in the results

**CycloneDX** is the standard file format BomLens writes its SBOMs in — a JSON document defined by the [OWASP CycloneDX](https://cyclonedx.org/) project (version 1.6). Because the format is standard, the file you generate can be read by other tools: vulnerability trackers, policy checkers, or a customer's own tooling.

**PURL** (Package URL) is the identifier each component carries inside the SBOM, such as `pkg:npm/express@4.18.2`. It names the ecosystem (npm, Maven, PyPI, and so on), the package, and the exact version in one string, so every tool that reads the SBOM agrees on which component is meant.

**ML-BOM** is the same idea applied to an AI model: a CycloneDX document listing what a model is made of — its datasets, base model, and license. BomLens generates one from a HuggingFace model id; see the [AI model guide](../guides/ai-model.md).

## Next steps

You do not need to remember any of this to run a scan. Pick your path:

- No command line: the [no-CLI quick start](../start/no-cli.md) goes from install to an open-source notice in clicks.
- Developer setup, web UI and CLI: [Getting started](../start/first-scan.md).

---

> **Related**: [Getting started](../start/first-scan.md) | [No-CLI quick start](../start/no-cli.md) | [Artifacts](../reference/artifacts.md)
