// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Human-readable labels for the best-effort post-process step ids docker/lib/
 * pipeline-step.sh stamps onto a failed SBOM (bomlens:pipeline-step-failed).
 * Every id run_optional_step is called with in entrypoint.sh should have an
 * entry here; a step id with no entry still renders (the caller falls back to
 * showing the raw id), so a new step added to the pipeline before this map is
 * updated never breaks the display, it is just untranslated.
 */
const STEP_LABEL_KEY: Record<string, string> = {
  "enrich-aibom": "pipelineSteps.enrichAibom",
  "verify-weights": "pipelineSteps.verifyWeights",
  "model-security": "pipelineSteps.modelSecurity",
  conformance: "pipelineSteps.conformance",
  "describe-input": "pipelineSteps.describeInput",
  "suggest-vendored": "pipelineSteps.suggestVendored",
  docmeta: "pipelineSteps.docmeta",
  normalize: "pipelineSteps.normalize",
  "enrich-cpe": "pipelineSteps.enrichCpe",
  "enrich-os-context": "pipelineSteps.enrichOsContext",
  "enrich-maven-cpe": "pipelineSteps.enrichMavenCpe",
  "enrich-github-cpe": "pipelineSteps.enrichGithubCpe",
  "enrich-interpreter-cpe": "pipelineSteps.enrichInterpreterCpe",
  "enrich-eol": "pipelineSteps.enrichEol",
  "enrich-malicious": "pipelineSteps.enrichMalicious",
  "enrich-staleness": "pipelineSteps.enrichStaleness",
  "assess-ai-risk": "pipelineSteps.assessAiRisk",
  "source-file-tree": "pipelineSteps.sourceFileTree",
  "source-snapshot": "pipelineSteps.sourceSnapshot",
  "generate-notice": "pipelineSteps.generateNotice",
  "scan-security": "pipelineSteps.scanSecurity",
  "generate-risk-report": "pipelineSteps.generateRiskReport",
  "firmware-packages": "pipelineSteps.firmwarePackages",
  "firmware-extra-roots": "pipelineSteps.firmwareExtraRoots",
  "cargo-lockfile": "pipelineSteps.cargoLockfile",
  "go-mod-tidy": "pipelineSteps.goModTidy",
  "bundle-lock": "pipelineSteps.bundleLock",
  "gradle-dependencies": "pipelineSteps.gradleDependencies",
  "android-release-classpath": "pipelineSteps.androidReleaseClasspath",
  "swift-package-resolve": "pipelineSteps.swiftPackageResolve",
  "npm-production-set": "pipelineSteps.npmProductionSet",
  "pip-install": "pipelineSteps.pipInstall",
};

/** The i18n key for a pipeline step id, or undefined for one with no label
 *  yet (the caller shows the raw id instead of translating). */
export function pipelineStepLabelKey(step: string): string | undefined {
  return STEP_LABEL_KEY[step];
}
