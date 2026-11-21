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
  "resolve-purl": "pipelineSteps.resolvePurl",
  "license-registry": "pipelineSteps.licenseRegistry",
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
  "declared-sources": "pipelineSteps.declaredSources",
  "declared-service": "pipelineSteps.declaredService",
  "assess-ai-risk": "pipelineSteps.assessAiRisk",
  "source-file-tree": "pipelineSteps.sourceFileTree",
  "source-snapshot": "pipelineSteps.sourceSnapshot",
  "generate-notice": "pipelineSteps.generateNotice",
  "reachability": "pipelineSteps.reachability",
  "scan-security": "pipelineSteps.scanSecurity",
  "generate-risk-report": "pipelineSteps.generateRiskReport",
  "firmware-packages": "pipelineSteps.firmwarePackages",
  "firmware-extra-roots": "pipelineSteps.firmwareExtraRoots",
  "cargo-lockfile": "pipelineSteps.cargoLockfile",
  "go-mod-tidy": "pipelineSteps.goModTidy",
  "bundle-lock": "pipelineSteps.bundleLock",
  "gradle-dependencies": "pipelineSteps.gradleDependencies",
  "gradle-packages": "pipelineSteps.gradlePackages",
  "gradle-wrapper-jdk": "pipelineSteps.gradleWrapperJdk",
  "maven-dependency-tree": "pipelineSteps.mavenDependencyTree",
  "maven-dependency-jars": "pipelineSteps.mavenDependencyJars",
  "maven-dependency-resolve": "pipelineSteps.mavenDependencyResolve",
  "android-release-classpath": "pipelineSteps.androidReleaseClasspath",
  "swift-package-resolve": "pipelineSteps.swiftPackageResolve",
  "npm-production-set": "pipelineSteps.npmProductionSet",
  "npm-installed-lock": "pipelineSteps.npmInstalledLock",
  "pnpm-installed-lock": "pipelineSteps.pnpmInstalledLock",
  "npm-registry:tls-trust": "pipelineSteps.npmRegistryTlsTrust",
  "npm-registry:network": "pipelineSteps.npmRegistryNetwork",
  "pip-install": "pipelineSteps.pipInstall",
  "poetry-graph": "pipelineSteps.poetryGraph",
  "cargo-workspace-metadata": "pipelineSteps.cargoWorkspaceMetadata",
  "cargo-license-metadata": "pipelineSteps.cargoLicenseMetadata",
  "license-fetch": "pipelineSteps.licenseFetch",
  "ai-usage": "pipelineSteps.aiUsage",
  "resolve-models": "pipelineSteps.resolveModels",
  "composer-install": "pipelineSteps.composerInstall",
  "pnpm-workspace-tree": "pipelineSteps.pnpmWorkspaceTree",
  "enrich-distro-supplier": "pipelineSteps.enrichDistroSupplier",
  "component-versions": "pipelineSteps.componentVersions",
  "upstream-purl": "pipelineSteps.upstreamPurl",
  "match-cpe": "pipelineSteps.matchCpe",
};

/** The i18n key for a pipeline step id, or undefined for one with no label
 *  yet (the caller shows the raw id instead of translating). */
export function pipelineStepLabelKey(step: string): string | undefined {
  return STEP_LABEL_KEY[step];
}

/**
 * Failed steps that leave no data missing. `license-fetch` records that the
 * package registries' license lookup was skipped: licenses still come from lock
 * files and package metadata, and the completeness grade does not count it
 * (docker/lib/completeness-reasons.json resolutionSteps).
 */
const NOTE_ONLY_STEPS: ReadonlySet<string> = new Set(["license-fetch"]);

export interface FailedStepSplit {
  /** Steps whose failure may leave data incomplete. */
  incomplete: string[];
  /** True when the registry license lookup was skipped. */
  licenseLookupSkipped: boolean;
}

/** Splits bomlens:pipeline-step-failed into steps that may leave data
 *  incomplete and the skipped license lookup, which is only a note. */
export function splitFailedSteps(steps: readonly string[] | undefined): FailedStepSplit {
  const list = steps ?? [];
  return {
    incomplete: list.filter((s) => !NOTE_ONLY_STEPS.has(s)),
    licenseLookupSkipped: list.includes("license-fetch"),
  };
}

/** Whether the failed steps (plus `more` past the listed cap) may leave data incomplete. */
export function hasIncompleteSteps(steps: readonly string[] | undefined, more = 0): boolean {
  return more > 0 || splitFailedSteps(steps).incomplete.length > 0;
}

/**
 * What a running scan is doing right now, read from the live log. The scanner
 * prefixes the lines of each stage with a marker; the last marker seen is the
 * current step. The server adds two of its own before the scanner starts (the
 * writable copy of the folder and the image download).
 */
const LIVE_STEPS: ReadonlyArray<{ id: string; labelKey: string; match: RegExp }> = [
  { id: "copy", labelKey: "run.live.copy", match: /Preparing a writable copy/i },
  { id: "pull", labelKey: "run.live.pull", match: /^\[ui\] pulling/i },
  { id: "buildPrep", labelKey: "run.live.buildPrep", match: /\[build-prep\]/i },
  { id: "generate", labelKey: "run.live.generate", match: /\[1\/2\]/ },
  { id: "post", labelKey: "run.live.post", match: /\[2\/2\]/ },
  { id: "normalize", labelKey: "run.live.normalize", match: /\[normalize\]/i },
  { id: "notice", labelKey: "run.live.notice", match: /\[notice\]/i },
  { id: "license", labelKey: "run.live.license", match: /\[(?:license|os-licenses)\]/i },
  { id: "security", labelKey: "run.live.security", match: /\[(?:security|vex)\]/i },
  { id: "deepCve", labelKey: "run.live.deepCve", match: /\[nvd-cpe\]/i },
  { id: "reachability", labelKey: "run.live.reachability", match: /\[reachability\]/i },
  { id: "risk", labelKey: "run.live.risk", match: /\[risk\]/i },
  { id: "analyze", labelKey: "run.live.analyze", match: /\[analyze\]/i },
];

export interface LiveStep {
  id: string;
  labelKey: string;
}

/** The step the newest recognisable log line belongs to, or null before any. */
export function currentLiveStep(logs: readonly string[]): LiveStep | null {
  for (let i = logs.length - 1; i >= 0; i--) {
    const line = logs[i];
    for (const step of LIVE_STEPS) {
      if (step.match.test(line)) return { id: step.id, labelKey: step.labelKey };
    }
  }
  return null;
}

/** A length of time as m:ss, or h:mm:ss from an hour on (no unit words, so the
 *  same text reads in every language). */
export function formatElapsed(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds));
  const sec = String(s % 60).padStart(2, "0");
  const min = Math.floor(s / 60);
  if (min < 60) return `${min}:${sec}`;
  return `${Math.floor(min / 60)}:${String(min % 60).padStart(2, "0")}:${sec}`;
}

/** Seconds without a new log line after which the screen says the quiet is normal. */
export const QUIET_AFTER_SECONDS = 60;
