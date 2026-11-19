// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Which build tool reads a folder that has both a Maven and a Gradle build file
 * (the CLI's --build-tool). Pure helpers: the form shows the choice only when
 * /project-info reports both files, and sends build_tool only then.
 */

export type BuildTool = "auto" | "maven" | "gradle";

export const BUILD_TOOLS: readonly BuildTool[] = ["auto", "maven", "gradle"];

export const BUILD_TOOL_LABEL_KEY: Record<BuildTool, string> = {
  auto: "options.buildToolAuto",
  maven: "options.buildToolMaven",
  gradle: "options.buildToolGradle",
};

/** The files /project-info found directly in the folder. */
export interface BuildToolsFound {
  maven?: boolean;
  gradle?: boolean;
}

/** Narrow anything (a saved scan config, a form value) to a known choice. */
export function normalizeBuildTool(v: unknown): BuildTool {
  return v === "maven" || v === "gradle" ? v : "auto";
}

/** The choice only matters when both build files are there. */
export function hasBothBuildTools(found: BuildToolsFound | null | undefined): boolean {
  return found?.maven === true && found?.gradle === true;
}

/** The value to send: "auto" unless the choice is shown and set. */
export function buildToolToSend(shown: boolean, choice: BuildTool): BuildTool {
  return shown ? choice : "auto";
}

/** The tool a finished scan used, when its SBOM says so (maven or gradle). */
export function builtWith(choice: string | null | undefined): "maven" | "gradle" | null {
  return choice === "maven" || choice === "gradle" ? choice : null;
}
