// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { explainFailure } from "./failureExplain";

describe("explainFailure", () => {
  it("uses the server's classification first", () => {
    expect(explainFailure([], "x", "run.errorGitNotFoundOrPrivate").causeKey).toBe("run.failGitPrivateCause");
    expect(explainFailure([], "x", "run.errorGitNetwork").fixKey).toBe("run.failGitNetworkFix");
  });

  it("names the tool and runtime behind exit code 126", () => {
    const e = explainFailure(["[1/2] cdxgen", "node: cannot execute binary file", "cdxgen exited with code 126"], null, null);
    expect(e.causeKey).toBe("run.fail126Cause");
    expect(e.vars).toEqual({ tool: "cdxgen", runtime: "Node.js" });
    expect(e.recognised).toBe(true);
  });

  it("leaves tool and runtime empty when the log names none", () => {
    expect(explainFailure([], "Exec format error", null).vars).toEqual({ tool: "", runtime: "" });
  });

  it("recognises an internal error", () => {
    expect(explainFailure(["Traceback (most recent call last):"], null, null).causeKey).toBe("run.failInternalCause");
  });

  it("falls back to a generic cause and says it is unrecognised", () => {
    const e = explainFailure(["boom"], "boom", null);
    expect(e.causeKey).toBe("run.failGenericCause");
    expect(e.recognised).toBe(false);
  });

  it("is not fooled by an IOException warning in an ordinary build log", () => {
    const e = explainFailure(["WARN java.io.IOException: retrying download", "[1/2] cdxgen", "build failed"], "build failed", null);
    expect(e.causeKey).toBe("run.failGenericCause");
  });

  it("names the tool that failed with 126, not the first tool in the log", () => {
    const logs = [
      "[1/2] cdxgen run",
      "node: resolved 120 packages",
      ...Array.from({ length: 30 }, (_, i) => `step ${i}`),
      "[security] starting trivy",
      "trivy: cannot execute binary file",
      "trivy exited with code 126",
    ];
    const e = explainFailure(logs, null, null);
    expect(e.causeKey).toBe("run.fail126Cause");
    expect(e.vars).toEqual({ tool: "trivy", runtime: "" });
  });

  it("uses the last exit line, not an earlier one", () => {
    expect(explainFailure(["syft exited with code 126", "recovered", "step", "step", "step", "step", "grype exited with code 1"], null, null).causeKey).toBe("run.failGenericCause");
  });

  it("shows an unknown server key as its own cause", () => {
    const e = explainFailure([], "x", "run.errorSomethingNew");
    expect(e.causeKey).toBe("run.errorSomethingNew");
    expect(e.recognised).toBe(false);
  });
});
