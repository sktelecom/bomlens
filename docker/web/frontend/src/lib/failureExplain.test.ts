// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { explainFailure, failureKeyForCode } from "./failureExplain";

describe("unreadable supplier SBOM", () => {
  it("maps the upload codes to wording that blames the file", () => {
    expect(failureKeyForCode("SBOM_FILE_EMPTY")).toBe("run.errorSbomEmpty");
    expect(explainFailure([], "x", failureKeyForCode("SBOM_JSON_TRUNCATED")).causeKey).toBe("source.uploadErrorSbomTruncated");
    const e = explainFailure([], "x", failureKeyForCode("SBOM_NOT_RECOGNIZED"));
    expect(e.causeKey).toBe("source.uploadErrorSbomNotRecognized");
    expect(e.fixKey).toBe("run.failSbomFileFix");
    expect(e.recognised).toBe(true);
  });
});

describe("image failures", () => {
  const head = "[ERROR] syft could not read the image nosuch/x:9.9: it does not exist, or the registry needs credentials.";

  it("tells a missing image from a refused login", () => {
    expect(explainFailure([], `${head}\nMANIFEST_UNKNOWN: manifest unknown`, null).causeKey).toBe("run.failImageMissingCause");
    expect(explainFailure([], `${head}\nDENIED: requested access to the resource is denied`, null).causeKey).toBe("run.failImageAuthCause");
    expect(explainFailure([], `${head}\nUNAUTHORIZED: authentication required`, null).causeKey).toBe("run.failImageAuthCause");
  });

  it("names an unresolvable registry host", () => {
    const e = explainFailure([], `${head}\ndial tcp: lookup registry.example.com: no such host`, null);
    expect(e.causeKey).toBe("run.failImageHostCause");
    expect(e.fixKey).toBe("run.failImageHostFix");
  });

  it("does not read an unrelated denied in the log as an image failure", () => {
    expect(explainFailure(["permission denied: /tmp/x"], "build failed", null).causeKey).toBe("run.failGenericCause");
  });

  it("falls back to the generic cause when the image message says nothing more", () => {
    expect(explainFailure([], head, null).causeKey).toBe("run.failGenericCause");
  });
});

describe("explainFailure", () => {
  it("uses the server's classification first", () => {
    expect(explainFailure([], "x", "run.errorGitNotFoundOrPrivate").causeKey).toBe("run.failGitPrivateCause");
    expect(explainFailure([], "x", "run.errorGitNetwork").fixKey).toBe("run.failGitNetworkFix");
    expect(explainFailure([], "x", failureKeyForCode("SCAN_TARGET_NOT_VISIBLE")).causeKey).toBe("run.failTargetHiddenCause");
    expect(failureKeyForCode("OTHER")).toBeUndefined();
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

describe("image failures summarised by the server", () => {
  it("reads the one-sentence messages the same way as the raw ones", () => {
    const base = "Could not read the image acme/app:1.0: ";
    expect(explainFailure([], base + "access was denied. The registry gives the same answer.", null).causeKey).toBe("run.failImageAuthCause");
    expect(explainFailure([], base + "no image has that name or tag.", null).causeKey).toBe("run.failImageMissingCause");
    expect(explainFailure([], base + "the registry host could not be found.", null).causeKey).toBe("run.failImageHostCause");
  });
});

describe("valid JSON that is not an SBOM", () => {
  it("is explained as a file problem", () => {
    const e = explainFailure([], "[ERROR] could not convert supplier SBOM to CycloneDX.", null);
    expect(e.causeKey).toBe("run.failSbomNotSbomCause");
    expect(e.fixKey).toBe("run.failSbomFileFix");
    expect(e.recognised).toBe(true);
  });
});
