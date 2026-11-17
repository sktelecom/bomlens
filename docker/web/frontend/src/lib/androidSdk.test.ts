// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  androidSdkNeed,
  canReplayScan,
  canRetryBuild,
  failureReason,
  firstStage,
  isAndroidSdkMissing,
  manualBuildCommand,
  releaseTag,
} from "./androidSdk";

const EVENT = {
  code: "ANDROID_SDK_IMAGE_MISSING",
  consentRequired: true,
  api: 34,
  image: "bomlens-android-sdk34",
  termsUrl: "https://developer.android.com/studio/terms",
  buildAvailable: true,
};

describe("androidSdkNeed", () => {
  it("reads the scan error event", () => {
    expect(androidSdkNeed(EVENT)).toEqual({
      api: 34,
      image: "bomlens-android-sdk34",
      termsUrl: "https://developer.android.com/studio/terms",
      consentRequired: true,
      buildAvailable: true,
    });
  });

  it("ignores other errors and incomplete events", () => {
    expect(androidSdkNeed(undefined)).toBeNull();
    expect(androidSdkNeed({ code: "OTHER" })).toBeNull();
    expect(androidSdkNeed({ code: EVENT.code, image: "x" })).toBeNull();
    expect(isAndroidSdkMissing(undefined)).toBe(false);
  });

  it("asks for consent when the server did not say", () => {
    const need = androidSdkNeed({ code: EVENT.code, api: 34, image: "i" });
    expect(need?.consentRequired).toBe(true);
    expect(need?.termsUrl).toContain("developer.android.com");
  });
});

describe("firstStage", () => {
  const need = androidSdkNeed(EVENT)!;
  it("asks first when the terms are not accepted", () => {
    expect(firstStage(need, true)).toBe("consent");
  });
  it("asks for a start click when the terms are on file", () => {
    expect(firstStage({ ...need, consentRequired: false }, true)).toBe("confirm");
  });
  it("only explains when the server cannot build", () => {
    expect(firstStage({ ...need, buildAvailable: false }, true)).toBe("manual");
    expect(firstStage(need, false)).toBe("manual");
    expect(firstStage(need, undefined)).toBe("consent");
  });
});

describe("helpers", () => {
  it("pins the manual command to the release tag", () => {
    expect(manualBuildCommand(34, "bomlens-android-sdk34", "1.15.0")).toBe(
      "docker build --build-arg ANDROID_API=34 -t bomlens-android-sdk34 https://github.com/sktelecom/bomlens.git#v1.15.0:docker/android",
    );
    expect(releaseTag("v1.15.0")).toBe("v1.15.0");
  });
  it("leaves a placeholder tag when the release is unknown", () => {
    for (const v of [undefined, "", "dev", "latest-abc1234"]) {
      expect(releaseTag(v)).toBeNull();
      expect(manualBuildCommand(34, "i", v)).toContain("#<release-tag>:docker/android");
    }
  });
  it("reads the older errorCode spelling of the missing-image code", () => {
    const { code: _c, ...rest } = EVENT;
    expect(androidSdkNeed({ ...rest, errorCode: "ANDROID_SDK_IMAGE_MISSING" })?.api).toBe(34);
  });
  it("maps reasons to known wording", () => {
    expect(failureReason("dns")).toBe("dns");
    expect(failureReason("sdk-install")).toBe("sdk-install");
    expect(failureReason("weird")).toBe("unknown");
    expect(failureReason(undefined)).toBe("unknown");
  });
  it("does not offer retry when it cannot help", () => {
    expect(canRetryBuild("no-docker")).toBe(false);
    expect(canRetryBuild("no-build-files")).toBe(false);
    expect(canRetryBuild("cancelled")).toBe(true);
  });
  it("replays only scans without one-shot tokens", () => {
    expect(canReplayScan({})).toBe(true);
    expect(canReplayScan({ token: "t" })).toBe(false);
    expect(canReplayScan(null)).toBe(false);
  });
});
