// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { licenseOperands, shownLicenseLabels } from "./licenseOperands";

describe("licenseOperands", () => {
  it("keeps plain ids and drops repeats", () => {
    expect(licenseOperands(["MIT", "Apache-2.0", "MIT"])).toEqual(["MIT", "Apache-2.0"]);
  });
  it("splits AND and OR, with or without parentheses", () => {
    expect(licenseOperands(["MIT AND (Apache-2.0 OR BSD-3-Clause)"])).toEqual(["MIT", "Apache-2.0", "BSD-3-Clause"]);
    expect(licenseOperands(["Apache-2.0 or MIT"])).toEqual(["Apache-2.0", "MIT"]);
  });
  it("keeps WITH inside one operand", () => {
    expect(licenseOperands(["GPL-2.0-only WITH Classpath-exception-2.0 OR MIT"])).toEqual(["GPL-2.0-only WITH Classpath-exception-2.0", "MIT"]);
  });
  it("leaves prose and hashes whole", () => {
    expect(licenseOperands(["GNU General Public License v2 or later"])).toEqual(["GNU General Public License v2 or later"]);
    expect(licenseOperands(["sha256:ab12/cd"])).toEqual(["sha256:ab12/cd"]);
  });
  it("skips empty values", () => {
    expect(licenseOperands(["", "  "])).toEqual([]);
  });
});

describe("shownLicenseLabels", () => {
  it("shows up to two operands as they are", () => {
    expect(shownLicenseLabels([])).toEqual([]);
    expect(shownLicenseLabels(["MIT OR ISC"])).toEqual(["MIT", "ISC"]);
  });
  it("folds the rest into a count", () => {
    expect(shownLicenseLabels(["MIT", "ISC", "Apache-2.0", "BSD-3-Clause"])).toEqual(["MIT", "ISC", "+2"]);
  });
  it("shows every operand with all", () => {
    expect(shownLicenseLabels(["MIT", "ISC", "Apache-2.0"], true)).toEqual(["MIT", "ISC", "Apache-2.0"]);
  });
});
