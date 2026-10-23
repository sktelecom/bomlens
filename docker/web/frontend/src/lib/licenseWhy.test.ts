// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { CONFLICT_WHY_KEYS, conflictWhyKey } from "./licenseWhy";

const rules = JSON.parse(
  readFileSync(new URL("../../../../lib/license-compat.json", import.meta.url), "utf-8"),
) as {
  matrix: Record<string, Record<string, { why: string }>>;
  pairs: { why: string }[];
};

function messages(lng: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(process.cwd(), "src", "locales", lng, "common.json"), "utf8"));
}

function lookup(obj: Record<string, unknown>, key: string): unknown {
  return key.split(".").reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], obj);
}

describe("conflictWhyKey", () => {
  it("recognises every reason in the scanner's rules file", () => {
    const whys = [
      ...Object.values(rules.matrix).flatMap((row) => Object.values(row).map((c) => c.why)),
      ...rules.pairs.map((p) => p.why),
    ];
    for (const why of whys) expect(conflictWhyKey(why), why).not.toBeNull();
  });

  it("recognises the sentences written around the rules", () => {
    expect(conflictWhyKey("The component declares no license.")?.key).toBe("licenses.why.noLicense");
    expect(conflictWhyKey('The license "Foo Bar" could not be parsed as an SPDX expression.')).toEqual({
      key: "licenses.why.unparsedLicense",
      params: { license: "Foo Bar" },
    });
    const wrapped = conflictWhyKey(
      "The dependency carries an exception clause, which exists to permit exactly this combination. Confirm the exception covers your use. (Both are permissive; keep the notices.)",
    );
    expect(wrapped).toEqual({
      key: "licenses.why.exception",
      params: { inner: { key: "licenses.why.permissivePermissive" } },
    });
  });

  it("returns null for a sentence it does not know, so the caller shows it verbatim", () => {
    expect(conflictWhyKey("Something a newer scanner wrote.")).toBeNull();
  });

  it("has a message for every key in both languages", () => {
    for (const lng of ["en", "ko"]) {
      const m = messages(lng);
      for (const key of CONFLICT_WHY_KEYS) expect(typeof lookup(m, key), `${lng} ${key}`).toBe("string");
    }
  });
});
