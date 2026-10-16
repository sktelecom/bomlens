// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  DEFAULT_DENSITY,
  DENSITY_KEY,
  densityClass,
  parseDensity,
  readDensity,
  ROW_HEIGHT_PX,
  writeDensity,
} from "./tableDensity";
import type { ViewStore } from "./tableView";

function store(initial: Record<string, string> = {}): ViewStore & { data: Record<string, string> } {
  const data = { ...initial };
  return {
    data,
    getItem: (k) => (k in data ? data[k] : null),
    setItem: (k, v) => {
      data[k] = v;
    },
  };
}

describe("row heights", () => {
  it("are 32px compact and 40px comfortable", () => {
    expect(ROW_HEIGHT_PX).toEqual({ compact: 32, comfortable: 40 });
  });

  it("maps a step to its table class", () => {
    expect(densityClass("compact")).toBe("table-density-compact");
    expect(densityClass("comfortable")).toBe("table-density-comfortable");
  });
});

describe("parseDensity", () => {
  it("accepts the two known steps", () => {
    expect(parseDensity("compact")).toBe("compact");
    expect(parseDensity("comfortable")).toBe("comfortable");
  });

  it("falls back to the default for anything else", () => {
    expect(parseDensity(null)).toBe(DEFAULT_DENSITY);
    expect(parseDensity("")).toBe(DEFAULT_DENSITY);
    expect(parseDensity("spacious")).toBe(DEFAULT_DENSITY);
    expect(parseDensity('"compact"')).toBe(DEFAULT_DENSITY);
  });
});

describe("read and write", () => {
  it("round-trips through the store", () => {
    const s = store();
    writeDensity("compact", s);
    expect(s.data[DENSITY_KEY]).toBe("compact");
    expect(readDensity(s)).toBe("compact");
  });

  it("returns the default with no store or a throwing one", () => {
    expect(readDensity(null)).toBe(DEFAULT_DENSITY);
    const broken: ViewStore = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    };
    expect(readDensity(broken)).toBe(DEFAULT_DENSITY);
    expect(() => writeDensity("compact", broken)).not.toThrow();
    expect(() => writeDensity("compact", null)).not.toThrow();
  });
});
