// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { RecentScan } from "./api";
import {
  filterRecent,
  formatRelativeTime,
  middleEllipsis,
  pickComparedScan,
  pickStartScans,
  presentTypes,
  scanComparison,
  scanType,
  scanTypeLabelKey,
  sortRecent,
  summarizeRecent,
} from "./recent";

function scan(over: Partial<RecentScan> = {}): RecentScan {
  return {
    id: "p_1.0",
    project: "p",
    version: "1.0",
    components: 10,
    maxSeverity: null,
    isAiScan: false,
    componentType: null,
    inputSource: null,
    generatedAt: 0,
    ...over,
  };
}

describe("summarizeRecent", () => {
  it("counts total, at-risk (CRITICAL/HIGH) and distinct projects", () => {
    const s = summarizeRecent([
      scan({ project: "a", maxSeverity: "CRITICAL" }),
      scan({ project: "a", maxSeverity: "HIGH" }),
      scan({ project: "b", maxSeverity: "MEDIUM" }),
      scan({ project: "c", maxSeverity: null, isAiScan: true }),
    ]);
    expect(s).toEqual({ total: 4, atRisk: 2, projects: 3 });
  });

  it("is all-zero for an empty list", () => {
    expect(summarizeRecent([])).toEqual({ total: 0, atRisk: 0, projects: 0 });
  });
});

describe("scanType / presentTypes", () => {
  it("derives the scan kind from isAiScan then componentType", () => {
    expect(scanType(scan({ isAiScan: true }))).toBe("ai");
    expect(scanType(scan({ componentType: "firmware" }))).toBe("firmware");
    expect(scanType(scan({ componentType: "container" }))).toBe("container");
    expect(scanType(scan({ componentType: "operating-system" }))).toBe("rootfs");
    expect(scanType(scan({ componentType: "application" }))).toBe("source");
    expect(scanType(scan({ componentType: null }))).toBe("sbom");
  });

  it("calls a model-rooted SBOM an AI scan even without the isAiScan flag", () => {
    // A spec-shaped AI SBOM names the model as its own root component, so the
    // components[] array `isAiScan` reads holds only the datasets.
    expect(
      scanType(scan({ isAiScan: false, componentType: "machine-learning-model" })),
    ).toBe("ai");
  });

  it("calls a scanned folder a folder, not a generic SBOM", () => {
    // A rootfs scan roots at `file`, which fell through to the default and put
    // the scan in the list as "SBOM" — out of every other filter. The saved
    // input says exactly what it was.
    expect(scanType(scan({ inputSource: "rootfs-dir", componentType: "file" }))).toBe("rootfs");
    // Scans made before the input sidecar existed have only the root type.
    expect(scanType(scan({ componentType: "file" }))).toBe("rootfs");
  });

  it("calls a submitted SBOM an SBOM, not the source its root claims to be", () => {
    // A supplier's document declares "application" at its root, exactly like a
    // source scan — reading the component type alone labelled it Source.
    expect(
      scanType(scan({ inputSource: "sbom-upload", componentType: "application" })),
    ).toBe("sbom");
    // A model SBOM someone submitted is still an AI scan; that signal wins.
    expect(
      scanType(scan({ inputSource: "sbom-upload", isAiScan: true })),
    ).toBe("ai");
  });

  it("leaves every other input on the SBOM's own declaration", () => {
    expect(
      scanType(scan({ inputSource: "current-dir", componentType: "application" })),
    ).toBe("source");
    expect(
      scanType(scan({ inputSource: "docker-image", componentType: "container" })),
    ).toBe("container");
    expect(
      scanType(scan({ inputSource: "firmware-upload", componentType: "firmware" })),
    ).toBe("firmware");
    // A scan saved before the sidecar existed has no input to read.
    expect(
      scanType(scan({ inputSource: null, componentType: "application" })),
    ).toBe("source");
  });

  it("lists distinct present types in display order", () => {
    const types = presentTypes([
      scan({ componentType: null }),
      scan({ isAiScan: true }),
      scan({ componentType: "container" }),
      scan({ componentType: "application" }),
    ]);
    expect(types).toEqual(["source", "container", "ai", "sbom"]);
  });
});

describe("filterRecent", () => {
  const list = [
    scan({ id: "a", project: "web-api", version: "2.0", maxSeverity: "CRITICAL", componentType: "application" }),
    scan({ id: "b", project: "mobile", version: "1.0", maxSeverity: "LOW", componentType: "container" }),
    scan({ id: "c", project: "ml-model", version: "1.0", maxSeverity: null, isAiScan: true }),
  ];
  const base = { query: "", type: "all" as const, atRisk: false };

  it("returns everything with no filter", () => {
    expect(filterRecent(list, base).map((s) => s.id)).toEqual(["a", "b", "c"]);
  });

  it("matches free text against project and version", () => {
    expect(filterRecent(list, { ...base, query: "web" }).map((s) => s.id)).toEqual(["a"]);
    expect(filterRecent(list, { ...base, query: "2.0" }).map((s) => s.id)).toEqual(["a"]);
    expect(filterRecent(list, { ...base, query: "MOBILE" }).map((s) => s.id)).toEqual(["b"]);
  });

  it("filters by scan type and by at-risk", () => {
    expect(filterRecent(list, { ...base, type: "ai" }).map((s) => s.id)).toEqual(["c"]);
    expect(filterRecent(list, { ...base, type: "source" }).map((s) => s.id)).toEqual(["a"]);
    expect(filterRecent(list, { ...base, type: "container" }).map((s) => s.id)).toEqual(["b"]);
    expect(filterRecent(list, { ...base, atRisk: true }).map((s) => s.id)).toEqual(["a"]);
  });

  it("combines text, type and at-risk", () => {
    expect(filterRecent(list, { query: "ml", type: "ai", atRisk: false }).map((s) => s.id)).toEqual(["c"]);
    expect(filterRecent(list, { query: "mobile", type: "ai", atRisk: false })).toEqual([]);
  });
});

describe("scanTypeLabelKey", () => {
  it("labels AI scans, with AI winning over component type", () => {
    expect(scanTypeLabelKey(scan({ isAiScan: true }))).toBe("recent.typeAi");
    expect(
      scanTypeLabelKey(scan({ isAiScan: true, componentType: "application" })),
    ).toBe("recent.typeAi");
  });

  it("maps the CycloneDX root component type for non-AI scans", () => {
    expect(scanTypeLabelKey(scan({ componentType: "application" }))).toBe(
      "recent.typeSource",
    );
    expect(scanTypeLabelKey(scan({ componentType: "firmware" }))).toBe(
      "recent.typeFirmware",
    );
    expect(scanTypeLabelKey(scan({ componentType: "container" }))).toBe(
      "recent.typeContainer",
    );
    expect(scanTypeLabelKey(scan({ componentType: "operating-system" }))).toBe(
      "recent.typeRootfs",
    );
  });

  it("falls back to a generic SBOM for unknown/absent types", () => {
    expect(scanTypeLabelKey(scan({ componentType: null }))).toBe(
      "recent.typeSbom",
    );
    expect(scanTypeLabelKey(scan({ componentType: "data" }))).toBe(
      "recent.typeSbom",
    );
  });
});

describe("scanComparison", () => {
  const list: RecentScan[] = [
    scan({ id: "cur", version: "2.0", components: 13, maxSeverity: "CRITICAL", generatedAt: 200 }),
    scan({ id: "prev", version: "1.0", components: 10, maxSeverity: "HIGH", generatedAt: 100 }),
    scan({ id: "other", project: "q", components: 99, generatedAt: 150 }),
  ];

  it("compares against the most recent earlier scan of the same project", () => {
    const cmp = scanComparison(list, "cur");
    expect(cmp?.prev.id).toBe("prev");
    expect(cmp?.componentsDelta).toBe(3);
    expect(cmp?.severityDir).toBe("up"); // HIGH → CRITICAL
  });

  it("leaves a run whose declaration was refused out of the comparison", () => {
    const withRefused = [
      scan({ id: "cur", components: 13, generatedAt: 300 }),
      scan({ id: "ref", components: 0, generatedAt: 200, refused: true }),
      scan({ id: "prev", components: 10, generatedAt: 100 }),
    ];
    expect(scanComparison(withRefused, "cur")?.prev.id).toBe("prev");
    expect(scanComparison(withRefused, "ref")).toBeNull();
  });

  it("reports a drop and an unchanged severity by rank", () => {
    expect(
      scanComparison(
        [
          scan({ id: "cur", components: 8, maxSeverity: "LOW", generatedAt: 200 }),
          scan({ id: "prev", components: 10, maxSeverity: "CRITICAL", generatedAt: 100 }),
        ],
        "cur",
      ),
    ).toMatchObject({ componentsDelta: -2, severityDir: "down" });
    expect(
      scanComparison(
        [
          scan({ id: "cur", maxSeverity: "MEDIUM", generatedAt: 200 }),
          scan({ id: "prev", maxSeverity: "MEDIUM", generatedAt: 100 }),
        ],
        "cur",
      )?.severityDir,
    ).toBe("same");
  });

  it("is null with no prior scan of the same project, or an unknown id", () => {
    expect(scanComparison(list, "prev")).toBeNull(); // nothing older for project p
    expect(scanComparison(list, "missing")).toBeNull();
  });
});

describe("sortRecent", () => {
  const list: RecentScan[] = [
    scan({ id: "a", project: "alpha", components: 5, maxSeverity: "LOW", generatedAt: 100 }),
    scan({ id: "b", project: "charlie", components: 30, maxSeverity: "CRITICAL", generatedAt: 300 }),
    scan({ id: "c", project: "bravo", components: 12, maxSeverity: null, generatedAt: 200 }),
  ];

  it("sorts by generated time (desc = newest first)", () => {
    expect(sortRecent(list, "generated", "desc").map((s) => s.id)).toEqual(["b", "c", "a"]);
    expect(sortRecent(list, "generated", "asc").map((s) => s.id)).toEqual(["a", "c", "b"]);
  });

  it("sorts by component count and by worst severity", () => {
    expect(sortRecent(list, "components", "desc").map((s) => s.id)).toEqual(["b", "c", "a"]);
    expect(sortRecent(list, "severity", "desc").map((s) => s.id)[0]).toBe("b"); // CRITICAL first
  });

  it("sorts by project name and doesn't mutate the input", () => {
    const copy = [...list];
    expect(sortRecent(list, "scan", "asc").map((s) => s.project)).toEqual([
      "alpha",
      "bravo",
      "charlie",
    ]);
    expect(list).toEqual(copy);
  });
});

describe("formatRelativeTime", () => {
  const nowMs = 1_000_000_000; // 1e9 s

  it("renders sub-minute as 'now'", () => {
    expect(formatRelativeTime(1_000_000_000 / 1000 - 30, nowMs, "en")).toBe(
      "now",
    );
  });

  it("renders hours and days ago", () => {
    const nowSec = nowMs / 1000;
    expect(formatRelativeTime(nowSec - 7200, nowMs, "en")).toBe("2 hours ago");
    expect(formatRelativeTime(nowSec - 86_400, nowMs, "en")).toBe("yesterday");
  });
});

describe("pickStartScans", () => {
  const base = {
    version: "1",
    components: 1,
    maxSeverity: null,
    isAiScan: false,
    inputSource: null,
  } as const;
  const mk = (id: string, componentType: string | null, generatedAt: number, extra = {}) =>
    ({ ...base, id, project: id, componentType, generatedAt, ...extra }) as RecentScan;

  it("picks the newest of source, container and AI, in that order", () => {
    const scans = [
      mk("old-src", "application", 1),
      mk("fw", "firmware", 9),
      mk("model", "machine-learning-model", 5, { isAiScan: true }),
      mk("img", "container", 4),
      mk("new-src", "application", 3),
    ];
    expect(pickStartScans(scans).map((s) => s.id)).toEqual(["new-src", "img", "model"]);
  });

  it("skips a missing type and returns nothing for an unrelated list", () => {
    expect(pickStartScans([mk("img", "container", 4)]).map((s) => s.id)).toEqual(["img"]);
    expect(pickStartScans([mk("fw", "firmware", 1)])).toEqual([]);
    expect(pickStartScans([])).toEqual([]);
  });

  it("does not count an uploaded supplier SBOM as a source project", () => {
    const up = mk("up", "application", 7, { inputSource: "sbom-upload" });
    expect(pickStartScans([up])).toEqual([]);
  });
});

describe("middleEllipsis", () => {
  it("leaves a short name alone", () => {
    expect(middleEllipsis("nginx", 20)).toBe("nginx");
    expect(middleEllipsis("a".repeat(20), 20)).toBe("a".repeat(20));
  });

  it("keeps the start and the end and fits the limit", () => {
    const out = middleEllipsis("2026-06-18-raspios-trixie-arm64-lite.img.xz", 24);
    expect(Array.from(out)).toHaveLength(24);
    expect(out.startsWith("2026-06-18-r")).toBe(true);
    expect(out.endsWith("lite.img.xz")).toBe(true);
    expect(out).toContain("…");
  });

  it("counts characters, not UTF-16 units", () => {
    const out = middleEllipsis("가".repeat(30), 10);
    expect(Array.from(out)).toHaveLength(10);
  });

  it("ignores a limit too small to be useful", () => {
    expect(middleEllipsis("abcdef", 2)).toBe("abcdef");
  });
});

describe("pickComparedScan", () => {
  it("returns the newest scan of a project that was scanned twice", () => {
    const scans = [
      scan({ id: "a_1", project: "a", version: "1", generatedAt: 1 }),
      scan({ id: "b_1", project: "b", version: "1", generatedAt: 2 }),
      scan({ id: "a_2", project: "a", version: "2", generatedAt: 3 }),
    ];
    expect(pickComparedScan(scans)?.id).toBe("a_2");
  });

  it("returns null when every project was scanned once", () => {
    expect(
      pickComparedScan([
        scan({ id: "a_1", project: "a", generatedAt: 1 }),
        scan({ id: "b_1", project: "b", generatedAt: 2 }),
      ]),
    ).toBeNull();
  });
});
