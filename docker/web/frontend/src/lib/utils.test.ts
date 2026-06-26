import { describe, expect, it } from "vitest";

import { cn, formatBytes } from "./utils";

describe("formatBytes", () => {
  it("returns 0 B for zero, falsy or negative input", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(NaN)).toBe("0 B");
    expect(formatBytes(-5)).toBe("0 B");
  });

  it("keeps raw bytes (no decimals) under 1 KB", () => {
    expect(formatBytes(1)).toBe("1 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1023)).toBe("1023 B");
  });

  it("switches to KB at 1024 and keeps one decimal", () => {
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
  });

  it("switches to MB and GB at the right thresholds", () => {
    expect(formatBytes(1024 * 1024)).toBe("1.0 MB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
    expect(formatBytes(1024 * 1024 * 1024)).toBe("1.0 GB");
  });

  it("caps at GB for very large values", () => {
    expect(formatBytes(5 * 1024 * 1024 * 1024 * 1024)).toBe("5120.0 GB");
  });
});

describe("cn", () => {
  it("merges and de-conflicts tailwind classes", () => {
    expect(cn("px-2", "px-4")).toBe("px-4");
    expect(cn("text-sm", false && "hidden", "font-bold")).toBe("text-sm font-bold");
  });
});
