import { describe, expect, it } from "vitest";

import { isNextUi } from "./flags";

describe("isNextUi", () => {
  it("is true only for ?ui=next", () => {
    expect(isNextUi("?ui=next")).toBe(true);
    expect(isNextUi("?foo=1&ui=next")).toBe(true);
  });

  it("is false for any other value or absence", () => {
    expect(isNextUi("")).toBe(false);
    expect(isNextUi("?ui=classic")).toBe(false);
    expect(isNextUi("?ui=")).toBe(false);
    expect(isNextUi("?next=ui")).toBe(false);
  });
});
