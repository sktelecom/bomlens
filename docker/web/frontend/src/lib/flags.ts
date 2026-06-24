/**
 * Feature flags for the UI rebuild. The new shell ships behind `?ui=next` so
 * the classic interface stays the default and keeps working while sections are
 * migrated phase by phase. Once parity is reached the flag is promoted to the
 * default and the classic path is removed.
 */

/** True when the new shell is requested via the `?ui=next` query parameter. */
export function isNextUi(search: string = window.location.search): boolean {
  try {
    return new URLSearchParams(search).get("ui") === "next";
  } catch {
    return false;
  }
}
