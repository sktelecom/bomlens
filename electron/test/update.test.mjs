import test from "node:test";
import assert from "node:assert/strict";
import {
  checkForUpdate,
  isNewerVersion,
  parseVersion,
  releaseUpdateInfo,
} from "../lib/update.mjs";

test("parseVersion handles v prefix, plain, and prerelease suffixes", () => {
  assert.deepEqual(parseVersion("v1.5.5"), [1, 5, 5]);
  assert.deepEqual(parseVersion("1.5.5"), [1, 5, 5]);
  assert.deepEqual(parseVersion("1.6.0-rc.1"), [1, 6, 0]);
  assert.equal(parseVersion("latest"), null);
  assert.equal(parseVersion(""), null);
  assert.equal(parseVersion(null), null);
  assert.equal(parseVersion("1.5"), null);
});

test("isNewerVersion compares major, minor, and patch", () => {
  assert.equal(isNewerVersion("1.5.6", "1.5.5"), true);
  assert.equal(isNewerVersion("1.6.0", "1.5.9"), true);
  assert.equal(isNewerVersion("2.0.0", "1.9.9"), true);
  assert.equal(isNewerVersion("1.5.5", "1.5.5"), false);
  assert.equal(isNewerVersion("1.5.4", "1.5.5"), false);
  assert.equal(isNewerVersion("garbage", "1.5.5"), false);
  assert.equal(isNewerVersion("1.5.6", "garbage"), false);
});

test("releaseUpdateInfo returns info only for a newer published release", () => {
  assert.deepEqual(
    releaseUpdateInfo({ tag_name: "v1.6.0", draft: false, prerelease: false }, "1.5.5"),
    { latest: "1.6.0", current: "1.5.5" },
  );
  assert.equal(
    releaseUpdateInfo({ tag_name: "v1.5.5", draft: false, prerelease: false }, "1.5.5"),
    null,
  );
  assert.equal(releaseUpdateInfo({ tag_name: "v9.9.9", draft: true }, "1.5.5"), null);
  assert.equal(releaseUpdateInfo({ tag_name: "v9.9.9", prerelease: true }, "1.5.5"), null);
  assert.equal(releaseUpdateInfo({ tag_name: "latest" }, "1.5.5"), null);
  assert.equal(releaseUpdateInfo({}, "1.5.5"), null);
  assert.equal(releaseUpdateInfo(null, "1.5.5"), null);
});

function fetchStub(status, body) {
  return async () => ({ status, json: async () => body });
}

test("checkForUpdate reports a newer release", async () => {
  const info = await checkForUpdate({
    currentVersion: "1.5.5",
    fetchImpl: fetchStub(200, { tag_name: "v1.6.0" }),
  });
  assert.deepEqual(info, { latest: "1.6.0", current: "1.5.5" });
});

test("checkForUpdate returns null on non-200 responses", async () => {
  for (const status of [403, 404, 500]) {
    assert.equal(
      await checkForUpdate({ currentVersion: "1.5.5", fetchImpl: fetchStub(status, {}) }),
      null,
    );
  }
});

test("checkForUpdate returns null when fetch rejects or JSON parsing fails", async () => {
  assert.equal(
    await checkForUpdate({
      currentVersion: "1.5.5",
      fetchImpl: async () => {
        throw new Error("offline");
      },
    }),
    null,
  );
  assert.equal(
    await checkForUpdate({
      currentVersion: "1.5.5",
      fetchImpl: async () => ({
        status: 200,
        json: async () => {
          throw new Error("bad json");
        },
      }),
    }),
    null,
  );
});

test("checkForUpdate sends a User-Agent header", async () => {
  let seenHeaders = null;
  await checkForUpdate({
    currentVersion: "1.5.5",
    fetchImpl: async (_url, opts) => {
      seenHeaders = opts.headers;
      return { status: 200, json: async () => ({ tag_name: "v1.5.5" }) };
    },
  });
  assert.ok(seenHeaders["User-Agent"]);
});
