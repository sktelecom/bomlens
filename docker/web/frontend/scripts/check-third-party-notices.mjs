// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// check-third-party-notices.mjs — gate the properties we claim about the SPA's
// bundled npm packages, rather than a hand-kept list that would drift.
//
// Run after `npm run build`. It reads dist/third-party-licenses.txt, which the
// vite plugin generates from the bundled module graph, and fails when:
//   - the file is missing or lists nothing (the plugin silently stopped working)
//   - a package declares no license, or none of its license text was found
//     (we would be redistributing terms we cannot show)
//   - a copyleft license appears (THIRD_PARTY_LICENSES.md tells readers the web
//     UI is permissive-only, and the AGPL section 13 argument for `--ui` rests
//     on it)
import fs from "node:fs";
import path from "node:path";

const NOTICE = path.join(process.cwd(), "dist", "third-party-licenses.txt");

// Ids that would break the permissive-only claim. Substring match on the
// declared id, so GPL-3.0-or-later and LGPL-2.1 are both caught.
const COPYLEFT = ["GPL", "AGPL", "LGPL", "MPL", "EPL", "CDDL", "CPL", "OSL", "SSPL"];

if (!fs.existsSync(NOTICE)) {
  console.error("[FAIL] dist/third-party-licenses.txt is missing — run `npm run build` first.");
  console.error("       If the build ran, the vite plugin stopped emitting it.");
  process.exit(1);
}

const text = fs.readFileSync(NOTICE, "utf8");
const declared = [...text.matchAll(/^License: (.+)$/gm)].map((m) => m[1].trim());
const listed = Number((text.match(/^Packages: (\d+)$/m) || [])[1]);

let failed = false;

if (!listed || declared.length !== listed) {
  console.error(
    `[FAIL] the notice claims ${listed} packages but carries ${declared.length} entries.`,
  );
  failed = true;
}

const unknown = declared.filter((id) => id === "UNKNOWN");
if (unknown.length) {
  console.error(`[FAIL] ${unknown.length} bundled package(s) declare no license.`);
  failed = true;
}

const missingText = (text.match(/No license file was found in this package/g) || []).length;
if (missingText) {
  console.error(`[FAIL] ${missingText} bundled package(s) ship no license text to reproduce.`);
  failed = true;
}

const copyleft = declared.filter((id) => COPYLEFT.some((c) => id.toUpperCase().includes(c)));
if (copyleft.length) {
  console.error(`[FAIL] copyleft license(s) in the web UI bundle: ${copyleft.join(", ")}`);
  console.error("       THIRD_PARTY_LICENSES.md states the web UI is permissive-only.");
  failed = true;
}

if (failed) process.exit(1);

const summary = [...new Set(declared)].sort().join(", ");
console.log(`[OK] ${listed} bundled packages, all with license text (${summary})`);
