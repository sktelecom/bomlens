// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// A vite plugin that writes the notice for every npm package whose code ends
// up in the built SPA.
//
// Why generated and not hand-written: the SPA ships inside the scanner image
// and the desktop installer, so MIT/ISC/BSD terms in it require their notices
// to travel along. A hand-kept list drifts the moment an import changes, and
// it cannot tell a dependency that ships from one the bundler drops -- this
// repo has both (@radix-ui/react-tabs is declared and installed, but no
// component imports ui/tabs.tsx, so none of it reaches the bundle).
//
// The list therefore comes from the emitted module graph, which is the same
// thing the browser downloads. The @fontsource packages appear in it too, via
// the CSS they contribute, so the fonts THIRD_PARTY_LICENSES.md attributes are
// covered here as well.
import fs from "node:fs";
import path from "node:path";

const LICENSE_FILENAMES = [
  "LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md",
  "LICENCE.txt", "license", "License", "COPYING", "COPYING.md",
];

/** The package directory a module id belongs to, or null outside node_modules. */
function packageRootOf(id) {
  const marker = "node_modules" + path.sep;
  const at = id.lastIndexOf(marker);
  if (at < 0) return null;
  const rest = id.slice(at + marker.length).split(path.sep);
  const depth = rest[0].startsWith("@") ? 2 : 1;
  if (rest.length < depth) return null;
  return id.slice(0, at + marker.length) + rest.slice(0, depth).join(path.sep);
}

function readLicenseText(dir) {
  for (const name of LICENSE_FILENAMES) {
    const p = path.join(dir, name);
    if (fs.existsSync(p) && fs.statSync(p).isFile()) {
      return { text: fs.readFileSync(p, "utf8").trim(), file: name };
    }
  }
  return { text: null, file: null };
}

/** The SPDX id a package declares, normalised across the legacy shapes. */
function declaredLicense(pkg) {
  if (typeof pkg.license === "string") return pkg.license;
  if (pkg.license && typeof pkg.license.type === "string") return pkg.license.type;
  if (Array.isArray(pkg.licenses)) {
    return pkg.licenses.map((l) => (typeof l === "string" ? l : l.type)).filter(Boolean).join(" OR ");
  }
  return null;
}

export function thirdPartyNotices({ fileName = "third-party-licenses.txt" } = {}) {
  return {
    name: "bomlens-third-party-notices",
    apply: "build",
    generateBundle(_options, bundle) {
      const roots = new Set();
      for (const output of Object.values(bundle)) {
        if (output.type !== "chunk") continue;
        for (const id of Object.keys(output.modules)) {
          const root = packageRootOf(id);
          if (root) roots.add(root);
        }
      }

      const entries = [];
      for (const root of roots) {
        const manifestPath = path.join(root, "package.json");
        if (!fs.existsSync(manifestPath)) continue;
        const pkg = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
        const { text, file } = readLicenseText(root);
        entries.push({
          name: pkg.name,
          version: pkg.version,
          license: declaredLicense(pkg) || "UNKNOWN",
          homepage: pkg.homepage || (pkg.repository && (pkg.repository.url || pkg.repository)) || "",
          licenseFile: file,
          licenseText: text,
        });
      }
      // Sorted so the same input always produces the same file.
      entries.sort((a, b) => a.name.localeCompare(b.name));

      const header = [
        "Third-party notices for the BomLens web UI",
        "",
        "The BomLens web UI is a single-page application built from the npm",
        "packages listed below. Their code is part of the bundle this file sits",
        "next to, so their terms and copyright notices are reproduced here in",
        "full. BomLens itself is licensed under Apache-2.0; see the LICENSE and",
        "NOTICE files that ship beside it.",
        "",
        "This file is generated at build time from the bundled module graph, so",
        "it lists what the browser actually downloads rather than what the",
        "manifest declares. THIRD_PARTY_LICENSES.md summarises the same set.",
        "",
        `Packages: ${entries.length}`,
        "",
        ...entries.map((e) => `  ${e.name}@${e.version} — ${e.license}`),
        "",
      ];

      const bodies = entries.map((e) => {
        const lines = [
          "".padEnd(76, "="),
          `${e.name}@${e.version}`,
          `License: ${e.license}`,
        ];
        if (e.homepage) lines.push(`Homepage: ${e.homepage}`);
        lines.push("".padEnd(76, "="), "");
        lines.push(
          e.licenseText ||
            `No license file was found in this package. Its package.json declares ` +
              `${e.license}; obtain the full text from the SPDX registry at ` +
              `https://spdx.org/licenses/${e.license}.html`,
        );
        return lines.join("\n") + "\n";
      });

      this.emitFile({
        type: "asset",
        fileName,
        source: header.join("\n") + "\n" + bodies.join("\n"),
      });
    },
  };
}
