#!/usr/bin/env node
/**
 * ko-style lint — Korean translation-ese (번역투) and terminology linter.
 *
 * Applies the per-line regex catalog in patterns.json to the public Korean
 * documentation surface, after masking regions where rules must not fire:
 * code fences, inline code, links/images, bare URLs, HTML comments, YAML
 * front-matter, and table rows.
 *
 * Scope (SCOPE below): the published docs and READMEs. Internal maintainer
 * notes (docs/maintainers/), the changelog, license inventories, and
 * generated artifacts are deliberately out of scope.
 *
 * severity: S1 = clear error, S2 = strong recommendation, S3 = advisory.
 * The CI gate fails on S1/S2 (see --fail-on). The terminology decisions the
 * rules encode are recorded in docs/korean-style-guide.md.
 *
 * Usage:
 *   node scripts/ko-style/lint.mjs [--all|--files <p> …] [--format text|json]
 *                                  [--fail-on S1|S2|S3] [--no-baseline]
 *                                  [--write-baseline]
 *
 * The rule taxonomy follows epoko77-ai/im-not-ai (MIT), adapted to this
 * repository's documents.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Repo root = two levels up from scripts/ko-style/.
export const REPO_ROOT = path.resolve(__dirname, "..", "..");
const PATTERNS_PATH = path.join(__dirname, "patterns.json");
const BASELINE_PATH = path.join(REPO_ROOT, ".ko-style-baseline.json");

// The public documentation surface this gate guards. Directories are walked
// recursively for *.md; files are taken as-is.
const SCOPE = [
  "docs",
  "README.md",
  "CONTRIBUTING.md",
  "examples",
  "docker",
  "electron",
];
// Kept out of the gate: internal maintainer notes (historical records quote
// pre-fix wording), the changelog (quotes history), license inventories, and
// the style guide itself (it must quote the very anti-patterns it bans).
const EXCLUDE = [
  "docs/maintainers",
  "docs/korean-style-guide.md",
  "CHANGELOG.md",
  "THIRD_PARTY_LICENSES.md",
];

const IGNORE_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "out",
  "vendor", ".venv", "venv", "coverage", ".cache", "test-workspace",
]);

const SEVERITY_RANK = { S1: 3, S2: 2, S3: 1 };

/** Compile the catalog once into { id, category, severity, re, … } entries. */
export function loadRules() {
  const raw = JSON.parse(fs.readFileSync(PATTERNS_PATH, "utf8"));
  return raw.rules.map((r) => {
    if (!SEVERITY_RANK[r.severity]) {
      throw new Error(`rule '${r.id}': invalid severity '${r.severity}'`);
    }
    return { ...r, re: new RegExp(r.pattern, "gu") };
  });
}

/** Replace every match with same-length spaces, keeping columns aligned. */
function maskOut(line, re) {
  return line.replace(re, (m) => " ".repeat(m.length));
}

/** Blank every open…close span (inclusive) via a single left-to-right scan. */
function maskDelimited(line, open, close) {
  let out = "";
  let i = 0;
  for (;;) {
    const start = line.indexOf(open, i);
    if (start === -1) return out + line.slice(i);
    const end = line.indexOf(close, start + open.length);
    if (end === -1) return out + line.slice(i);
    const stop = end + close.length;
    out += line.slice(i, start) + " ".repeat(stop - start);
    i = stop;
  }
}

/** Strip the parts of a single (non-fenced) line where rules must not fire. */
function maskLine(line) {
  let out = line;
  out = maskDelimited(out, "<!--", "-->");
  out = maskOut(out, /`[^`]*`/g);
  // Mask whole links/images including display text, so interpuncts in link
  // runs are not misread as decorative lists.
  out = maskOut(out, /!?\[[^\]]*\]\([^)]*\)/g);
  out = maskOut(out, /https?:\/\/\S+/g);
  out = maskOut(out, /<https?:\/\/[^>]*>/g);
  return out;
}

/** Lint already-read text. Returns an array of findings. */
export function lintText(text, relPath, rules) {
  const findings = [];
  const lines = text.split("\n");
  let inFence = false;
  let inComment = false;
  let inFrontMatter = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (i === 0 && line.trim() === "---") {
      inFrontMatter = true;
      continue;
    }
    if (inFrontMatter) {
      if (line.trim() === "---") inFrontMatter = false;
      continue;
    }

    if (/^\s*(```|~~~)/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;

    // Skip table rows — bold/status marks (✅❌) inside cells are data.
    if (/^\s*\|/.test(line)) continue;

    if (inComment) {
      if (line.includes("-->")) inComment = false;
      continue;
    }
    if (line.includes("<!--") && !line.includes("-->")) {
      inComment = true;
      continue;
    }

    const masked = maskLine(line);
    if (masked.trim() === "") continue;

    for (const rule of rules) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(masked)) !== null) {
        findings.push({
          doc: relPath,
          line: i + 1,
          col: m.index + 1,
          id: rule.id,
          category: rule.category,
          severity: rule.severity,
          message: rule.message,
          suggestion: rule.suggestion,
          text: line.slice(m.index, m.index + m[0].length),
        });
        if (m[0].length === 0) rule.re.lastIndex++;
      }
    }
  }
  return findings;
}

/** Lint one file by path. */
export function lintFile(absPath, relPath, rules = loadRules()) {
  return lintText(fs.readFileSync(absPath, "utf8"), relPath, rules);
}

/** Recursively collect *.md under a root (absolute paths). */
function walkMarkdown(root) {
  const out = [];
  if (!fs.existsSync(root)) return out;
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (IGNORE_DIRS.has(entry.name) || entry.name.startsWith(".")) continue;
      out.push(...walkMarkdown(path.join(root, entry.name)));
    } else if (entry.name.endsWith(".md")) {
      out.push(path.join(root, entry.name));
    }
  }
  return out;
}

function excluded(rel) {
  return EXCLUDE.some((e) => rel === e || rel.startsWith(e + "/"));
}

/** All in-scope markdown files as {abs, rel}. */
function scopeTargets() {
  const out = [];
  for (const s of SCOPE) {
    const abs = path.join(REPO_ROOT, s);
    if (!fs.existsSync(abs)) continue;
    const files = fs.statSync(abs).isDirectory() ? walkMarkdown(abs) : [abs];
    for (const f of files) {
      const rel = path.relative(REPO_ROOT, f);
      if (!excluded(rel)) out.push({ abs: f, rel });
    }
  }
  return out;
}

/** A stable signature for baseline matching (line-number independent). */
export function signature(f) {
  return `${f.doc}|${f.id}|${f.text.trim()}`;
}

function loadBaseline() {
  if (!fs.existsSync(BASELINE_PATH)) return new Set();
  const arr = JSON.parse(fs.readFileSync(BASELINE_PATH, "utf8"));
  return new Set(Array.isArray(arr) ? arr : arr.signatures || []);
}

// ───── CLI ──────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const opts = { mode: "all", files: [], format: "text", failOn: "S2", baseline: true, writeBaseline: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--all") opts.mode = "all";
    else if (a === "--files") opts.mode = "files";
    else if (a === "--format") opts.format = argv[++i];
    else if (a === "--fail-on") opts.failOn = argv[++i];
    else if (a === "--no-baseline") opts.baseline = false;
    else if (a === "--write-baseline") opts.writeBaseline = true;
    else if (a.startsWith("--")) throw new Error(`unknown flag '${a}'`);
    else opts.files.push(a);
  }
  return opts;
}

function resolveTargets(opts) {
  if (opts.mode === "all") return scopeTargets();
  return opts.files
    .map((p) => (path.isAbsolute(p) ? p : path.join(REPO_ROOT, p)))
    .filter((abs) => abs.endsWith(".md") && fs.existsSync(abs))
    .map((abs) => ({ abs, rel: path.relative(REPO_ROOT, abs) }));
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const rules = loadRules();
  const targets = resolveTargets(opts);

  let findings = [];
  for (const t of targets) findings.push(...lintFile(t.abs, t.rel, rules));

  if (opts.writeBaseline) {
    const sigs = [...new Set(findings.map(signature))].sort();
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(sigs, null, 2) + "\n");
    console.log(`ko-style: wrote baseline with ${sigs.length} signature(s) to ${path.relative(REPO_ROOT, BASELINE_PATH)}`);
    return;
  }

  if (opts.baseline) {
    const base = loadBaseline();
    findings = findings.filter((f) => !base.has(signature(f)));
  }

  if (opts.format === "json") {
    console.log(JSON.stringify({ files: targets.length, findings }, null, 2));
  } else {
    for (const f of findings) {
      console.log(
        `${f.doc}:${f.line}:${f.col}  [${f.severity} ${f.category}] ${f.message}\n` +
          `    “${f.text}”  → ${f.suggestion}`,
      );
    }
    const counts = { S1: 0, S2: 0, S3: 0 };
    for (const f of findings) counts[f.severity]++;
    console.log(
      `\nko-style: ${targets.length} file(s), ${findings.length} finding(s) ` +
        `(S1 ${counts.S1} / S2 ${counts.S2} / S3 ${counts.S3}).`,
    );
  }

  const threshold = SEVERITY_RANK[opts.failOn] || SEVERITY_RANK.S2;
  const blocking = findings.some((f) => SEVERITY_RANK[f.severity] >= threshold);
  process.exit(blocking ? 1 : 0);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
