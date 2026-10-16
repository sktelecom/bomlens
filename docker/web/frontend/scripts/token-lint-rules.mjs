// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The token-lint rules, kept apart from the file walker so a unit test can feed
 * them single lines (src/lib/tokenLintRules.test.ts). scripts/token-lint.mjs is
 * the CLI that applies them to src/**.
 */

/** Tailwind's built-in palette families. A token never names one of these. */
export const PALETTE =
  "slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose";
/** Utilities that take a colour. `border` and `divide` also take widths, but a
 *  width is a bare number, not a palette family, so the family match is enough. */
export const COLOUR_UTILS =
  "text|bg|border|ring|ring-offset|outline|decoration|divide|placeholder|caret|accent|fill|stroke|shadow|from|via|to";

export const RULES = [
  { name: "hex colour", re: /#[0-9a-fA-F]{3,8}\b/ },
  { name: "literal rgb()/hsl()", re: /\b(?:rgba?|hsla?)\(\s*[\d.]/ },
  { name: "Tailwind arbitrary colour", re: /\[(?:#[0-9a-fA-F]|(?:rgba?|hsla?)\()/ },
  // A palette class is a colour decided in a component rather than in the token
  // file, which is the same drift as a hex literal and was invisible to the
  // three rules above. It is also how a light/dark pair goes out of sync: the
  // class carries one shade and its `dark:` twin carries another, maintained by
  // hand at each site. Turned on at zero violations, once every component had
  // moved onto tokens; a new one is therefore a regression, not a backlog item.
  { name: "Tailwind palette class", re: new RegExp(`\\b(?:${COLOUR_UTILS})-(?:${PALETTE})-\\d{2,3}\\b`) },
  // risk-* tokens come in pairs: the bare name (text-risk-high) is the
  // saturated colour meant for icons and badge backgrounds, and -fg is a
  // separate, darker/lighter variant chosen to meet WCAG AA text contrast on
  // the page background (badge.tsx already uses -fg for this). A bare token
  // reaching body text is how Overview.tsx's "more severe than before" text
  // failed contrast in light mode (3.56:1, needs 4.5:1) before switching to
  // -fg. This is a same-line heuristic, not real JSX parsing: an aria-hidden
  // icon is always flagged safe here because every icon site in this codebase
  // keeps its className and aria-hidden on one line; it does not see an
  // aria-hidden on a different line of a multi-line element, and it cannot
  // tell a genuine icon-only usage without aria-hidden from body text. Mark a
  // real false positive with `// token-lint-ignore` rather than reformatting
  // the JSX just to satisfy the lint.
  {
    name: "risk token on body text (use the -fg variant)",
    test: (line) =>
      /\btext-risk-(?:critical|high|medium|low|info)(?!-fg)\b/.test(line) && !/aria-hidden/.test(line),
  },
  // The role tokens (index.css) come in four shades, and only `-fg` is a text
  // colour: it is the one checked at 4.5:1 on its muted surface, the card and the
  // page. `-muted` and `-border` are surfaces and outlines, `-emphasis` is a fill
  // (several sit near 3:1 on white). Same same-line heuristic and the same
  // aria-hidden / token-lint-ignore escapes as the rule above.
  {
    name: "role or category shade other than -fg used as text colour",
    test: (line) =>
      /\btext-(?:role-(?:danger|severe|attention|info|success|neutral)|cat-(?:permissive|weak|strong|network|review))-(?:muted|emphasis|border)\b/.test(
        line,
      ) && !/aria-hidden/.test(line),
  },
  // The brand red marks the primary action, the logo and keyboard focus. It is
  // not a data colour: on a graph node or a badge it reads as "problem" next to
  // the severity colours, and on the active menu fill it made "where you are"
  // look like a warning. Scoped to the files and lines that draw data, so a
  // primary button or a logo may still use it.
  {
    name: "brand token in the graph or a badge (use a role, a category or a neutral)",
    test: (line, file = "") =>
      BRAND_TOKEN.test(line) &&
      (DATA_COLOUR_FILES.test(file.replace(/\\/g, "/")) || /<Badge\b|\bbadgeVariants\(/.test(line)),
  },
];

/** A brand utility class (bg-brand/10, text-brand-strong, hover:border-brand) or the CSS variable. */
export const BRAND_TOKEN =
  /--brand\b|(?:^|[^\w-])(?:[\w-]+:)*(?:bg|text|border|ring|ring-offset|outline|decoration|divide|placeholder|caret|accent|fill|stroke|shadow|from|via|to)-brand(?:-(?:foreground|accent|strong))?(?:\/\d+)?(?![\w-])/;

/** Files that draw data and so never use the brand colour at all. */
export const DATA_COLOUR_FILES =
  /(?:^|\/)(?:DependencyGraph\.tsx|DependencyTree\.tsx|ui\/badge\.tsx|ui\/marker\.tsx|LicenseRiskBar\.tsx|SeverityBar\.tsx|ui\/barlist\.tsx)$/;

/** Rules that report a line, as `[ruleName, ...]`. */
export function lintLine(line, file = "") {
  if (/token-lint-ignore/.test(line)) return [];
  return RULES.filter((r) => (r.re ? r.re.test(line) : r.test(line, file))).map((r) => r.name);
}
