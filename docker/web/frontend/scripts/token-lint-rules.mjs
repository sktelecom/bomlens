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
  // The brand navy marks the primary action, links, the logo and keyboard
  // focus. It is not a data colour and not decoration: on a badge, a chart, a
  // drop target or a callout it competes with the primary action and reads as
  // "click here". So the rule is an allow list, not a deny list: a brand utility
  // is accepted only in BRAND_ALLOWED_FILES (the primary button variant). The
  // logo is an image and the focus ring is the `ring` colour (`--ring`), neither
  // of which is a brand utility class. Primer controls (checkbox, radio, toggle
  // switch) take the accent through Primer's own variables (src/primer.css),
  // which is allowed; this rule covers the Tailwind brand classes. Anything else
  // uses a neutral, a role or a category.
  {
    name: "brand token outside the allow list (primary button, logo, focus ring only)",
    test: (line, file = "") => BRAND_TOKEN.test(line) && !BRAND_ALLOWED_FILES.test(file.replace(/\\/g, "/")),
  },
  // Font sizes come from the role scale (text-display ... text-mono, defined in
  // index.css and tailwind.config.ts), not from a value typed at the call site.
  {
    name: "arbitrary font size (use a role size: text-caption, text-label, text-body-sm ...)",
    re: /\btext-\[\s*[\d.]+(?:px|rem|em|pt)\s*\]/,
  },
  // Shape rules. A thick bar on the left edge of a card, row or menu item is
  // not part of the design language (Primer's own active-item bar is hidden in
  // src/primer.css), and corners and shadows come from the token scale
  // (rounded-sm/md/lg/full, shadow-sm/md/lg, or a Primer variable), not from a
  // value typed at the call site. A 1px left border (border-l) is a divider and
  // stays allowed.
  {
    name: "thick left accent border (border-l-2 and up, or a left border of 2px or more)",
    test: (line) => hasLeftBarClass(line) || hasLeftBarStyle(line),
  },
  {
    name: "arbitrary shadow (use shadow-sm/md/lg or a Primer shadow variable)",
    test: (line) => ARBITRARY_SHADOW_CLASS.test(line) || LITERAL_SHADOW_STYLE.test(line),
  },
  {
    name: "arbitrary corner radius (use rounded-sm/md/lg/full or a Primer radius variable)",
    test: (line) => ARBITRARY_RADIUS_CLASS.test(line) || LITERAL_RADIUS_STYLE.test(line),
  },
  // Tailwind's own size names were removed from the theme (tailwind.config.ts),
  // so a leftover one would silently render at the inherited size.
  {
    name: "legacy Tailwind font size (renamed: xs=label, sm=body-sm, base=body, lg=heading, xl=title, 3xl=display)",
    re: /(?<![\w-])text-(?:xs|sm|base|lg|xl|[2-9]xl)(?![\w-])/,
  },
];

/** A brand utility class (bg-brand/10, text-brand-strong, hover:bg-brand-hover) or the CSS variable. */
export const BRAND_TOKEN =
  /--brand\b|(?:^|[^\w-])(?:[\w-]+:)*(?:bg|text|border|ring|ring-offset|outline|decoration|divide|placeholder|caret|accent|fill|stroke|shadow|from|via|to)-brand(?:-(?:foreground|strong|hover))?(?:\/\d+)?(?![\w-])/;

/** The only files that may use a brand utility: the Button variants (the primary
 *  action). Add a file here only for a primary action, never for data or decoration. */
export const BRAND_ALLOWED_FILES = /(?:^|\/)ui\/button\.tsx$/;

/** Rules that report a line, as `[ruleName, ...]`. */
export function lintLine(line, file = "") {
  if (/token-lint-ignore/.test(line)) return [];
  return RULES.filter((r) => (r.re ? r.re.test(line) : r.test(line, file))).map((r) => r.name);
}

/** A CSS length in px (rem and em at 16px), or null when the text is not a
 *  plain length (a keyword, a var(), a colour). */
export function lengthPx(text) {
  const m = /^\s*(\d*\.?\d+)\s*(px|rem|em)?\s*$/.exec(text);
  if (!m) return null;
  const n = Number(m[1]);
  return m[2] === "rem" || m[2] === "em" ? n * 16 : n;
}

/** border-l-2, border-s-4, md:border-l-[3px], border-l-[0.25rem]: a left or
 *  inline-start border of 2px or more. border-l, border-l-0, border-l-[1px],
 *  border-l-[0px] and colour classes (border-l-border) pass. */
export function hasLeftBarClass(line) {
  for (const m of line.matchAll(/(?:^|[^\w-])(?:[\w-]+:)*border-[ls]-(\d+|\[[^\]]*\])/g)) {
    const v = m[1];
    const px = v.startsWith("[") ? lengthPx(v.slice(1, -1)) : Number(v);
    if (px !== null && px >= 2) return true;
  }
  return false;
}

/** borderLeft: "3px solid ...", borderLeft: "0.25rem solid", borderLeftWidth: 2,
 *  border-left: 4px ..., border-inline-start-width: 2px. The first word of the
 *  value is read as a length; under 2px passes. */
export function hasLeftBarStyle(line) {
  const re = /\bborder(?:Left|InlineStart|-left|-inline-start)(?:Width|-width)?\s*:\s*["'`]?\s*([\d.]+(?:px|rem|em)?)(?![\w.])/g;
  for (const m of line.matchAll(re)) {
    const px = lengthPx(m[1]);
    if (px !== null && px >= 2) return true;
  }
  return false;
}

/** shadow-[0_1px_2px_...], hover:shadow-[...]. shadow-[var(--...)] (a Primer
 *  shadow variable) passes. */
export const ARBITRARY_SHADOW_CLASS = /(?:^|[^\w-])(?:[\w-]+:)*shadow-\[(?!\s*var\()/;
/** boxShadow: "0 1px 2px ...", box-shadow: inset ... A quoted value other than
 *  none, a var() or a template, or an unquoted number or `inset`, is a literal.
 *  An unquoted identifier (boxShadow: theShadow) is a variable and passes. */
export const LITERAL_SHADOW_STYLE =
  /\b(?:boxShadow|box-shadow)\s*:\s*(?:["'`]\s*(?!none\b|var\(|inherit\b|initial\b|unset\b|["'`]|\$\{)\S|(?:\d|\.\d|inset\b))/;
/** rounded-[10px], rounded-tl-[4px], md:rounded-[1.5rem]. rounded-[var(--...)]
 *  (a Primer radius variable) passes. */
export const ARBITRARY_RADIUS_CLASS =
  /(?:^|[^\w-])(?:[\w-]+:)*rounded(?:-(?:[trblse]|tl|tr|bl|br|ss|se|es|ee))?-\[(?!\s*var\()/;
/** borderRadius: 8, borderRadius: 0.5, borderTopLeftRadius: "4px", "0.375rem",
 *  "0px 4px", border-radius: 6px. Only a single zero (0, "0px", "0rem") or a
 *  var() / identifier passes. */
export const LITERAL_RADIUS_STYLE =
  /\b(?:border(?:[A-Z][a-z]+)*Radius|border(?:-[a-z]+)*-radius)\s*:\s*["'`]?\s*(?!0(?:px|rem|em|%)?\s*(?:["'`;,})]|$))(?:\d|\.\d)/;
