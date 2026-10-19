// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Boxes, ScanSearch, Search, ShieldAlert } from "lucide-react";
import { type KeyboardEvent, useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Input } from "@/components/ui/input";
import type { DoneEvent } from "@/lib/api";
import { parseLookupInput } from "@/lib/lookup";
import { isAppleKeyboard } from "@/lib/platform";
import type { SectionId } from "@/lib/nav";
import { searchScan } from "@/lib/search";

/**
 * Cross-section quick search in the top bar (shown only with a scan loaded).
 * Type to find a component or CVE from anywhere; picking a result routes to its
 * section with the term pre-applied. Lives in the chrome (outside `main`), so it
 * doesn't touch the result-section visual snapshots.
 *
 * Keyboard follows the APG combobox-with-listbox pattern: focus stays in the
 * input and the active option is named by `aria-activedescendant` rather than
 * moved to. Options are therefore not tab stops and carry no tabIndex — a
 * screen reader announces the active one because the input points at it.
 */
export function GlobalSearch({
  result,
  onPick,
  onLookup,
}: {
  result: DoneEvent;
  /** Navigate to a section with the chosen term applied to its search. */
  onPick: (section: SectionId, term: string) => void;
  /**
   * Route to the External lookup screen (`#/lookup?q=…`) with the typed term.
   * Absent hides the row entirely, which is how the caller says
   * `capabilities.externalLookup` is off (or this is the static demo)
   * without this component needing to know why. Never called on every
   * keystroke: picking this row only navigates, the destination screen makes
   * the actual request.
   */
  onLookup?: (term: string) => void;
}) {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const blurTimer = useRef<number>();
  const inputRef = useRef<HTMLInputElement>(null);
  const baseId = useId();

  const { components, vulns } = searchScan(result, query);
  const hasResults = components.length > 0 || vulns.length > 0;
  const show = open && query.trim().length > 0;
  // Offered when the term looks like an advisory id (CVE/GHSA/…), since this
  // scan's own inventory can't answer that, or when nothing here matched at all.
  const trimmedQuery = query.trim();
  const showLookup =
    Boolean(onLookup) &&
    show &&
    (parseLookupInput(trimmedQuery).kind === "advisory" || !hasResults);

  // One flat list so arrow keys cross every group boundary without special
  // cases; the lookup row (when offered) is always last.
  type Option =
    | { kind: "pick"; section: SectionId; term: string }
    | { kind: "lookup"; term: string };
  const options: Option[] = [
    ...components.map((c) => ({ kind: "pick" as const, section: "components" as SectionId, term: c.name })),
    ...vulns.map((v) => ({ kind: "pick" as const, section: "vulnerabilities" as SectionId, term: v.id })),
    ...(showLookup ? [{ kind: "lookup" as const, term: trimmedQuery }] : []),
  ];
  const lookupIdx = showLookup ? options.length - 1 : -1;
  // A shrinking result set can strand the index past the end.
  const activeIdx = active >= 0 && active < options.length ? active : -1;

  const listboxId = `${baseId}-listbox`;
  const optionId = (i: number) => `${baseId}-opt-${i}`;
  const componentsHeadingId = `${baseId}-h-components`;
  const vulnsHeadingId = `${baseId}-h-vulns`;
  const lookupHeadingId = `${baseId}-h-lookup`;

  const activate = (opt: Option) => {
    if (opt.kind === "lookup") onLookup?.(opt.term);
    else onPick(opt.section, opt.term);
    setQuery("");
    setOpen(false);
    setActive(-1);
  };

  // Keep the active option in view when arrowing past the visible window.
  useEffect(() => {
    if (activeIdx < 0) return;
    document.getElementById(optionId(activeIdx))?.scrollIntoView({ block: "nearest" });
    // optionId is derived from baseId, which is stable for the component's life.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeIdx, baseId]);

  // Cmd/Ctrl+K from anywhere in the app focuses the search.
  useEffect(() => {
    const onShortcut = (e: globalThis.KeyboardEvent) => {
      if (e.key.toLowerCase() !== "k" || !(e.metaKey || e.ctrlKey)) return;
      e.preventDefault();
      inputRef.current?.focus();
      inputRef.current?.select();
    };
    window.addEventListener("keydown", onShortcut);
    return () => window.removeEventListener("keydown", onShortcut);
  }, []);

  const move = (delta: number) => {
    if (!options.length) return;
    setActive((prev) => {
      const next = (prev < 0 ? (delta > 0 ? -1 : 0) : prev) + delta;
      if (next < 0) return options.length - 1;
      if (next >= options.length) return 0;
      return next;
    });
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Escape") {
      setOpen(false);
      setActive(-1);
      e.currentTarget.blur();
      return;
    }
    if (!show) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      move(1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      move(-1);
    } else if (e.key === "Home" && options.length) {
      e.preventDefault();
      setActive(0);
    } else if (e.key === "End" && options.length) {
      e.preventDefault();
      setActive(options.length - 1);
    } else if (e.key === "Enter") {
      // No arrowing yet: Enter takes the first result, as it always has.
      const target = options[activeIdx] ?? options[0];
      if (target) activate(target);
    }
  };

  const optionClass = (i: number) =>
    [
      "flex w-full cursor-pointer items-center gap-2 px-3 py-1.5 text-left",
      i === activeIdx ? "bg-muted" : "hover:bg-muted",
    ].join(" ");

  return (
    <div className="relative hidden min-w-0 md:block">
      <Search
        className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
        aria-hidden
      />
      <Input
        ref={inputRef}
        type="search"
        role="combobox"
        aria-expanded={show}
        aria-controls={show ? listboxId : undefined}
        aria-activedescendant={activeIdx >= 0 ? optionId(activeIdx) : undefined}
        aria-autocomplete="list"
        aria-keyshortcuts="Meta+K Control+K"
        data-testid="global-search"
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
          setActive(-1);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => {
          blurTimer.current = window.setTimeout(() => setOpen(false), 120);
        }}
        onKeyDown={onKeyDown}
        placeholder={t("search.placeholder")}
        aria-label={t("search.placeholder")}
        className="h-8 w-56 pl-8 pr-3 lg:w-72 lg:pr-14"
      />
      <kbd
        className="pointer-events-none absolute right-2 top-1/2 hidden -translate-y-1/2 select-none rounded border bg-muted px-1.5 py-0.5 font-sans text-caption font-medium text-muted-foreground lg:block"
        aria-hidden
      >
        {isAppleKeyboard() ? "⌘K" : "Ctrl K"}
      </kbd>
      {show && (
        <div
          id={listboxId}
          role="listbox"
          aria-label={t("search.placeholder")}
          className="absolute left-0 top-full z-30 mt-1 w-80 max-w-[90vw] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-lg"
          // Keep the input focused through the click so onClick fires before blur.
          onMouseDown={(e) => {
            e.preventDefault();
            window.clearTimeout(blurTimer.current);
          }}
        >
          {!hasResults && !showLookup ? (
            <p className="px-3 py-3 text-body-sm text-muted-foreground">{t("search.none")}</p>
          ) : (
            <div className="max-h-80 overflow-auto py-1 text-body-sm">
              {components.length > 0 && (
                <div role="group" aria-labelledby={componentsHeadingId}>
                  <div
                    id={componentsHeadingId}
                    className="px-3 pb-1 pt-2 text-label font-semibold uppercase tracking-wider text-muted-foreground"
                  >
                    {t("search.components")}
                  </div>
                  {components.map((c, i) => (
                    <div
                      key={`c-${c.purl || c.name}-${i}`}
                      id={optionId(i)}
                      role="option"
                      aria-selected={i === activeIdx}
                      onClick={() => activate({ kind: "pick", section: "components", term: c.name })}
                      className={optionClass(i)}
                    >
                      <Boxes className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
                      <span className="truncate">{c.name}</span>
                      {c.version && (
                        <span className="shrink-0 text-label text-muted-foreground">{c.version}</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
              {vulns.length > 0 && (
                <div role="group" aria-labelledby={vulnsHeadingId}>
                  <div
                    id={vulnsHeadingId}
                    className="px-3 pb-1 pt-2 text-label font-semibold uppercase tracking-wider text-muted-foreground"
                  >
                    {t("search.vulnerabilities")}
                  </div>
                  {vulns.map((v, i) => (
                    <div
                      key={`v-${v.id}-${i}`}
                      id={optionId(components.length + i)}
                      role="option"
                      aria-selected={components.length + i === activeIdx}
                      onClick={() => activate({ kind: "pick", section: "vulnerabilities", term: v.id })}
                      className={optionClass(components.length + i)}
                    >
                      <ShieldAlert
                        className="h-3.5 w-3.5 shrink-0 text-muted-foreground"
                        aria-hidden
                      />
                      <span className="truncate font-mono text-label">{v.id}</span>
                      <span className="shrink-0 text-label text-muted-foreground">{v.pkg}</span>
                    </div>
                  ))}
                </div>
              )}
              {showLookup && (
                <div role="group" aria-labelledby={lookupHeadingId}>
                  <div
                    id={lookupHeadingId}
                    className="px-3 pb-1 pt-2 text-label font-semibold uppercase tracking-wider text-muted-foreground"
                  >
                    {t("search.lookupGroup")}
                  </div>
                  <div
                    id={optionId(lookupIdx)}
                    role="option"
                    aria-selected={lookupIdx === activeIdx}
                    onClick={() => activate({ kind: "lookup", term: trimmedQuery })}
                    className={optionClass(lookupIdx)}
                  >
                    <ScanSearch className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
                    <span className="truncate">
                      {t("search.lookupExternal", { term: trimmedQuery })}
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
