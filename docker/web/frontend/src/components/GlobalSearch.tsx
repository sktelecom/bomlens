// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { GlobeIcon, ListUnorderedIcon, PackageIcon, SearchIcon, XCircleFillIcon } from "@primer/octicons-react";
import { TextInput } from "@primer/react";
import { type KeyboardEvent, useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import type { DoneEvent } from "@/lib/api";
import { parseLookupInput } from "@/lib/lookup";
import type { SectionId } from "@/lib/nav";
import { isAppleKeyboard } from "@/lib/platform";
import { PACKAGE_SEPARATOR, SeverityLabel, splitPackage } from "@/components/primer";
import { searchScan } from "@/lib/search";

/**
 * Cross-section quick search in the top bar (shown only with a scan loaded).
 * Type to find a component or CVE from anywhere; picking a result routes to its
 * section with the term pre-applied.
 *
 * Keyboard follows the APG combobox-with-listbox pattern: focus stays in the
 * input and the active option is named by `aria-activedescendant` rather than
 * moved to. Options are therefore not tab stops and carry no tabIndex; a
 * screen reader announces the active one because the input points at it.
 */
export function GlobalSearch({
  result,
  onPick,
  onLookup,
  width,
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
  /** Box width in px (narrower when the top bar is short of room). */
  width: number;
}) {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const blurTimer = useRef<number>();
  const inputRef = useRef<HTMLInputElement>(null);
  const baseId = useId();

  const { components, vulns, componentTotal, vulnTotal } = searchScan(result, query, GROUP_CAP);
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
  // A group cut at its cap ends with a row that opens the section filtered
  // to the typed term, where every match is listed.
  const moreComponents = componentTotal > components.length;
  const moreVulns = vulnTotal > vulns.length;
  const options: Option[] = [
    ...components.map((c) => ({ kind: "pick" as const, section: "components" as SectionId, term: c.name })),
    ...(moreComponents ? [{ kind: "pick" as const, section: "components" as SectionId, term: trimmedQuery }] : []),
    ...vulns.map((v) => ({ kind: "pick" as const, section: "vulnerabilities" as SectionId, term: v.id })),
    ...(moreVulns ? [{ kind: "pick" as const, section: "vulnerabilities" as SectionId, term: trimmedQuery }] : []),
    ...(showLookup ? [{ kind: "lookup" as const, term: trimmedQuery }] : []),
  ];
  const moreComponentsIdx = moreComponents ? components.length : -1;
  const vulnBase = components.length + (moreComponents ? 1 : 0);
  const moreVulnsIdx = moreVulns ? vulnBase + vulns.length : -1;
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

  return (
    <div className="bl-search">
      <TextInput
        ref={inputRef}
        type="text"
        role="combobox"
        aria-expanded={show}
        aria-controls={show ? listboxId : undefined}
        aria-activedescendant={activeIdx >= 0 ? optionId(activeIdx) : undefined}
        aria-autocomplete="list"
        aria-keyshortcuts="Meta+K Control+K"
        aria-label={t("search.placeholder")}
        data-testid="global-search"
        leadingVisual={SearchIcon}
        // The shortcut hint while empty; a clear button once there is a term.
        trailingVisual={
          query ? undefined : (
            <kbd className="bl-kbd" aria-hidden>
              {isAppleKeyboard() ? "⌘K" : "Ctrl K"}
            </kbd>
          )
        }
        trailingAction={
          query ? (
            <TextInput.Action
              icon={XCircleFillIcon}
              aria-label={t("search.clear")}
              onClick={() => {
                setQuery("");
                setActive(-1);
                inputRef.current?.focus();
              }}
            />
          ) : undefined
        }
        placeholder={t("search.placeholder")}
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
        width={width}
      />
      {show && (
        <div
          id={listboxId}
          role="listbox"
          aria-label={t("search.placeholder")}
          className="bl-searchpop"
          // Keep the input focused through the click so onClick fires before blur.
          onMouseDown={(e) => {
            e.preventDefault();
            window.clearTimeout(blurTimer.current);
          }}
        >
          {/* Said before the lookup row too, so the row reads as the next step. */}
          {!hasResults && <p className="bl-searchpop-empty">{t("search.none")}</p>}
          {components.length > 0 && (
            <div role="group" aria-labelledby={componentsHeadingId}>
              <div id={componentsHeadingId} className="bl-searchpop-group">
                {t("search.components")}
              </div>
              {components.map((c, i) => (
                <div
                  key={`c-${c.purl || c.name}-${i}`}
                  id={optionId(i)}
                  role="option"
                  aria-selected={i === activeIdx}
                  onClick={() => activate({ kind: "pick", section: "components", term: c.name })}
                >
                  <PackageIcon size={16} />
                  <Coordinate group={c.group} name={c.name} />
                  {c.version && <span className="bl-searchpop-aside">{c.version}</span>}
                </div>
              ))}
              {moreComponents && (
                <ShowAll
                  id={optionId(moreComponentsIdx)}
                  selected={moreComponentsIdx === activeIdx}
                  label={t("search.showAllComponents", { count: componentTotal })}
                  onClick={() => activate({ kind: "pick", section: "components", term: trimmedQuery })}
                />
              )}
            </div>
          )}
          {vulns.length > 0 && (
            <div role="group" aria-labelledby={vulnsHeadingId}>
              <div id={vulnsHeadingId} className="bl-searchpop-group">
                {t("search.vulnerabilities")}
              </div>
              {vulns.map((v, i) => (
                <div
                  key={`v-${v.id}-${i}`}
                  id={optionId(vulnBase + i)}
                  role="option"
                  aria-selected={vulnBase + i === activeIdx}
                  onClick={() => activate({ kind: "pick", section: "vulnerabilities", term: v.id })}
                >
                  <span className="bl-searchpop-id">
                    <SeverityLabel severity={v.severity} size="small" />
                  </span>
                  <span className="bl-searchpop-id bl-searchpop-mono">{v.id}</span>
                  <span className="bl-searchpop-aside bl-searchpop-coordwrap">
                    <Coordinate {...splitPackage(v.pkg)} />
                  </span>
                </div>
              ))}
              {moreVulns && (
                <ShowAll
                  id={optionId(moreVulnsIdx)}
                  selected={moreVulnsIdx === activeIdx}
                  label={t("search.showAllVulns", { count: vulnTotal })}
                  onClick={() => activate({ kind: "pick", section: "vulnerabilities", term: trimmedQuery })}
                />
              )}
            </div>
          )}
          {showLookup && (
            <div role="group" aria-labelledby={lookupHeadingId}>
              <div id={lookupHeadingId} className="bl-searchpop-group">
                {t("search.lookupGroup")}
              </div>
              <div
                id={optionId(lookupIdx)}
                role="option"
                aria-selected={lookupIdx === activeIdx}
                onClick={() => activate({ kind: "lookup", term: trimmedQuery })}
              >
                <GlobeIcon size={16} />
                <span className="bl-searchpop-text">
                  {t("search.lookupExternal", { term: trimmedQuery })}
                </span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** Matches listed per group before its "View all" row. Five, so both groups'
 *  rows and the lookup row fit the popup without scrolling. */
const GROUP_CAP = 5;

/** "group / name" in one line: the group gives way first (ellipsis), the name
 *  stays whole, the full coordinate is the tooltip. */
function Coordinate({ group, name }: { group?: string; name: string }) {
  return (
    <span className="bl-searchpop-coord" title={group ? `${group}${PACKAGE_SEPARATOR}${name}` : name}>
      {group && <span className="bl-searchpop-coord-group">{group}</span>}
      {group && <span className="bl-searchpop-coord-sep">{PACKAGE_SEPARATOR}</span>}
      <span className="bl-searchpop-coord-name">{name}</span>
    </span>
  );
}

/** The last row of a group cut at its cap. */
function ShowAll({
  id,
  selected,
  label,
  onClick,
}: {
  id: string;
  selected: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <div id={id} role="option" aria-selected={selected} onClick={onClick} className="bl-searchpop-all">
      <ListUnorderedIcon size={16} />
      <span className="bl-searchpop-text">{label}</span>
    </div>
  );
}
