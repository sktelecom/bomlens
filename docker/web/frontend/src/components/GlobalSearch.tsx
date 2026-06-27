import { Boxes, Search, ShieldAlert } from "lucide-react";
import { type KeyboardEvent, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Input } from "@/components/ui/input";
import type { DoneEvent } from "@/lib/api";
import type { SectionId } from "@/lib/nav";
import { searchScan } from "@/lib/search";

/**
 * Cross-section quick search in the top bar (shown only with a scan loaded).
 * Type to find a component or CVE from anywhere; picking a result routes to its
 * section with the term pre-applied. Lives in the chrome (outside `main`), so it
 * doesn't touch the result-section visual snapshots.
 */
export function GlobalSearch({
  result,
  onPick,
}: {
  result: DoneEvent;
  /** Navigate to a section with the chosen term applied to its search. */
  onPick: (section: SectionId, term: string) => void;
}) {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const blurTimer = useRef<number>();

  const { components, vulns } = searchScan(result, query);
  const hasResults = components.length > 0 || vulns.length > 0;
  const show = open && query.trim().length > 0;

  const pick = (section: SectionId, term: string) => {
    onPick(section, term);
    setQuery("");
    setOpen(false);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Escape") {
      setOpen(false);
      e.currentTarget.blur();
    } else if (e.key === "Enter") {
      if (components[0]) pick("components", components[0].name);
      else if (vulns[0]) pick("vulnerabilities", vulns[0].id);
    }
  };

  return (
    <div className="relative hidden min-w-0 md:block">
      <Search
        className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
        aria-hidden
      />
      <Input
        type="search"
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => {
          blurTimer.current = window.setTimeout(() => setOpen(false), 120);
        }}
        onKeyDown={onKeyDown}
        placeholder={t("search.placeholder")}
        aria-label={t("search.placeholder")}
        className="h-8 w-56 pl-8"
      />
      {show && (
        <div
          role="listbox"
          aria-label={t("search.placeholder")}
          className="absolute left-0 top-full z-30 mt-1 w-80 max-w-[90vw] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-lg"
          // Keep the input focused through the click so onClick fires before blur.
          onMouseDown={(e) => {
            e.preventDefault();
            window.clearTimeout(blurTimer.current);
          }}
        >
          {!hasResults ? (
            <p className="px-3 py-3 text-sm text-muted-foreground">{t("search.none")}</p>
          ) : (
            <ul className="max-h-80 overflow-auto py-1 text-sm">
              {components.length > 0 && (
                <li className="px-3 pb-1 pt-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  {t("search.components")}
                </li>
              )}
              {components.map((c, i) => (
                <li key={`c-${c.purl || c.name}-${i}`}>
                  <button
                    type="button"
                    onClick={() => pick("components", c.name)}
                    className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-muted focus-visible:bg-muted focus-visible:outline-none"
                  >
                    <Boxes className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
                    <span className="truncate">{c.name}</span>
                    {c.version && (
                      <span className="shrink-0 text-xs text-muted-foreground">{c.version}</span>
                    )}
                  </button>
                </li>
              ))}
              {vulns.length > 0 && (
                <li className="px-3 pb-1 pt-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  {t("search.vulnerabilities")}
                </li>
              )}
              {vulns.map((v, i) => (
                <li key={`v-${v.id}-${i}`}>
                  <button
                    type="button"
                    onClick={() => pick("vulnerabilities", v.id)}
                    className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-muted focus-visible:bg-muted focus-visible:outline-none"
                  >
                    <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
                    <span className="truncate font-mono text-xs">{v.id}</span>
                    <span className="shrink-0 text-xs text-muted-foreground">{v.pkg}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
