// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { AlertTriangle, ExternalLink, ScanSearch, ShieldOff } from "lucide-react";
import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/state";
import {
  getAdvisory,
  getPackageAdvisories,
  LookupError,
  type AdvisoryRecord,
  type AdvisoryResult,
  type LookupErrorKind,
  type PackageAdvisoriesResult,
} from "@/lib/api";
import {
  ECOSYSTEM_SLUGS,
  parseLookupInput,
  type EcosystemSlug,
} from "@/lib/lookup";
import { homeHash } from "@/lib/route";
import { severityTone } from "@/lib/severity";

/** Display name for each ecosystem slug: OSV's own spelling, since that's
 *  the least ambiguous choice and matches what the server sends it as. */
const ECOSYSTEM_LABEL_KEY: Record<EcosystemSlug, string> = {
  npm: "lookup.ecosystem.npm",
  pypi: "lookup.ecosystem.pypi",
  maven: "lookup.ecosystem.maven",
  go: "lookup.ecosystem.go",
  cargo: "lookup.ecosystem.cargo",
  rubygems: "lookup.ecosystem.rubygems",
  packagist: "lookup.ecosystem.packagist",
  nuget: "lookup.ecosystem.nuget",
};

/** Human-readable date; falls back to the raw string if it doesn't parse. */
function formatDate(iso: string, locale: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(locale, { dateStyle: "medium" });
}

/** Best-effort summary of one OSV range object. Ranges are typed `unknown` on
 *  the wire (server.py passes them through unshaped), so this reads
 *  defensively rather than assuming every event carries every field. */
function formatRange(range: unknown): string {
  if (!range || typeof range !== "object") return "";
  const events = (range as { events?: unknown }).events;
  if (!Array.isArray(events)) return "";
  const parts = events
    .map((e) => {
      if (!e || typeof e !== "object") return "";
      const ev = e as Record<string, string>;
      if (ev.introduced !== undefined) return `>= ${ev.introduced || "0"}`;
      if (ev.fixed !== undefined) return `< ${ev.fixed}`;
      if (ev.last_affected !== undefined) return `<= ${ev.last_affected}`;
      if (ev.limit !== undefined) return `< ${ev.limit}`;
      return "";
    })
    .filter(Boolean);
  return parts.join(", ");
}

/** One found advisory's full detail, shared by the single-id lookup and each
 *  row of a package lookup's `items`. */
function AdvisoryCard({ advisory }: { advisory: AdvisoryRecord }) {
  const { t, i18n } = useTranslation();
  return (
    <Card>
      <CardContent className="space-y-3 p-5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-body-sm font-medium">{advisory.id}</span>
          <Badge tone={severityTone(advisory.severity)} mark>
            {t(`severity.${advisory.severity}`)}
          </Badge>
          {advisory.withdrawn && (
            <Badge tone="none" variant="destructive">
              {t("lookup.withdrawn")}
            </Badge>
          )}
        </div>
        {advisory.title && (
          <p className="text-body-sm font-medium text-foreground">{advisory.title}</p>
        )}
        {advisory.cvss != null && (
          <div className="flex flex-wrap items-baseline gap-2 text-body-sm">
            <span className="font-medium">{t("lookup.cvss")}</span>
            <span className="tabular-nums">{advisory.cvss}</span>
            {advisory.cvssVector && (
              <span className="font-mono text-label text-muted-foreground">
                {advisory.cvssVector}
              </span>
            )}
          </div>
        )}
        {(advisory.published || advisory.modified) && (
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-label text-muted-foreground">
            {advisory.published && (
              <span>
                {t("lookup.published")}: {formatDate(advisory.published, i18n.language)}
              </span>
            )}
            {advisory.modified && (
              <span>
                {t("lookup.modified")}: {formatDate(advisory.modified, i18n.language)}
              </span>
            )}
          </div>
        )}
        {advisory.description && (
          <p className="max-w-3xl text-body-sm leading-relaxed text-muted-foreground">
            {advisory.description}
          </p>
        )}
        {advisory.aliases.length > 0 && (
          <div className="space-y-1">
            <div className="text-label font-medium text-foreground">{t("lookup.aliases")}</div>
            <div className="flex flex-wrap gap-1.5">
              {advisory.aliases.map((a) => (
                <Badge key={a} variant="muted">
                  {a}
                </Badge>
              ))}
            </div>
          </div>
        )}
        {advisory.affected.length > 0 && (
          <div className="space-y-1">
            <div className="text-label font-medium text-foreground">{t("lookup.affected")}</div>
            <ul className="space-y-1 text-label text-muted-foreground">
              {advisory.affected.map((a, i) => (
                <li key={`${a.ecosystem}-${a.name}-${i}`} className="font-mono">
                  {a.ecosystem ? `${a.ecosystem}: ` : ""}
                  {a.name}
                  {a.versions && a.versions.length > 0 && ` @ ${a.versions.join(", ")}`}
                  {a.ranges && a.ranges.length > 0 && (
                    <span> ({a.ranges.map(formatRange).filter(Boolean).join("; ")})</span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
        {advisory.refs.length > 0 && (
          <div className="space-y-1">
            <div className="text-label font-medium text-foreground">{t("lookup.references")}</div>
            <ul className="space-y-0.5">
              {advisory.refs.map((href) => (
                <li key={href}>
                  <a
                    href={href}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 break-all text-label text-primary underline-offset-2 hover:underline"
                  >
                    <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
                    {href}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface Props {
  /** The `q` param from `#/lookup?q=…` (a GlobalSearch pick or a shared
   *  link), prefills the input and runs the lookup once on arrival.
   *  Absent/empty for a bare `#/lookup` visit (nothing runs). */
  initialQuery?: string;
  /** Report the term actually looked up, so the shell can make the URL
   *  reflect it (a shareable link), without this screen touching the hash
   *  itself. */
  onQueryChange?: (term: string) => void;
}

type LookupResult =
  | { kind: "advisory"; result: AdvisoryResult }
  | { kind: "package"; result: PackageAdvisoriesResult };

/**
 * External vulnerability lookup (`#/lookup`): a CVE/GHSA id, a purl, or a
 * package name + version, checked live against OSV.dev via the server (see
 * `lib/api.ts`). Reachable with or without a scan loaded; `NextApp` hides
 * every entry point (and this route) when `capabilities.externalLookup` is
 * off, so reaching the "disabled" response here is defensive only.
 */
export function ExternalLookup({ initialQuery, onQueryChange }: Props) {
  const { t } = useTranslation();
  const [input, setInput] = useState(initialQuery ?? "");
  const [ecosystem, setEcosystem] = useState<EcosystemSlug | "">("");
  const [version, setVersion] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LookupResult | null>(null);
  const [errorKind, setErrorKind] = useState<LookupErrorKind | null>(null);

  const parsed = parseLookupInput(input);

  // Sync the ecosystem/version fields from whatever the input itself
  // resolves (a purl's type, a "name@version" split) without clobbering a
  // value the user picked independently (a bare name typed after a purl).
  useEffect(() => {
    if (parsed.kind !== "package") return;
    if (parsed.ecosystem) setEcosystem(parsed.ecosystem);
    if (parsed.version) setVersion(parsed.version);
    // Only the classification should drive this, not every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [input]);

  const runLookup = useCallback(
    async (term: string) => {
      const p = parseLookupInput(term);
      if (p.kind === "empty" || p.kind === "unsupportedPurl") {
        setResult(null);
        setErrorKind(p.kind === "unsupportedPurl" ? "invalid" : null);
        return;
      }
      setLoading(true);
      setErrorKind(null);
      setResult(null);
      try {
        if (p.kind === "advisory") {
          const res = await getAdvisory(p.id);
          setResult({ kind: "advisory", result: res });
        } else {
          const eco = p.ecosystem || (ecosystem || undefined);
          const ver = p.version || version;
          if (!eco || !ver || !p.name) {
            setErrorKind("invalid");
            return;
          }
          const res = await getPackageAdvisories(eco, p.name, ver);
          setResult({ kind: "package", result: res });
        }
        onQueryChange?.(term);
      } catch (e) {
        const kind = e instanceof LookupError ? e.kind : "unreachable";
        if (kind === "disabled") {
          // The screen should never be reachable in this state: the shell
          // hides every entry point when externalLookup is off. Reaching
          // this is defensive only, so just leave.
          window.location.hash = homeHash();
          return;
        }
        setErrorKind(kind);
      } finally {
        setLoading(false);
      }
    },
    [ecosystem, version, onQueryChange],
  );

  // Auto-run once per distinct incoming `q` (a GlobalSearch pick or a
  // shared link), without re-firing on every render, and without clobbering
  // the user's own typing on the input this screen owns thereafter.
  const lastAutoRef = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (!initialQuery || lastAutoRef.current === initialQuery) return;
    lastAutoRef.current = initialQuery;
    setInput(initialQuery);
    void runLookup(initialQuery);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialQuery]);

  const needsEcosystemPicker = parsed.kind === "package" && !parsed.ecosystem;
  const needsVersionInput = parsed.kind === "package" && !parsed.version;
  const resolvedEcosystem =
    parsed.kind === "package" ? parsed.ecosystem || (ecosystem || undefined) : undefined;
  const resolvedVersion = parsed.kind === "package" ? parsed.version || version : undefined;
  const canSubmit =
    parsed.kind === "advisory" ||
    (parsed.kind === "package" && Boolean(parsed.name && resolvedEcosystem && resolvedVersion));

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    void runLookup(input);
  };

  return (
    <div className="space-y-6">
      <div className="space-y-1.5">
        <h1 className="text-display font-semibold tracking-tight text-foreground">
          {t("lookup.title")}
        </h1>
        <p className="max-w-2xl text-body-sm text-muted-foreground">{t("lookup.subtitle")}</p>
      </div>

      <Card>
        <CardContent className="p-5">
          <form className="flex flex-wrap items-end gap-3" onSubmit={onSubmit}>
            <div className="min-w-[16rem] flex-1 space-y-1.5">
              <Label htmlFor="lookup-input">{t("lookup.inputLabel")}</Label>
              <Input
                id="lookup-input"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={t("lookup.inputPlaceholder")}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            {needsEcosystemPicker && (
              <div className="w-48 space-y-1.5">
                <Label htmlFor="lookup-ecosystem">{t("lookup.ecosystemLabel")}</Label>
                <Select
                  id="lookup-ecosystem"
                  value={ecosystem}
                  onChange={(e) => setEcosystem(e.target.value as EcosystemSlug | "")}
                  className="w-full"
                >
                  <option value="">{t("lookup.ecosystemPlaceholder")}</option>
                  {ECOSYSTEM_SLUGS.map((slug) => (
                    <option key={slug} value={slug}>
                      {t(ECOSYSTEM_LABEL_KEY[slug])}
                    </option>
                  ))}
                </Select>
              </div>
            )}
            {needsVersionInput && (
              <div className="w-40 space-y-1.5">
                <Label htmlFor="lookup-version">{t("lookup.versionLabel")}</Label>
                <Input
                  id="lookup-version"
                  value={version}
                  onChange={(e) => setVersion(e.target.value)}
                  placeholder={t("lookup.versionPlaceholder")}
                  autoComplete="off"
                />
              </div>
            )}
            <Button type="submit" disabled={!canSubmit || loading} className="gap-1.5">
              <ScanSearch className="h-4 w-4" aria-hidden />
              {t("lookup.submit")}
            </Button>
          </form>
          {parsed.kind === "unsupportedPurl" && (
            <p className="mt-2 text-body-sm text-muted-foreground">
              {t("lookup.unsupportedPurl", { type: parsed.type })}
            </p>
          )}
        </CardContent>
      </Card>

      {loading && <LoadingState>{t("lookup.searching")}</LoadingState>}

      {!loading && errorKind && (
        <ErrorState>
          <span>
            {errorKind === "offline"
              ? t("lookup.errorOffline")
              : errorKind === "upstream"
                ? t("lookup.errorUpstream")
                : errorKind === "busy"
                  ? t("lookup.errorBusy")
                  : errorKind === "unreachable"
                    ? t("lookup.errorUnreachable")
                    : t("lookup.errorInvalid")}
          </span>
        </ErrorState>
      )}

      {!loading && !errorKind && result?.kind === "advisory" && (
        result.result.found ? (
          <AdvisoryCard advisory={result.result} />
        ) : (
          <EmptyState icon={ShieldOff} hint={t("lookup.notFoundHint")}>
            {t("lookup.notFound")}
          </EmptyState>
        )
      )}

      {!loading && !errorKind && result?.kind === "package" && (
        result.result.found ? (
          <div className="space-y-3">
            {result.result.truncated && (
              <p className="flex items-center gap-1.5 rounded-md border border-role-attention-border bg-role-attention-muted px-3 py-2 text-body-sm text-foreground">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-role-attention-fg" aria-hidden />
                {t("lookup.truncated")}
              </p>
            )}
            {result.result.items.map((a, i) => (
              <AdvisoryCard key={`${a.id}-${i}`} advisory={a} />
            ))}
          </div>
        ) : (
          <EmptyState icon={ScanSearch}>{t("lookup.packageClean")}</EmptyState>
        )
      )}
    </div>
  );
}
