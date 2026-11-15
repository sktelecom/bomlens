// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { SearchIcon, ShieldCheckIcon, ShieldSlashIcon, SyncIcon } from "@primer/octicons-react";
import { Banner, Button, FormControl, Link, Select, Spinner, TextInput } from "@primer/react";
import { Blankslate } from "@primer/react/experimental";
import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { AdvisoryList } from "@/components/lookup/AdvisoryList";
import { ScreenHeader } from "@/components/primer";
import {
  getAdvisory,
  getPackageAdvisories,
  LookupError,
  type AdvisoryResult,
  type LookupErrorKind,
  type PackageAdvisoriesResult,
} from "@/lib/api";
import { ECOSYSTEM_SLUGS, parseLookupInput, type EcosystemSlug } from "@/lib/lookup";
import { homeHash, type RouteQuery } from "@/lib/route";

import "@/components/lookup/lookup.css";

interface Props {
  /** The query of `#/lookup?q=…&eco=…&ver=…` (a GlobalSearch pick or a shared
   *  link): `q` prefills the input and runs the lookup once on arrival; `eco`
   *  and `ver` complete a bare package name. Empty for a bare `#/lookup`. */
  query: RouteQuery;
  /** Report what was actually looked up, so the shell can make the URL reflect
   *  it (a shareable link) without this screen touching the hash itself. */
  onQueryChange?: (query: RouteQuery) => void;
}

type LookupResult =
  | { kind: "advisory"; result: AdvisoryResult }
  | { kind: "package"; result: PackageAdvisoriesResult };

type Failure = Exclude<LookupErrorKind, "disabled">;

const ERROR_KEY: Record<Failure, string> = {
  offline: "lookup.errorOffline",
  upstream: "lookup.errorUpstream",
  busy: "lookup.errorBusy",
  unreachable: "lookup.errorUnreachable",
  invalid: "lookup.errorInvalid",
};

const EXAMPLES = ["CVE-2021-44228", "GHSA-35jh-r3h4-6jhm", "pkg:npm/lodash@4.17.21"];

const isEcosystem = (s: string | undefined): s is EcosystemSlug =>
  Boolean(s) && (ECOSYSTEM_SLUGS as string[]).includes(s as string);

/**
 * External vulnerability lookup (`#/lookup`): a CVE/GHSA id, a purl, or a
 * package name + version, checked live against OSV.dev via the server (see
 * `lib/api.ts`). Reachable with or without a scan loaded; `NextApp` hides
 * every entry point (and this route) when `capabilities.externalLookup` is
 * off, so the "turned off" notice here is defensive only.
 */
export function ExternalLookup({ query, onQueryChange }: Props) {
  const { t } = useTranslation();
  const [input, setInput] = useState(query.q ?? "");
  const [ecosystem, setEcosystem] = useState<EcosystemSlug | "">(isEcosystem(query.eco) ? query.eco : "");
  const [version, setVersion] = useState(query.ver ?? "");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LookupResult | null>(null);
  const [errorKind, setErrorKind] = useState<LookupErrorKind | null>(null);
  const lastRun = useRef<{ term: string; eco: EcosystemSlug | ""; ver: string } | null>(null);
  const seq = useRef(0);

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
    async (term: string, eco: EcosystemSlug | "", ver: string) => {
      const p = parseLookupInput(term);
      // Any newer call, even one that ends right here, makes an older request's answer stale.
      const mine = ++seq.current;
      if (p.kind === "empty" || p.kind === "unsupportedPurl") {
        setLoading(false);
        setResult(null);
        setErrorKind(p.kind === "unsupportedPurl" ? "invalid" : null);
        return;
      }
      lastRun.current = { term, eco, ver };
      setLoading(true);
      setErrorKind(null);
      setResult(null);
      try {
        if (p.kind === "advisory") {
          const res = await getAdvisory(p.id);
          if (mine !== seq.current) return;
          setResult({ kind: "advisory", result: res });
          onQueryChange?.({ q: term });
        } else {
          const ecosystemSlug = p.ecosystem || eco || undefined;
          const versionText = p.version || ver;
          if (!ecosystemSlug || !versionText || !p.name) {
            setErrorKind("invalid");
            return;
          }
          const res = await getPackageAdvisories(ecosystemSlug, p.name, versionText);
          if (mine !== seq.current) return;
          setResult({ kind: "package", result: res });
          // A name typed alone needs the picked ecosystem and version to be
          // found again from the link.
          onQueryChange?.({
            q: term,
            ...(p.ecosystem ? {} : { eco: ecosystemSlug }),
            ...(p.version ? {} : { ver: versionText }),
          });
        }
      } catch (e) {
        if (mine !== seq.current) return;
        setErrorKind(e instanceof LookupError ? e.kind : "unreachable");
      } finally {
        if (mine === seq.current) setLoading(false);
      }
    },
    [onQueryChange],
  );

  // Auto-run once per distinct incoming query (a GlobalSearch pick or a shared
  // link), without re-firing on every render, and without clobbering the
  // user's own typing on the fields this screen owns thereafter.
  const lastAuto = useRef<string | undefined>(undefined);
  useEffect(() => {
    const key = `${query.q}|${query.eco}|${query.ver}`;
    if (!query.q || lastAuto.current === key) return;
    lastAuto.current = key;
    // What the term itself says wins over the separate keys, so the values the
    // input sync filled in are not overwritten by a stale `eco` or `ver`.
    const p = parseLookupInput(query.q);
    const eco = p.kind === "package" && p.ecosystem ? p.ecosystem : isEcosystem(query.eco) ? query.eco : "";
    const ver = p.kind === "package" && p.version ? p.version : (query.ver ?? "");
    setInput(query.q);
    setEcosystem(eco);
    setVersion(ver);
    void runLookup(query.q, eco, ver);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query.q, query.eco, query.ver]);

  const needsEcosystemPicker = parsed.kind === "package" && !parsed.ecosystem;
  const needsVersionInput = parsed.kind === "package" && !parsed.version;
  const resolvedEcosystem = parsed.kind === "package" ? parsed.ecosystem || ecosystem || undefined : undefined;
  const resolvedVersion = parsed.kind === "package" ? parsed.version || version : undefined;
  const canSubmit =
    parsed.kind === "advisory" ||
    (parsed.kind === "package" && Boolean(parsed.name && resolvedEcosystem && resolvedVersion));

  const caption =
    parsed.kind === "empty"
      ? t("lookup.captionEmpty")
      : parsed.kind === "package" && !canSubmit
        ? t("lookup.captionPackage")
        : null;

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    void runLookup(input, ecosystem, version);
  };

  const retry = () => {
    const last = lastRun.current;
    if (last) void runLookup(last.term, last.eco, last.ver);
  };

  return (
    <div className="bl-stack">
      <ScreenHeader title={t("lookup.title")} description={t("lookup.subtitle")} />

      <section className="bl-box">
        <form className="bl-lk-form" onSubmit={onSubmit}>
          <FormControl id="lookup-input" className="bl-lk-input">
            <FormControl.Label>{t("lookup.inputLabel")}</FormControl.Label>
            {caption && <FormControl.Caption>{caption}</FormControl.Caption>}
            <TextInput
              block
              leadingVisual={SearchIcon}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={t("lookup.inputPlaceholder")}
              autoComplete="off"
              spellCheck={false}
            />
          </FormControl>
          {needsEcosystemPicker && (
            <FormControl id="lookup-ecosystem" className="bl-lk-eco">
              <FormControl.Label>{t("lookup.ecosystemLabel")}</FormControl.Label>
              <Select block value={ecosystem} onChange={(e) => setEcosystem(e.target.value as EcosystemSlug | "")}>
                <Select.Option value="">{t("lookup.ecosystemPlaceholder")}</Select.Option>
                {ECOSYSTEM_SLUGS.map((slug) => (
                  <Select.Option key={slug} value={slug}>
                    {t(`lookup.ecosystem.${slug}`)}
                  </Select.Option>
                ))}
              </Select>
            </FormControl>
          )}
          {needsVersionInput && (
            <FormControl id="lookup-version" className="bl-lk-ver">
              <FormControl.Label>{t("lookup.versionLabel")}</FormControl.Label>
              <TextInput
                block
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                placeholder={t("lookup.versionPlaceholder")}
                autoComplete="off"
              />
            </FormControl>
          )}
          <Button type="submit" variant="primary" leadingVisual={SearchIcon} disabled={!canSubmit || loading}>
            {t("lookup.submit")}
          </Button>
        </form>
        {parsed.kind === "unsupportedPurl" && (
          <p className="bl-lk-unsupported">{t("lookup.unsupportedPurl", { type: parsed.type })}</p>
        )}
        <p className="bl-lk-note">{t("lookup.formats")}</p>
      </section>

      {loading && (
        <div className="bl-box bl-lk-state" role="status">
          <Spinner size="small" srText={null} />
          <span className="bl-muted">{t("lookup.searching")}</span>
        </div>
      )}

      {!loading && errorKind === "disabled" && (
        <Banner
          variant="warning"
          title={t("lookup.disabledTitle")}
          description={t("lookup.disabledBody")}
          primaryAction={
            <Banner.PrimaryAction as="a" href={homeHash()}>
              {t("lookup.goHome")}
            </Banner.PrimaryAction>
          }
        />
      )}

      {!loading && errorKind && errorKind !== "disabled" && (
        <Banner
          variant={errorKind === "unreachable" ? "critical" : "warning"}
          title={t(ERROR_KEY[errorKind])}
          primaryAction={
            errorKind !== "invalid" && lastRun.current ? (
              <Banner.PrimaryAction leadingVisual={SyncIcon} onClick={retry}>
                {t("retry")}
              </Banner.PrimaryAction>
            ) : undefined
          }
        />
      )}

      {!loading && !errorKind && !result && parsed.kind === "empty" && (
        <div className="bl-box" data-testid="lookup-examples">
          <Blankslate>
            <Blankslate.Visual>
              <SearchIcon size={24} />
            </Blankslate.Visual>
            <Blankslate.Heading as="h2">{t("lookup.emptyTitle")}</Blankslate.Heading>
            <Blankslate.Description>{t("lookup.emptyHint")}</Blankslate.Description>
            <div className="bl-lk-examples">
              {EXAMPLES.map((ex) => (
                <Link key={ex} as="button" type="button" className="bl-mono" onClick={() => setInput(ex)}>
                  {ex}
                </Link>
              ))}
            </div>
          </Blankslate>
        </div>
      )}

      {!loading && !errorKind && result?.kind === "advisory" &&
        (result.result.found ? (
          <AdvisoryList items={[result.result]} open />
        ) : (
          <div className="bl-box">
            <Blankslate>
              <Blankslate.Visual>
                <ShieldSlashIcon size={24} />
              </Blankslate.Visual>
              <Blankslate.Heading as="h2">{t("lookup.notFound")}</Blankslate.Heading>
              <Blankslate.Description>{t("lookup.notFoundHint")}</Blankslate.Description>
            </Blankslate>
          </div>
        ))}

      {!loading && !errorKind && result?.kind === "package" &&
        (result.result.found ? (
          <>
            {result.result.truncated && <Banner variant="warning" title={t("lookup.truncated")} />}
            <AdvisoryList items={result.result.items} />
          </>
        ) : (
          <div className="bl-box">
            <Blankslate>
              <Blankslate.Visual>
                <ShieldCheckIcon size={24} />
              </Blankslate.Visual>
              <Blankslate.Heading as="h2">{t("lookup.packageClean")}</Blankslate.Heading>
              <Blankslate.Description>{t("lookup.notFoundHint")}</Blankslate.Description>
            </Blankslate>
          </div>
        ))}
    </div>
  );
}
