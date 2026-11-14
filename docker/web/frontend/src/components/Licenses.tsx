// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { LawIcon } from "@primer/octicons-react";
import { Banner } from "@primer/react";
import { Blankslate } from "@primer/react/experimental";
import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { TIER_LABEL_KEY } from "@/components/primer";
import type { ComponentItem } from "@/lib/api";
import { componentRiskTier, type LicenseRiskTier } from "@/lib/licenses";
import { buildQuery, parseQuery, type RouteQuery } from "@/lib/route";
import { licensesFromQuery, licensesToQuery } from "@/lib/section-query";

import { ConflictOff } from "./licenses/ConflictOff";
import { Conflicts } from "./licenses/Conflicts";
import { Distribution } from "./licenses/Distribution";
import { Obligations } from "./licenses/Obligations";
import { Review } from "./licenses/Review";
import { TierBar } from "./licenses/TierBar";

/** A tier in the URL that is none of the six: an old or mistyped link. */
function badTierOf(query: RouteQuery | undefined): string {
  const raw = query?.tier ?? "";
  return raw && !licensesFromQuery(query).tier ? raw : "";
}

/**
 * Licenses: the classification axis (copyleft strength) over the per-license
 * distribution, then the obligations a component list cannot express: conflicts
 * with the declared outbound license, terms that need human review, and what
 * each license asks of a redistributor. Picking a class (bar or legend) narrows
 * the distribution, conflicts, review and obligations boxes; the bar itself keeps
 * the whole scan's proportions. Picking a license opens the Components table
 * filtered to it.
 */
export function Licenses({
  components,
  query,
  onQueryChange,
  outboundLicense,
  licenseHref,
  onRescanWithLicense,
  rescanFieldAvailable = true,
}: {
  components: ComponentItem[];
  /** Tier filter as carried in the URL: a shared link, a reload, or a class
   *  routed in from an Overview classification-bar click. */
  query?: RouteQuery;
  /** Report the tier back so the URL can carry it. */
  onQueryChange?: (query: RouteQuery) => void;
  /** The license the project declares it ships under. Absent means the conflict
   *  check never ran, which the screen states outright rather than leaving the
   *  reader to read an empty table as an all-clear. */
  outboundLicense?: string;
  /** Where a license row goes: Components filtered to that license id. */
  licenseHref?: (license: string) => string;
  /** Open the New scan form on the outbound-license field. Absent where a
   *  re-scan is not possible (the read-only demo). */
  onRescanWithLicense?: () => void;
  /** The New scan form has an outbound-license field for this kind of scan. */
  rescanFieldAvailable?: boolean;
}) {
  const { t } = useTranslation();
  const [tier, setTier] = useState<LicenseRiskTier | "">(() => licensesFromQuery(query).tier);
  const [badTier, setBadTier] = useState(() => badTierOf(query));

  // The URL is the source; see ComponentsTable for why this compares strings.
  const urlQuery = buildQuery(query);
  const appliedRef = useRef(urlQuery);
  useEffect(() => {
    if (appliedRef.current === urlQuery) return;
    appliedRef.current = urlQuery;
    const next = parseQuery(urlQuery);
    setTier(licensesFromQuery(next).tier);
    setBadTier(badTierOf(next));
  }, [urlQuery]);

  const choose = (next: LicenseRiskTier | "") => {
    setTier(next);
    setBadTier("");
    const q = buildQuery(licensesToQuery(next));
    if (q === appliedRef.current) return;
    appliedRef.current = q;
    onQueryChange?.(parseQuery(q));
  };

  const filtered = useMemo(
    () => (tier ? components.filter((c) => componentRiskTier(c) === tier) : components),
    [tier, components],
  );

  if (components.length === 0) {
    return (
      <div className="bl-box" data-testid="licenses-empty">
        <Blankslate spacious>
          <Blankslate.Visual>
            <LawIcon size={24} />
          </Blankslate.Visual>
          <Blankslate.Heading as="h2">{t("licenses.empty")}</Blankslate.Heading>
          <Blankslate.Description>{t("licenses.emptyHint")}</Blankslate.Description>
        </Blankslate>
      </div>
    );
  }

  return (
    <div className="bl-stack bl-lic">
      {!outboundLicense && <ConflictOff fieldAvailable={rescanFieldAvailable} onRescan={onRescanWithLicense} />}
      {badTier && (
        <Banner
          variant="warning"
          data-testid="license-bad-tier"
          primaryAction={<Banner.PrimaryAction onClick={() => choose("")}>{t("result.clearFilters")}</Banner.PrimaryAction>}
        >
          <Banner.Title as={"p" as "h2"}>{t("licenses.badTierTitle")}</Banner.Title>
          <Banner.Description>{t("licenses.badTierBody", { tier: badTier })}</Banner.Description>
        </Banner>
      )}
      <TierBar
        components={components}
        selected={tier}
        shownCount={filtered.length}
        onSelect={(next) => choose(tier === next ? "" : next)}
        onClear={() => choose("")}
      />
      {outboundLicense && <Conflicts components={filtered} outbound={outboundLicense} />}
      {/* From 1536px up the distribution and the review box sit in a main column
          and the obligations box in a narrow one beside it. Below that the
          wrappers vanish and `order` keeps the single-column sequence. */}
      <div className="bl-licgrid">
        <div className="bl-licgrid-col">
          <div className="bl-licgrid-1">
            <Distribution components={filtered} licenseHref={licenseHref} />
          </div>
          <div className="bl-licgrid-4">
            <Review components={filtered} />
          </div>
        </div>
        <div className="bl-licgrid-col">
          <div className="bl-licgrid-2">
            <Obligations components={filtered} />
          </div>
        </div>
      </div>
    </div>
  );
}
