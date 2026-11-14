// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { BeakerIcon } from "@primer/octicons-react";
import { Banner } from "@primer/react";
import { useTranslation } from "react-i18next";

import { demoInstallUrl } from "@/lib/demo";

/**
 * The notice the read-only demo shows at the top of every screen.
 *
 * It says two things a visitor needs before they read anything else: the
 * numbers on screen came from a real scan (not mock data), and the actions
 * that would change something are off. Rendered only when the bundle is the
 * demo (`AppShell` gates it), so a normal build never mounts this.
 */
export function DemoBanner() {
  const { t, i18n } = useTranslation();
  return (
    <Banner
      variant="info"
      className="bl-demo-banner"
      data-testid="demo-banner"
      leadingVisual={<BeakerIcon />}
      primaryAction={
        <Banner.PrimaryAction
          as="a"
          href={demoInstallUrl(i18n.language)}
          target="_blank"
          rel="noreferrer"
        >
          {t("shell.demoBannerCta")}
        </Banner.PrimaryAction>
      }
    >
      {/* Banner only offers heading levels for its title, and an h2 here would
          come before the page's own h1. The title is a plain line instead. */}
      <Banner.Title as={"p" as "h2"}>{t("shell.demoBannerTitle")}</Banner.Title>
      <Banner.Description>{t("shell.demoBannerBody")}</Banner.Description>
    </Banner>
  );
}
