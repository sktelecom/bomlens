// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { MoonIcon, SunIcon } from "@primer/octicons-react";
import { IconButton } from "@primer/react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { saveTheme } from "@/lib/theme";

/** Light or dark, saved for the next visit (lib/theme.ts). */
export function ThemeToggle() {
  const { t } = useTranslation();
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));

  const toggle = () => {
    const next = !dark;
    setDark(next);
    saveTheme(document.documentElement, localStorage, next ? "dark" : "light");
  };

  return (
    <IconButton
      icon={dark ? SunIcon : MoonIcon}
      variant="invisible"
      aria-label={dark ? t("theme.toLight") : t("theme.toDark")}
      onClick={toggle}
      data-testid="theme-toggle"
    />
  );
}
