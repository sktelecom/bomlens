// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ThemeProvider } from "@primer/react/next";
import { useEffect, useState, type ReactNode } from "react";

import { primerColorMode, readTheme, watchColorMode, type ThemeMode } from "@/lib/theme";

/**
 * Primer's theme context for the whole app.
 *
 * The colour mode follows the `dark` class on <html> (lib/theme.ts keeps the
 * Primer attributes there in step with it), so a theme switch from anywhere
 * reaches Primer. `contextOnly` skips Primer's wrapper element: the attributes
 * already sit on <html>, which also covers overlays portalled to <body>.
 *
 * BaseStyles is not used. Its stylesheet changes global focus, link, font and
 * line-height rules that the existing Tailwind screens rely on; Primer screens
 * get the font through the --fontStack-* overrides in src/primer.css instead.
 */
export function PrimerRoot({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<ThemeMode>(() => readTheme(document.documentElement));
  useEffect(() => {
    setMode(readTheme(document.documentElement));
    return watchColorMode(document.documentElement, setMode);
  }, []);
  return (
    <ThemeProvider
      colorMode={primerColorMode(mode)}
      dayScheme="light"
      nightScheme="dark"
      contextOnly
    >
      {children}
    </ThemeProvider>
  );
}
