// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import ReactDOM from "react-dom/client";

// Self-host fonts so they load from 'self' under the desktop Electron CSP
// (style-src 'self'), which blocks the Google Fonts CDN. Bundling also keeps
// typography intact offline. Weights mirror the former CDN request.
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/inter/700.css";
import "@fontsource/jetbrains-mono/400.css";
// Korean text fell back to whatever the OS supplies (Apple SD Gothic on macOS,
// Malgun Gothic on Windows), so a ko screen rendered differently per platform
// and its weights did not line up with Inter's beside it. The dynamic subset
// splits the face across unicode ranges, so a screen loads the ranges it
// actually shows rather than the whole face.
import "pretendard/dist/web/variable/pretendardvariable-dynamic-subset.css";
import "@fontsource/jetbrains-mono/500.css";

// Primer design tokens: sizes, type, motion and the light and dark themes
// only (no high-contrast or colour-blind themes). src/primer.css follows them
// so its overrides win.
import "@primer/primitives/dist/css/base/size/size.css";
import "@primer/primitives/dist/css/base/typography/typography.css";
import "@primer/primitives/dist/css/base/motion/motion.css";
import "@primer/primitives/dist/css/functional/size/border.css";
import "@primer/primitives/dist/css/functional/size/radius.css";
import "@primer/primitives/dist/css/functional/size/size.css";
import "@primer/primitives/dist/css/functional/typography/typography.css";
import "@primer/primitives/dist/css/functional/themes/light.css";
import "@primer/primitives/dist/css/functional/themes/dark.css";
import "./primer.css";

import App from "./App";
import { PrimerRoot } from "./components/primer/PrimerRoot";
import "./index.css";
import "./lib/i18n";
import { applyTheme, initialTheme, THEME_STORAGE_KEY } from "./lib/theme";
import { ToastProvider } from "./lib/toast";

// Theme: restore saved preference, else follow OS. Applied before paint so
// there is no light→dark flash. applyTheme sets the `dark` class and the
// Primer colour-mode attributes together.
applyTheme(
  document.documentElement,
  initialTheme(
    localStorage.getItem(THEME_STORAGE_KEY),
    window.matchMedia("(prefers-color-scheme: dark)").matches,
  ),
);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <PrimerRoot>
      <ToastProvider>
        <App />
      </ToastProvider>
    </PrimerRoot>
  </React.StrictMode>,
);
