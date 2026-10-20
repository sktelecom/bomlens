// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// @no-unit-test: i18next bootstrap (side-effecting init + re-export); behavior covered by the Playwright i18n suite.
import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

import en from "../locales/en/common.json";
import ko from "../locales/ko/common.json";
import { formatNumber } from "./format";

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { common: en },
      ko: { common: ko },
    },
    fallbackLng: "en",
    supportedLngs: ["en", "ko"],
    defaultNS: "common",
    detection: {
      order: ["localStorage", "navigator"],
      lookupLocalStorage: "sbom.lang",
      caches: ["localStorage"],
    },
    // alwaysFormat routes every interpolated value through `format`, so each
    // numeric count in a translated string gets digit grouping without
    // touching the strings. Only numbers are changed; text passes through.
    interpolation: {
      escapeValue: false,
      alwaysFormat: true,
      format: (value, _format, lng) =>
        typeof value === "number" ? formatNumber(value, lng) : value,
    },
  });

// Keep <html lang> equal to the UI language from the first render on.
// init() with inline resources resolves the language right away, so write it
// once here and keep the listener for later switches.
function syncHtmlLang(lng: string | undefined): void {
  if (typeof document === "undefined") return; // unit tests run without a DOM
  const base = (lng || "en").split("-")[0];
  document.documentElement.lang = base === "ko" ? "ko" : "en";
}
syncHtmlLang(i18n.resolvedLanguage || i18n.language);
i18n.on("languageChanged", syncHtmlLang);

export default i18n;
