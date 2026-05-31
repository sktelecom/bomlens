import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

import en from "../locales/en/common.json";
import ko from "../locales/ko/common.json";

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
    interpolation: { escapeValue: false },
  });

// Keep <html lang> in sync for a11y / SEO.
i18n.on("languageChanged", (lng) => {
  document.documentElement.lang = lng;
});

export default i18n;
