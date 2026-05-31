import { useTranslation } from "react-i18next";

import { cn } from "@/lib/utils";

const LANGS: Array<[string, string]> = [
  ["ko", "KO"],
  ["en", "EN"],
];

export function LangToggle() {
  const { i18n, t } = useTranslation();
  const current = i18n.resolvedLanguage ?? i18n.language;

  return (
    <div
      className="inline-flex items-center rounded-md border border-input bg-background p-0.5"
      role="group"
      aria-label={t("lang.label")}
    >
      {LANGS.map(([code, label]) => {
        const active = current === code;
        return (
          <button
            key={code}
            type="button"
            onClick={() => void i18n.changeLanguage(code)}
            aria-pressed={active}
            className={cn(
              "rounded-sm px-2 py-1 text-xs font-medium transition-colors duration-fast ease-out-soft",
              active
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {label}
          </button>
        );
      })}
    </div>
  );
}
