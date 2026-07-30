// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Config } from "tailwindcss";
import animate from "tailwindcss-animate";

/**
 * Tailwind config — mirrors TRUSCA's "W11-A" token mapping so the
 * two UIs share one design language. Token VALUES live in src/index.css as CSS
 * custom properties; this file maps them to utility classes. Dark mode IS
 * populated here (BomLens ships a dark theme — see index.css `.dark`).
 */
const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["class"],
  theme: {
    container: { center: true, padding: "1rem", screens: { "2xl": "1400px" } },
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        // Brand accent — SKT (SK Red primary / SK Orange secondary). Active nav,
        // selection accents, primary CTAs. Distinct from neutral `primary`.
        brand: {
          DEFAULT: "hsl(var(--brand))",
          foreground: "hsl(var(--brand-foreground))",
          accent: "hsl(var(--brand-accent))",
        },
        // Sidebar surface — the left rail reads as its own plane.
        sidebar: {
          DEFAULT: "hsl(var(--sidebar))",
          foreground: "hsl(var(--sidebar-foreground))",
          border: "hsl(var(--sidebar-border))",
        },
        // Risk severity tokens — domain semantics fixed (shared with portal).
        //
        // The variables hold bare RGB channels ("234 88 12"), not a colour, so
        // that `<alpha-value>` can be substituted here. With a plain
        // `var(--risk-high)` Tailwind cannot see the channels and silently emits
        // no rule at all for a modifier like `bg-risk-high/30` — the element
        // then renders with no background rather than a faint one, which is how
        // the license distribution's copyleft tint was invisible from the start.
        risk: {
          critical: "rgb(var(--risk-critical) / <alpha-value>)",
          high: "rgb(var(--risk-high) / <alpha-value>)",
          medium: "rgb(var(--risk-medium) / <alpha-value>)",
          low: "rgb(var(--risk-low) / <alpha-value>)",
          info: "rgb(var(--risk-info) / <alpha-value>)",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      borderRadius: {
        sm: "calc(var(--radius) - 2px)",
        md: "var(--radius)",
        lg: "calc(var(--radius) + 2px)",
        xl: "calc(var(--radius) + 6px)",
      },
      boxShadow: {
        sm: "var(--shadow-sm)",
        md: "var(--shadow-md)",
        lg: "var(--shadow-lg)",
      },
      transitionDuration: {
        fast: "var(--duration-fast)",
        base: "var(--duration-base)",
        slow: "var(--duration-slow)",
      },
      transitionTimingFunction: {
        "ease-out-soft": "var(--ease-out)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        // Bar charts wipe in from the left on mount (pair with origin-left).
        "grow-x": {
          from: { transform: "scaleX(0)" },
          to: { transform: "scaleX(1)" },
        },
      },
      animation: {
        "fade-in": "fade-in var(--duration-base) var(--ease-out)",
        "grow-x": "grow-x var(--duration-slow) var(--ease-out)",
      },
    },
  },
  plugins: [animate],
};

export default config;
