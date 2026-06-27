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
import "@fontsource/jetbrains-mono/500.css";

import App from "./App";
import "./index.css";
import "./lib/i18n";
import { ToastProvider } from "./lib/toast";

// Theme: restore saved preference, else follow OS. Applied before paint so
// there is no light→dark flash.
const saved = localStorage.getItem("sbom.theme");
const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
document.documentElement.classList.toggle(
  "dark",
  saved ? saved === "dark" : prefersDark,
);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ToastProvider>
      <App />
    </ToastProvider>
  </React.StrictMode>,
);
