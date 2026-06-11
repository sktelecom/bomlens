import React from "react";
import ReactDOM from "react-dom/client";

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
