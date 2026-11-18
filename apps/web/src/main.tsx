import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { UIProvider } from "./store/ui";
import { queryClient } from "./services/queryClient";
import "./index.css";

const container = document.getElementById("root");
if (!container) {
  throw new Error("root container missing");
}

// Subpath basename normalization:
// e.g. "/services/kelvin/" -> "/services/kelvin"
const rawBasename =
  import.meta.env.VITE_ROUTER_BASENAME ??
  (import.meta.env.BASE_URL && import.meta.env.BASE_URL !== "/"
    ? import.meta.env.BASE_URL
    : "/services/kelvin");

const basename = rawBasename === "/" ? "/" : rawBasename.replace(/\/+$/, "") || "/";

// Standalone fallback: redirect root or non-subpath access to subpath prefix
if (basename !== "/" && typeof window !== "undefined") {
  const currentPath = window.location.pathname;
  if (!currentPath.startsWith(basename)) {
    const targetPath = currentPath === "/" ? "/dashboard" : currentPath;
    window.location.replace(`${basename}${targetPath}${window.location.search}${window.location.hash}`);
  }
}

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <UIProvider>
        <BrowserRouter basename={basename}>
          <App />
        </BrowserRouter>
      </UIProvider>
    </QueryClientProvider>
  </StrictMode>,
);
