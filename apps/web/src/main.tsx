import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { UIProvider } from "./store/ui";
import { AuthProvider } from "./features/auth";
import { queryClient } from "./services/queryClient";
import "./index.css";

const container = document.getElementById("root");
if (!container) {
  throw new Error("root container missing");
}

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <UIProvider>
          <BrowserRouter basename={import.meta.env.BASE_URL}>
            <App />
          </BrowserRouter>
        </UIProvider>
      </AuthProvider>
    </QueryClientProvider>
  </StrictMode>,
);
