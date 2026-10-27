import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { UIProvider } from "./store/ui";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false, refetchOnWindowFocus: false, staleTime: 30_000 },
  },
});

const container = document.getElementById("root");
if (!container) {
  throw new Error("root container missing");
}

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <UIProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </UIProvider>
    </QueryClientProvider>
  </StrictMode>,
);
