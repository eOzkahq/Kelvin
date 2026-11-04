export interface AppConfig {
  apiBase: string;
  appEnv: "development" | "staging" | "production";
  basePath: string;
  isProduction: boolean;
  isDevelopment: boolean;
}

export function loadAppConfig(): AppConfig {
  const apiBase = import.meta.env?.VITE_API_BASE ?? "/api/v1";
  const appEnv = (import.meta.env?.VITE_APP_ENV ?? "development") as "development" | "staging" | "production";
  const basePath = import.meta.env?.BASE_URL ?? "/services/kelvin/";

  // Validation
  if (!apiBase.startsWith("/") && !apiBase.startsWith("http://") && !apiBase.startsWith("https://")) {
    throw new Error(`Invalid VITE_API_BASE configured: "${apiBase}". Must be an absolute path or full URL.`);
  }

  return {
    apiBase,
    appEnv,
    basePath,
    isProduction: appEnv === "production",
    isDevelopment: appEnv === "development",
  };
}

export const appConfig = loadAppConfig();
