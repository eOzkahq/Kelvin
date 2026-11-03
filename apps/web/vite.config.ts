import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

const apiTarget = process.env.KELVIN_API_URL ?? "http://localhost:8080";

export default defineConfig({
  base: process.env.VITE_BASE_PATH ?? "/services/kelvin/",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@kelvin/common": fileURLToPath(new URL("../../packages/common/src/ts/index.ts", import.meta.url)),
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
});
