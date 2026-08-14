import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Builds the SPA into ../static/, which FastAPI serves in production. In dev,
// `npm run dev` proxies /api to the running recce server.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "../static", emptyOutDir: true },
  server: { proxy: { "/api": "http://127.0.0.1:8008" } },
});
