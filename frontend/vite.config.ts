import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During development the Vite dev server proxies API + WebSocket traffic to the
// Rust backend on :8080, so the SPA and API share an origin from the browser's
// perspective (no CORS surprises, relative URLs work in dev and prod alike).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
