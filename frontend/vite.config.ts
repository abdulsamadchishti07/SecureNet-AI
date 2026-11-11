import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { assetsDir: "static", sourcemap: false },
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:8010", changeOrigin: false },
      "/ws/alerts": { target: "ws://127.0.0.1:8010", ws: true },
    },
  },
});
