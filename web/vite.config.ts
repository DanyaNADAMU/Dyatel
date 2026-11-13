import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { sourcemap: false },
  server: {
    // The dev server is only ever used against the staging nginx vhost,
    // which proxies /api/v1 to the core; same-origin, no CORS needed.
    proxy: {
      "/api": "http://127.0.0.1:8100",
    },
  },
});
