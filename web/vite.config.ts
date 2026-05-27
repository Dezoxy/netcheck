import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  // Tailwind v4 ships as a Vite plugin (CSS-first config in src/index.css
  // via @theme). PostCSS is no longer needed for v4 + Vite — the plugin
  // handles compilation. Plugin order matters: tailwindcss before react.
  plugins: [tailwindcss(), react()],
  build: {
    emptyOutDir: true,
    outDir: "../internal/webui/dist",
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8787",
    },
  },
});
