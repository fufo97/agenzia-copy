// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig({
  // assicura che gli asset siano richiesti come /assets/... (niente path relativi)
  base: "/",
  plugins: [react()],

  // il codice sorgente vive in client/
  root: path.resolve(__dirname, "client"),

  // alias utili lato client
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "client", "src"),
      "@shared": path.resolve(__dirname, "shared"),
      "@assets": path.resolve(__dirname, "attached_assets"),
    },
  },

  build: {
    // output finale dove il server andrà a servire gli asset
    outDir: path.resolve(__dirname, "dist/public"),
    assetsDir: "assets",
    emptyOutDir: true,
  },

  // piccola hardening in dev
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"],
    },
  },
});
