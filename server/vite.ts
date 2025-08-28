// server/vite.ts

import type { Express } from "express";
import type { Server } from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { promises as fsp } from "node:fs";

/** ESM compat per __dirname */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Log minimale (riusato dal server) */
export function log(message: string, source = "express") {
  const t = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });
  // eslint-disable-next-line no-console
  console.log(`${t} [${source}] ${message}`);
}

/**
 * Avvia il Vite Dev Server **solo** in sviluppo.
 * In produzione è un NO-OP (non monta nessun middleware).
 */
export async function setupVite(app: Express, server: Server) {
  // Produzione: NON avviare Vite/SSR, lascia che Express serva i file buildati.
  if (process.env.NODE_ENV === "production") return;

  // Import dinamico: questi moduli non vengono mai valutati in produzione.
  const { createServer: createViteServer, createLogger } = await import("vite");

  // Importa il config del progetto senza usare configFile (lo passiamo inline)
  const viteConfigMod: any = await import("../vite.config");
  const viteConfig = viteConfigMod.default ?? viteConfigMod;

  const viteLogger = createLogger();

  const serverOptions = {
    middlewareMode: true as const,
    hmr: { server },
    allowedHosts: true,
  };

  const vite = await createViteServer({
    ...viteConfig,
    configFile: false,        // usiamo l'oggetto importato sopra
    server: serverOptions,
    appType: "custom",
    customLogger: viteLogger,
  });

  // Middlewares dev di Vite (HMR, trasformazioni, asset non buildati)
  app.use(vite.middlewares);

  // Servizio di index.html in DEV: trasformiamo il template con Vite
  app.use("*", async (req, res, next) => {
    try {
      const url = req.originalUrl;
      const clientTemplate = path.resolve(__dirname, "..", "client", "index.html");
      const template = await fsp.readFile(clientTemplate, "utf-8");
      const html = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(html);
    } catch (e) {
      // Migliora lo stack in dev e passa all'error handler
      vite.ssrFixStacktrace(e as Error);
      next(e);
    }
  });
}
