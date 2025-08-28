// server/vite.ts

import express, { type Express } from "express";
import fs from "node:fs";
import { promises as fsp } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Server } from "node:http";
import { nanoid } from "nanoid";

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
 * DEV ONLY: avvia Vite in middleware mode.
 * Importiamo 'vite' e 'vite.config' **solo qui**, dinamicamente,
 * così in produzione non vengono mai valutati.
 */
export async function setupVite(app: Express, server: Server) {
  const { createServer: createViteServer, createLogger } = await import("vite");
  const viteLogger = createLogger();

  // Import dinamico del config (solo in dev)
  const viteConfigMod: any = await import("../vite.config");
  const viteConfig = viteConfigMod.default ?? viteConfigMod;

  const serverOptions = {
    middlewareMode: true as const,
    hmr: { server },
    allowedHosts: true,
  };

  const vite = await createViteServer({
    ...viteConfig,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      },
    },
    server: serverOptions,
    appType: "custom",
  });

  app.use(vite.middlewares);

  app.use("*", async (req, res, next) => {
    try {
      const url = req.originalUrl;
      const clientTemplate = path.resolve(__dirname, "..", "client", "index.html");
      let template = await fsp.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const html = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(html);
    } catch (e) {
      vite.ssrFixStacktrace(e as Error);
      next(e);
    }
  });
}

/**
 * PROD: serve i file statici buildati (dist/public).
 * Non tocca né importa Vite né vite.config.
 */
export function serveStatic(app: Express) {
  const distPath = process.env.FRONTEND_DIR
    ? path.resolve(process.env.FRONTEND_DIR)
    : path.join(__dirname, "public"); // in prod ≈ /app/dist/public

  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Build directory not found: ${distPath}. Esegui la build del client prima del deploy.`
    );
  }

  app.use(
    express.static(distPath, {
      maxAge: "1y",
      etag: true,
      redirect: false,
    })
  );

  // SPA fallback
  app.get("*", (_req, res) => {
    res.sendFile(path.resolve(distPath, "index.html"));
  });
}
