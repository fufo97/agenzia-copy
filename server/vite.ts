// server/vite.ts

import express, { type Express } from "express";
import fs from "node:fs";
import { promises as fsp } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServer as createViteServer, createLogger } from "vite";
import type { Server } from "node:http";
import viteConfig from "../vite.config";
import { nanoid } from "nanoid";

/**
 * Node 18 + ESM: import.meta.dirname NON esiste → ricaviamo __filename / __dirname
 */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const viteLogger = createLogger();

export function log(message: string, source = "express") {
  const formattedTime = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}

/**
 * DEV: Vite in middleware mode (appType: "custom").
 * In produzione NON viene chiamata: usiamo serveStatic().
 */
export async function setupVite(app: Express, server: Server) {
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
        // in dev visualizziamo bene l’errore
        viteLogger.error(msg, options);
        process.exit(1);
      },
    },
    server: serverOptions,
    appType: "custom",
  });

  app.use(vite.middlewares);

  app.use("*", async (req, res, next) => {
    const url = req.originalUrl;

    try {
      // Template del client in DEV (non buildato)
      const clientTemplate = path.resolve(__dirname, "..", "client", "index.html");

      // Rileggiamo sempre da disco per avere HMR corretto
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
 * PROD: serve i file statici generati dalla build.
 * Fallback robusto → usa FRONTEND_DIR se presente, altrimenti /app/dist/public.
 */
export function serveStatic(app: Express) {
  const distPath = process.env.FRONTEND_DIR
    ? path.resolve(process.env.FRONTEND_DIR)
    : path.join(__dirname, "public"); // in bundle __dirname ≈ /app/dist

  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Build directory not found: ${distPath}. Esegui la build del client prima del deploy.`
    );
  }

  // Statiche con cache di lungo periodo + ETag
  app.use(
    express.static(distPath, {
      maxAge: "1y",
      etag: true,
      redirect: false,
    })
  );

  // SPA fallback: qualunque rotta non file → index.html
  app.get("*", (_req, res) => {
    res.sendFile(path.resolve(distPath, "index.html"));
  });
}
