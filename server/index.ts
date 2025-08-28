// server/index.ts

import express, { type Request, type Response, type NextFunction } from "express";
import compression from "compression";
import rateLimit from "express-rate-limit";
import cors from "cors";
import path from "node:path";

import { registerRoutes } from "./routes";
import { setupVite, log } from "./vite"; // SOLO in dev
import { getCorsConfig, addSecurityHeaders } from "./corsConfig";
import {
  forceHTTPS,
  addHTTPSSecurityHeaders,
  handleCTViolationReport,
} from "./httpsRedirect";

// ----------------------------------------------------------------------------
// App base
// ----------------------------------------------------------------------------
const app = express();

// Indica a Express che è dietro un proxy (Railway) → req.secure funziona
app.set("trust proxy", 1);

// Rimuovi header di default
app.disable("x-powered-by");

// Ambiente
const isProd = process.env.NODE_ENV === "production";

// Compressione sempre attiva
app.use(compression());

// Directory di build (in produzione __dirname === .../dist)
const distDir = __dirname;
const publicDir = path.join(distDir, "public");

// ----------------------------------------------------------------------------
// 1) **ASSET STATICI PRIMA DI TUTTO** (SOLO PRODUZIONE)
// ----------------------------------------------------------------------------
if (isProd) {
  // /assets con cache lunga + immutable
  app.use(
    "/assets",
    express.static(path.join(publicDir, "assets"), {
      immutable: true,
      maxAge: "1y",
    })
  );

  // static generico per tutto il resto in /public (favicon, robots.txt, immagini…)
  app.use(express.static(publicDir));
}

// ----------------------------------------------------------------------------
// 2) Sicurezza/CORS, parser, rate limit **dopo** gli statici
// ----------------------------------------------------------------------------

// Forza HTTPS solo in produzione
if (isProd) {
  app.use(forceHTTPS);
}

// CORS (si applica alle API; gli asset statici sono già usciti)
app.use(cors(getCorsConfig()));

// Security headers “base”
app.use(addSecurityHeaders);

// Security headers specifici HTTPS (HSTS, ecc.)
app.use(addHTTPSSecurityHeaders);

// Endpoint di report sicurezza (Certificate Transparency)
app.post("/api/security/ct-report", express.json(), handleCTViolationReport);

// Parser corpo richiesta
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ----------------------------------------------------------------------------
// 3) Rate limiting (scoped alle API)
// ----------------------------------------------------------------------------
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuti
  max: 100,
  message: {
    success: false,
    message: "Troppi tentativi. Riprova più tardi.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    success: false,
    message: "Troppi tentativi di login. Riprova tra 15 minuti.",
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

app.use("/api", generalLimiter);
app.use("/api/admin/login", adminLoginLimiter);

// ----------------------------------------------------------------------------
// 4) Statiche upload (fuori da /public)
// ----------------------------------------------------------------------------
app.use("/uploads", express.static(path.join(process.cwd(), "uploads")));

// ----------------------------------------------------------------------------
// 5) Logging minimale per le API
// ----------------------------------------------------------------------------
app.use((req, res, next) => {
  const start = Date.now();
  const reqPath = req.path;
  let capturedJsonResponse: Record<string, unknown> | undefined;

  const originalResJson = res.json.bind(res);
  (res as any).json = (body: unknown, ...args: unknown[]) => {
    capturedJsonResponse = body as Record<string, unknown>;
    return originalResJson(body, ...args);
  };

  res.on("finish", () => {
    if (reqPath.startsWith("/api")) {
      const duration = Date.now() - start;
      let line = `${req.method} ${reqPath} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        try {
          line += ` :: ${JSON.stringify(capturedJsonResponse)}`;
        } catch {
          /* ignore circulars */
        }
      }
      if (line.length > 300) line = line.slice(0, 299) + "…";
      log(line);
    }
  });

  next();
});

// ----------------------------------------------------------------------------
// 6) Bootstrap asincrono: routes → (vite in dev) → catch-all prod → listen
// ----------------------------------------------------------------------------
(async () => {
  // Registra le route dell’app e ottieni l’istanza di http.Server
  const server = await registerRoutes(app);

  // Dev middleware Vite SOLO in sviluppo
  if (!isProd) {
    await setupVite(app, server);
  } else {
    // Catch-all SPA in produzione: tutte le route non/API servono l'index.html
    app.get("*", (_req, res) => {
      res.sendFile(path.join(publicDir, "index.html"));
    });
  }

  // === Error handler UNICO e per ultimo (dopo rotte e statici) ===
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err?.status || err?.statusCode || 500;

    // se la risposta è già partita, non inviare di nuovo
    if (res.headersSent) {
      console.error("[error after headersSent]", status, err?.message);
      return;
    }

    if (status >= 500) {
      console.error("[server error]", status, err?.stack || err);
    } else {
      console.warn("[client error]", status, err?.message);
    }

    res.status(status).json({
      message: err?.message || "Internal Server Error",
    });
  });

  // Porta Railway (se non presente, 3000 per locale)
  const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

  // Unica listen corretta
  server.listen(PORT, "0.0.0.0", () => {
    log(`🚀 Server online su porta ${PORT}`);
  });
})().catch((e) => {
  // eslint-disable-next-line no-console
  console.error("Fatal bootstrap error:", e);
  process.exit(1);
});
