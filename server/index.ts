// server/index.ts

import express, { type Request, type Response, type NextFunction } from "express";
import rateLimit from "express-rate-limit";
import cors from "cors";
import path from "node:path";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
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
const isProd = app.get("env") === "production";

// Forza HTTPS solo in produzione
if (isProd) {
  app.use(forceHTTPS);
}

// CORS sicuro
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
/** Rate limiting */
// ----------------------------------------------------------------------------

// Generale per tutte le API
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

// Più stretto per login admin (anti brute force)
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

// Applica i limiter
app.use("/api", generalLimiter);
app.use("/api/admin/login", adminLoginLimiter);

// ----------------------------------------------------------------------------
// Statiche upload
// ----------------------------------------------------------------------------
app.use("/uploads", express.static(path.join(process.cwd(), "uploads")));

// ----------------------------------------------------------------------------
// Logging minimale per le API (metodo, path, status, durata)
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
// Bootstrap asincrono: routes → vite/dev o static/prod → listen
// ----------------------------------------------------------------------------
(async () => {
  // Registra tutte le route dell’app e ottieni l’istanza di http.Server
  const server = await registerRoutes(app);

  // Error handler (sempre DOPO le route)
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const anyErr = err as { status?: number; statusCode?: number; message?: string };
    const status = anyErr?.status ?? anyErr?.statusCode ?? 500;
    const message = anyErr?.message ?? "Internal Server Error";
    res.status(status).json({ message });

    if (!isProd) {
      // in dev stampiamo lo stack per debug
      // eslint-disable-next-line no-console
      console.error(err);
    }
    // in prod non rilanciamo per non killare il processo
  });

  // Importante: Vite SOLO in dev, e DOPO le altre route
  if (!isProd) {
    await setupVite(app, server);
  } else {
    // In produzione serviamo i file statici buildati
    serveStatic(app);
  }

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
