import express, { type Request, Response, NextFunction } from "express";
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { getCorsConfig, addSecurityHeaders } from "./corsConfig";
import { forceHTTPS, addHTTPSSecurityHeaders, handleCTViolationReport } from "./httpsRedirect";
import path from "path";

const app = express();

// Indica a Express che è dietro un proxy (Railway) -> req.secure funziona
app.set("trust proxy", 1);

// Force HTTPS solo in produzione
if (app.get("env") === "production") {
 app.use(forceHTTPS);
}

// Apply secure CORS configuration
app.use(cors(getCorsConfig()));

// Add security headers
app.use(addSecurityHeaders);

// Add HTTPS-specific security headers
app.use(addHTTPSSecurityHeaders);

// Security reporting endpoint for Certificate Transparency
app.post('/api/security/ct-report', express.json(), handleCTViolationReport);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Rate limiting configuration for security
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Troppi tentativi. Riprova più tardi.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict rate limiting for admin login to prevent brute force attacks
const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 admin login attempts per windowMs
  message: {
    success: false,
    message: 'Troppi tentativi di login. Riprova tra 15 minuti.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful requests
  // Use default IP-based key generation (handles IPv4 and IPv6 correctly)
});

// Apply general rate limiting to all API routes
app.use('/api', generalLimiter);

// Apply strict rate limiting to admin login endpoint
app.use('/api/admin/login', adminLoginLimiter);

// Serve uploaded images statically
app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));

app.use((req, res, next) => {
  const start = Date.now();
  const reqPath = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (reqPath.startsWith("/api")) {
      let logLine = `${req.method} ${reqPath} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    if (app.get("env") === "development") {
         // in dev puoi voler vedere lo stack
        console.error(err);
       }
     // in produzione non rilanciare per non killare il processo
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

 // Usa la porta assegnata da Railway o 3000 in locale
const port = Number(process.env.PORT) || 3000;

server.listen(
  {
    port,
    host: "0.0.0.0",
    reusePort: true,
  },
  () => {
    log(`🚀 Server online su porta ${port}`);
  }
);

})();
