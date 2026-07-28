import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { env } from "./config/env.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { authRouter } from "./auth module/auth.routes.js";
import { globalLimiter } from "./middleware/rateLimiter.js";

export const app = express();

// Trust the first proxy hop. Required for req.ip to contain the real
// client IP when running behind Render's load balancer or any reverse proxy.
// Without this, req.ip is undefined and all rate limit keys collapse into one.
app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", env.CLIENT_URL],
        fontSrc: ["'self'", "https:", "data:"], // Allows fonts from HTTPS font CDNs, your server, base64 fonts.
        objectSrc: ["'none'"], //Prevents Flash / plugin injection.
        baseUri: ["'self'"], // Stops attackers changing how URLs resolve.
        frameAncestors: ["'none'"], // Prevents clickjacking by disallowing site to be framed by any site. Adjust if you need to allow framing from specific origins (e.g., for embedding in a trusted partner site).
        upgradeInsecureRequests: [], // Tells browsers to upgrade HTTP requests to HTTPS automatically
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true },
  })
);

app.use(
  cors({
    origin: env.CLIENT_URL,
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true, limit: "20kb" })); // Allows form submission
app.use(cookieParser());
app.use(globalLimiter)


app.get("/", (_req, res) => {
  res.status(200).json({ status: "ok", message: "Welcome to Auth Gateway", timestamp: new Date().toISOString() });
});


app.use("/api/auth", authRouter);

app.use((_req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
    code: "NOT_FOUND",
  });
});

// This is last because it receives any error passed via next(err) from routes
app.use(errorHandler);