import type { Request, Response, NextFunction } from "express";
import { redis } from "../config/db.redis.js";
import { sendError } from "../shared/response.js";

interface RateLimitOptions {
  windowSeconds: number;
  maxRequests: number;
  keyPrefix: string;
}

// ---------------------------------------------------------------------------
// In-memory fallback store
// Active only when Redis is unreachable.
// Safe on single Render instance. On multiple instances, effective limit becomes (maxRequests * instanceCount) because stores do not share state.
//
//This fallback is used in case of one render
// If at all we scale beyond one render we have to replace this fallback
// with a hard rejection when Redis is down and set up alerting instead.
// ---------------------------------------------------------------------------
interface MemoryEntry {
  count: number;
  resetAt: number;
}

const memoryStore = new Map<string, MemoryEntry>();

function memoryRateCheck(
  key: string,
  windowMs: number,
  maxRequests: number
): boolean {
  const now = Date.now();
  const entry = memoryStore.get(key);

  if (!entry || now > entry.resetAt) {
    memoryStore.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }

  entry.count += 1;
  return entry.count <= maxRequests;
}

// Sweep expired entries every 5 minutes to prevent unbounded memory growth
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of memoryStore.entries()) {
    if (now > entry.resetAt) {
      memoryStore.delete(key);
    }
  }
}, 5 * 60 * 1000);

// ---------------------------------------------------------------------------
// Redis health tracking
// ---------------------------------------------------------------------------
let redisAvailable = true;

redis.on("error", () => {
  if (redisAvailable) {
    redisAvailable = false;
    console.error(
      "[REMOVE LOG LATER] Redis unreachable. Rate limiter falling back to " +
      "in-memory store. Brute force protection is degraded on multi-instance deployments."
    );
  }
});

redis.on("ready", () => {
  if (!redisAvailable) {
    redisAvailable = true;
    console.log("[REMOVE LOG LATER] Redis reconnected. Rate limiter restored.");
  }
});

// ---------------------------------------------------------------------------
// Key builder
// ---------------------------------------------------------------------------
const getClientKey = (req: Request, prefix: string): string => {
  // req.ip is populated correctly only after app.set("trust proxy", 1) in app.ts.
  // And if the request is authenticated we use req.user.id instead to ensure the limit is per user not per IP, which is more user friendly and effective against brute force attacks.

  if (req.user?.id) {
    return `rl:${prefix}:user:${req.user.id}`;
  }

  // Unauthenticated routes (login, register, forgot password) use IP address.
  const ip = req.ip ??
    (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ??
    "NO_IP_FOUND";

  if (ip === "NO_IP_FOUND") {
    console.error(
      "[REMOVE LOG LATER] Rate limiter could not determine client IP. " +
      "Check that app.set trust proxy is configured in app.ts."
    );
  }

  // Each prefix is unique per endpoint so counters are fully independent.
  return `rl:${prefix}:${ip}`;
};

// ---------------------------------------------------------------------------
// Main factory
// ---------------------------------------------------------------------------
export function rateLimiter({
  windowSeconds,
  maxRequests,
  keyPrefix,
}: RateLimitOptions) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const key = getClientKey(req, keyPrefix);
    const windowMs = windowSeconds * 1000;

    // Path A. Redis available
    if (redisAvailable) {
      try {
        const pipeline = redis.multi();
        pipeline.incr(key);
        pipeline.expire(key, windowSeconds);
        const results = await pipeline.exec();

        // pipeline.exec() returns ReplyUnion[], a union type that TypeScript cannot safely narrow to number with a direct cast.
        // I cast through unknown first (safe because I confirmed the shape with the test-redis.ts output results[0] is always a number here),
        // then guard with typeof to satisfy TypeScript's type checker.

        const rawCount = results?.[0] as unknown;
        const count = typeof rawCount === "number" ? rawCount : 0;

        // If count is 0 here it means the cast failed unexpectedly.
        // Log it to catch any future Redis version behaviour change.
        if (count === 0 && results?.[0] !== undefined) {
        console.error(
            "[REMOVE LOG LATER] Rate limiter: unexpected pipeline exec result type:",
            typeof results?.[0], results?.[0]
        );
        }

        if (count > maxRequests) {
          sendError({
            res,
            message: "Too many requests. Please slow down.",
            statusCode: 429,
            code: "RATE_LIMITED",
          });
          return;
        }

        res.setHeader("X-RateLimit-Limit", maxRequests);
        res.setHeader("X-RateLimit-Remaining", Math.max(0, maxRequests - count));
        next();
        return;
      } catch (err) {
        redisAvailable = false;
        console.error(
          "[REMOVE LOG LATER] Redis pipeline failed. Switching to memory fallback.",
          err
        );
      }
    }

    // Path B. in-memory fallback
    console.warn(
      "[REMOVE LOG LATER] Rate limiter using in-memory fallback for key:", key
    );

    const allowed = memoryRateCheck(key, windowMs, maxRequests);

    if (!allowed) {
      sendError({
        res,
        message: "Too many requests. Please slow down.",
        statusCode: 429,
        code: "RATE_LIMITED",
      });
      return;
    }

    next();
  };
}

// Pre-built limiters, import directly in route files
// Each limiter has unique prefix that specifies specific endpoint.
// This ensures counters are independent. hitting /login does not affect /register.

// Login. tightest limit to prevent brute force attacks.
export const loginLimiter = rateLimiter({
  windowSeconds: 15 * 60,
  maxRequests: 10,
  keyPrefix: "auth:login",
});

// Register. slightly more generous. account creation is less sensitive than login.
export const registerLimiter = rateLimiter({
  windowSeconds: 15 * 60,
  maxRequests: 5,
  keyPrefix: "auth:register",
});

// Forgot password. very tight. prevents email enumeration and spam.
export const forgotPasswordLimiter = rateLimiter({
  windowSeconds: 15 * 60,
  maxRequests: 3,
  keyPrefix: "auth:forgot",
});

// OTP verification. per attempt limit handled in service layer too.
export const verifyOtpLimiter = rateLimiter({
  windowSeconds: 15 * 60,
  maxRequests: 10,
  keyPrefix: "auth:verify-otp",
});

// Resend OTP. tight to prevent email spam abuse.
export const resendOtpLimiter = rateLimiter({
  windowSeconds: 15 * 60,
  maxRequests: 3,
  keyPrefix: "auth:resend-otp",
});

// Refresh. generous.
export const refreshLimiter = rateLimiter({
  windowSeconds: 15 * 60,
  maxRequests: 30,
  keyPrefix: "auth:refresh",
});
