import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { env } from "../config/env.js";
import { AppError } from "../shared/errors.js";
import type { AuthenticatedUser } from "../shared/types.js";

// ---------------------------------------------------------------------------
// authenticate middleware
// Verifies the JWT access token on every protected route. And attaches the decoded user payload to req.user so downstream handlers
// can access the current user without another database query.
//
// Usage in a route file:
//   router.get("/me", authenticate, meController);
// ---------------------------------------------------------------------------
export function authenticate(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // Extract the token from the Authorization header.
  // Expected format: "Bearer <token>"
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next(
      new AppError("Authentication required", 401, "NO_TOKEN")
    );
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return next(
      new AppError("Authentication required", 401, "NO_TOKEN")
    );
  }

  try {
    // jwt.verify throws if the token is expired, tampered, or signed
    // with a different secret. We catch those cases below.
    const decoded = jwt.verify(token, env.ACCESS_TOKEN_SECRET) as {
      sub: string;
      role: string;
      iat: number;
      exp: number;
    };

    // Attach the user payload to the request.
    // Controllers access this via req.user, no extra DB query needed for basic auth checks because the token already carries id and role.
    const user: AuthenticatedUser = {
      id: decoded.sub,
      email: "",  // not in JWT payload, to fetch from DB if needed via /me
      role: decoded.role,
    };

    req.user = user;
    next();
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return next(
        new AppError("Session expired. Please refresh your token.", 401, "TOKEN_EXPIRED")
      );
    }

    if (err instanceof jwt.JsonWebTokenError) {
      return next(
        new AppError("Invalid token", 401, "INVALID_TOKEN")
      );
    }

    // Unknown JWT error pass to global error handler
    return next(err);
  }
}

// ---------------------------------------------------------------------------
// requireRole middleware
// Used after authenticate to restrict routes to specific roles.
// Example: router.delete("/admin/user/:id", authenticate, requireRole("admin"), handler)
// ---------------------------------------------------------------------------
export function requireRole(...roles: string[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401, "NO_TOKEN"));
    }

    if (!roles.includes(req.user.role)) {
      return next(
        new AppError("You do not have permission to perform this action", 403, "FORBIDDEN")
      );
    }

    next();
  };
}