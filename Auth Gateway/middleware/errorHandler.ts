import type { Request, Response, NextFunction } from "express";
import { AppError } from "../shared/errors.js";
import { sendError } from "../shared/response.js";
import { env } from "../config/env.js";

export function errorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  if (err instanceof AppError) {
    // This is an expected error
    sendError({
      res,
      message: err.message,
      statusCode: err.statusCode,
      code: err.code,
    });
    return;
  }

  console.error("Unhandled server error:", {
    name: err.name,
    message: err.message,
    stack: env.NODE_ENV !== "production" ? err.stack : "[stack hidden in production]",
  });

  sendError({
    res,
    message:
      env.NODE_ENV === "production"
        ? "Something went wrong. Please try again."
        : err.message,
    statusCode: 500,
    code: "INTERNAL_ERROR",
  });
}