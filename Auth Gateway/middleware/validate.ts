import type { Request, Response, NextFunction } from "express";
import type { ZodSchema } from "zod";
import { sendError } from "../shared/response.js";

export function validate(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      const firstIssue = result.error.issues[0];
      sendError({
        res,
        message: firstIssue?.message ?? "Invalid request data",
        statusCode: 400,
        code: "VALIDATION_ERROR",
      });
      return;
    }

    req.body = result.data;
    next();
  };
}