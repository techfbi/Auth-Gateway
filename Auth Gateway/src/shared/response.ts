import type { Response } from "express";

//Instead of manually writing res.status(...).json(...) everywhere, we can use these helper functions to standardize our API responses and reduce boilerplate code in our controllers.

interface SuccessPayload<T> {
  res: Response;
  data?: T;
  message?: string;
  statusCode?: number;
}

interface ErrorPayload {
  res: Response;
  message: string;
  statusCode?: number;
  code?: string;
}

export function sendSuccess<T>({
  res,
  data,
  message,
  statusCode = 200,
}: SuccessPayload<T>): Response {
  return res.status(statusCode).json({
    success: true,
    message: message ?? "OK",
    data: data ?? null,
  });
}

export function sendError({
  res,
  message,
  statusCode = 500,
  code,
}: ErrorPayload): Response {
  return res.status(statusCode).json({
    success: false,
    message,
    code: code ?? "INTERNAL_ERROR",
    data: null,
  });
}