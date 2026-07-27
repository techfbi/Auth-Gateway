import type { Request, Response, NextFunction } from "express";
import {
  registerUser,
  loginUser,
  refreshTokens,
  logoutUser,
  getUserById,
  requestPasswordReset,
  resetPassword,
} from "./auth.service.js";
import { sendSuccess } from "../shared/response.js";
import type { RegisterInput, LoginInput, ForgotPasswordInput, ResetPasswordInput } from "./auth.schema.js";
import { verifyRegistrationOtp, resendOtp, googleAuth } from "./auth.service.js";
import type { VerifyOtpInput, ResendOtpInput, GoogleAuthInput } from "./auth.schema.js";
import { AppError } from "../shared/errors.js";

// ---------------------------------------------------------------------------
// Cookie configuration
// The refresh token lives in an httpOnly cookie, JavaScript cannot read it, so XSS attacks cannot steal it even if they execute in the browser.
// ---------------------------------------------------------------------------
const REFRESH_COOKIE_NAME = "refresh_token";
const isProduction = process.env.NODE_ENV === "production";

const cookieOptions = {
  httpOnly: true,
  secure: isProduction,  // this is true
  sameSite:  "lax" as "lax",   // lax now in prod and dev, proxy set up in varcel config
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
  path: "/api/auth",            // cookie only sent to auth routes. reduces exposure
};

// ---------------------------------------------------------------------------
// Helper to set the refresh token cookie
// Centralised so cookie options are never accidentally inconsistent
// ---------------------------------------------------------------------------
const setRefreshCookie = (res: Response, token: string): void => {
  res.cookie(REFRESH_COOKIE_NAME, token, cookieOptions);
};

const clearRefreshCookie = (res: Response): void => {
  res.clearCookie(REFRESH_COOKIE_NAME, {
    path: "/api/auth",
    // Must match the original cookie options exactly for the browser to clear it
    secure: isProduction,
    sameSite: (isProduction ? "none" : "lax") as "none" | "lax",
  });
};

// ---------------------------------------------------------------------------
// POST /api/auth/register
// ---------------------------------------------------------------------------
export const register = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const input = req.body as RegisterInput;
    const result = await registerUser(input);

    if (result.verified) {
      // Verification disabled. user created immediately.
      setRefreshCookie(res, result.tokens.refreshToken);

      sendSuccess({
        res,
        statusCode: 201,
        message: "Account created successfully",
        data: {
          user: result.user,
          accessToken: result.tokens.accessToken,
          requiresVerification: false,
        },
      });
    } else {
      // Verification enabled. pending registration created, OTP sent.
      // Return pendingId so the frontend knows which session to verify.
      sendSuccess({
        res,
        statusCode: 200,
        message: result.message,
        data: {
          pendingId: result.pendingId,
          requiresVerification: true,
        },
      });
    }
  } catch (err) {
    next(err);
  }
};

// ---------------------------------------------------------------------------
// POST /api/auth/login
// ---------------------------------------------------------------------------
export const login = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const input = req.body as LoginInput;
    const { user, tokens } = await loginUser(input);

    setRefreshCookie(res, tokens.refreshToken);

    sendSuccess({
      res,
      message: "Logged in successfully",
      data: {
        user,
        accessToken: tokens.accessToken,
      },
    });
  } catch (err) {
    next(err);
  }
}

// ---------------------------------------------------------------------------
// POST /api/auth/refresh
// ---------------------------------------------------------------------------
export const refresh = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const rawToken = req.cookies[REFRESH_COOKIE_NAME] as string | undefined;

    if (!rawToken) {
  // No cookie, user is not logged in or cookie was cleared. A clean
  // 401 with a real code, not an unhandled exception, since the
  // frontend specifically checks for NO_TOKEN to recognize this as
  // an expected logged out state, not a server fault.
  throw new AppError("No refresh token provided", 401, "NO_TOKEN");
}

    const tokens = await refreshTokens(rawToken);

    // Issue new cookie with the rotated refresh token
    setRefreshCookie(res, tokens.refreshToken);

    sendSuccess({
      res,
      message: "Token refreshed",
      data: { accessToken: tokens.accessToken },
    });
  } catch (err) {
    next(err);
  }
}

// ---------------------------------------------------------------------------
// POST /api/auth/google
// Receives the authorization code from the frontend after the user completes the Google consent screen and is redirected back to the frontend.
// ---------------------------------------------------------------------------
export const googleAuthHandler = async ( req: Request, res: Response, next: NextFunction ): Promise<void> => {
  try {
    const { code } = req.body as GoogleAuthInput;

    const { user, tokens, isNewUser } = await googleAuth(code);

    setRefreshCookie(res, tokens.refreshToken);

    sendSuccess({
      res,
      message: isNewUser ? "Account created with Google." : "Logged in with Google.",
      data: {
        user,
        accessToken: tokens.accessToken,
        isNewUser,
      },
    });
  } catch (err) {
    next(err);
  }
};

// ---------------------------------------------------------------------------
// POST /api/auth/logout
// ---------------------------------------------------------------------------
export const logout = async ( req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const rawToken = req.cookies[REFRESH_COOKIE_NAME] as string | undefined;

    // logoutUser handles missing token gracefully it always returns success
    if (rawToken) {
      await logoutUser(rawToken);
    }

    clearRefreshCookie(res);

    sendSuccess({ res, message: "Logged out successfully" });
  } catch (err) {
    next(err);
  }
}

// ---------------------------------------------------------------------------
// GET /api/auth/me
// ---------------------------------------------------------------------------
export const getMe = async ( req: Request, res: Response, next: NextFunction ): Promise<void> => {
  try {
    // req.user is set by the authenticate middleware before this runs.
    // If authenticate did not run, req.user is undefined and we throw.
    if (!req.user) {
      throw new Error("authenticate middleware missing on /me route");
    }

    const user = await getUserById(req.user.id);

    sendSuccess({ res, data: { user } });
  } catch (err) {
    next(err);
  }
}

// ---------------------------------------------------------------------------
// POST /api/auth/forgot-password
// ---------------------------------------------------------------------------
export const forgotPassword = async ( req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const input = req.body as ForgotPasswordInput;

    await requestPasswordReset(input);

    // Always return success regardless of whether the email exists.
    // This prevents email enumeration attacks.
    sendSuccess({
      res,
      message:
        "A password reset link has been sent your to email.",
    });
  } catch (err) {
    next(err);
  }
};

// ---------------------------------------------------------------------------
// POST /api/auth/reset-password
// ---------------------------------------------------------------------------
export const resetPasswordHandler = async ( req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const input = req.body as ResetPasswordInput;

    await resetPassword(input);

    // Clear the refresh token cookie. the user must log in again with their new password to get a fresh session.
    clearRefreshCookie(res);

    sendSuccess({
      res,
      message:
        "Password reset successfully. Please log in with your new password.",
    });
  } catch (err) {
    next(err);
  }
};

// ---------------------------------------------------------------------------
// POST /api/auth/verify-otp
// ---------------------------------------------------------------------------
export const verifyOtp = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const input = req.body as VerifyOtpInput;
    const { user, tokens } = await verifyRegistrationOtp(input);

    setRefreshCookie(res, tokens.refreshToken);

    sendSuccess({
      res,
      statusCode: 201,
      message: "Email verified. Account created successfully.",
      data: {
        user,
        accessToken: tokens.accessToken,
      },
    });
  } catch (err) {
    next(err);
  }
};

// ---------------------------------------------------------------------------
// POST /api/auth/resend-otp
// ---------------------------------------------------------------------------
export const resendOtpHandler = async ( req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const input = req.body as ResendOtpInput;

    await resendOtp(input);

    sendSuccess({
      res,
      message: "A new verification code has been sent to your email.",
    });
  } catch (err) {
    next(err);
  }
};