import { Router } from "express";
import { loginLimiter, registerLimiter, forgotPasswordLimiter, verifyOtpLimiter, resendOtpLimiter, refreshLimiter, } from "../middleware/rateLimiter.js";
import { validate } from "../middleware/validate.js";
import { authenticate } from "../middleware/authenticate.js";
import { registerSchema, loginSchema, forgotPasswordSchema, resetPasswordSchema, verifyOtpSchema, resendOtpSchema, googleAuthSchema } from "./auth.schema.js";
import {
  register,
  login,
  refresh,
  logout,
  getMe,
  forgotPassword,
  resetPasswordHandler,
  verifyOtp,
  resendOtpHandler,
  googleAuthHandler,
} from "./auth.controller.js";

export const authRouter = Router();

// Each route has its own independent rate limiter.
// Hitting one endpoint does not affect the counter on any other endpoint.
authRouter.post("/register", registerLimiter, validate(registerSchema), register);
authRouter.post("/login", loginLimiter, validate(loginSchema), login);
authRouter.post("/refresh", refreshLimiter, refresh);
authRouter.post("/google", loginLimiter, validate(googleAuthSchema), googleAuthHandler); // same limiter as login cos they can be the same abuse
authRouter.post("/logout", logout);  // no limiter. logout should always succeed
authRouter.post("/forgot-password", forgotPasswordLimiter, validate(forgotPasswordSchema), forgotPassword);
authRouter.post("/reset-password", validate(resetPasswordSchema), resetPasswordHandler);
authRouter.post("/verify-otp", verifyOtpLimiter, validate(verifyOtpSchema), verifyOtp);
authRouter.post("/resend-otp", resendOtpLimiter, validate(resendOtpSchema), resendOtpHandler);

// Protected route, authenticate middleware verifies the JWT access token
authRouter.get("/me", authenticate, getMe);