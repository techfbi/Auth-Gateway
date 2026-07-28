import { z } from "zod";

// ---------------------------------------------------------------------------
// Password rules, applied consistently across register and any future
// password change endpoint. Exported perhaps the frontend can import and reuse
// the same rules for real-time validation without duplicating logic.
// ---------------------------------------------------------------------------
export const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
  .regex(/[0-9]/, "Password must contain at least one number")
  .regex(/[^A-Za-z0-9]/, "Password must contain at least one special character");

// ---------------------------------------------------------------------------
// Register schema
// .object() already automatically strips or removes any fields the client sends that are not defined here.
// This is Zod's default for it instead of .strip(), but we can also state it explicitly for clarity.
// ---------------------------------------------------------------------------
export const registerSchema = z
  .object({
    display_name: z
      .string()
      .min(2, "Name must be at least 2 characters")
      .max(50, "Name must be under 50 characters")
      .trim(),
    email: z
      .string()
      .email("Please enter a valid email address")
      .toLowerCase()  // prevents duplicate accounts
      .trim(),
    password: passwordSchema,
    confirm_password: z.string().nullable().optional(),
  })
  .refine((data) => !data.confirm_password || data.password === data.confirm_password, {
    // refine() adds cross-field validation, Zod cannot express this with single-field rules alone
    message: "Passwords do not match",
    path: ["confirm_password"],
  });

// ---------------------------------------------------------------------------
// Login schema
// The password field is just a non-empty string here because I am
// checking it against the stored hash, not re-validating its format.
// ---------------------------------------------------------------------------
export const loginSchema = z.object({
  email: z
    .string()
    .email("Please enter a valid email address")
    .toLowerCase()
    .trim(),
  password: z.string().min(1, "Password is required"),
});

//----------------------------------------------------------------------------------
// Forgot Password
//----------------------------------------------------------------------------------

// Accepts the email to send the reset link to
export const forgotPasswordSchema = z.object({
  email: z
    .string()
    .email("Please enter a valid email address")
    .toLowerCase()
    .trim(),
});

// Accepts the raw token from the reset link URL and the new password
export const resetPasswordSchema = z
  .object({
    token: z.string().min(1, "Reset token is required"),
    password: passwordSchema,
    confirm_password: z.string(),
  })
  .refine((data) => data.password === data.confirm_password, {
    message: "Passwords do not match",
    path: ["confirm_password"],
  });

//-----------------------------------------------------------------------------------
// Verify OTP
// pendingId identifies which pending registration to verify.
// otp is the 6-digit code the user received by email
//-----------------------------------------------------------------------------------
export const verifyOtpSchema = z.object({
  pendingId: z.coerce.number().int().positive("Invalid registration session"), // converts id to integer and checks it's positive, if it fails to convert or is not positive, it throws the error message.
  otp: z
    .string()
    .length(6, "OTP must be exactly 6 digits")
    .regex(/^\d{6}$/, "OTP must contain digits only"),
});

//-----------------------------------------------------------------------------------
// Resend OTP schema.
// Used when the user did not receive the email or the OTP expired.
//-----------------------------------------------------------------------------------
export const resendOtpSchema = z.object({
  pendingId: z.coerce.number().int().positive("Invalid registration session"),
});

// ---------------------------------------------------------------------------
// Google OAuth callback schema.
// The frontend sends only the authorization code it received from Google.
// ---------------------------------------------------------------------------
export const googleAuthSchema = z.object({
  code: z.string().min(1, "Authorization code is required"),
});

// ---------------------------------------------------------------------------
// TypeScript types inferred from schemas
// we can use these as the type of req.body after the validate() middleware runs.
// ---------------------------------------------------------------------------
export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;
export type VerifyOtpInput = z.infer<typeof verifyOtpSchema>;
export type ResendOtpInput = z.infer<typeof resendOtpSchema>;
export type GoogleAuthInput = z.infer<typeof googleAuthSchema>;