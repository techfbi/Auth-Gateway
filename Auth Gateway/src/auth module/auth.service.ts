import jwt from "jsonwebtoken";
import argon2 from "@node-rs/argon2";
import { pgPool } from "../config/db.postgres.js";
import { env } from "../config/env.js";
import { AppError } from "../shared/errors.js";
import { generateToken, hashToken } from "../shared/crypto.js";
import type { RegisterInput, LoginInput } from "./auth.schema.js";
import { sendPasswordResetEmail, sendOtpEmail, sendWelcomeEmail } from "../config/email.js";
import type { ForgotPasswordInput, ResetPasswordInput } from "./auth.schema.js";
import type { VerifyOtpInput, ResendOtpInput } from "./auth.schema.js";
import { exchangeCodeForProfile } from "../config/google.js";

// ---------------------------------------------------------------------------
// Set Types
// ---------------------------------------------------------------------------

export interface TokenPair {
  accessToken: string;
  refreshToken: string; // raw token, sent to client, never stored
}

export interface SafeUser {
  id: string;
  email: string;
  display_name: string;
  role: string;
  is_verified: boolean;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Token generation helpers
// ---------------------------------------------------------------------------

// 15min accesstoken with user ID and role in the payload. Signed with a strong secret key.
const generateAccessToken = (userId: string, role: string): string => {
  return jwt.sign({ sub: userId, role }, env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
}

// Generates a refresh token, stores its hash in the database, and returns the raw token to be sent to the client.
// We store only the hash, if the DB is breached, raw tokens cannot be replayed.
const generateAndStoreRefreshToken = async ( userId: string, familyId: string ): Promise<string> => {
  const rawToken = generateToken(48);       // 96-character random hex string
  const tokenHash = hashToken(rawToken);    // SHA-256 hash. what we store
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  await pgPool.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [userId, tokenHash, familyId, expiresAt]
  );

  // Return the raw token. this goes into the httpOnly cookie.
  // After this point the raw token is never stored anywhere on the server.
  return rawToken;
}

// ---------------------------------------------------------------------------
// Register.
// ---------------------------------------------------------------------------
export const registerUser = async (
  input: RegisterInput
): Promise <
  | { verified: true; user: SafeUser; tokens: TokenPair }
  | { verified: false; pendingId: number; message: string }
> => {
  // Check for existing confirmed account
  const existing = await pgPool.query(
    "SELECT id FROM users WHERE email = $1 ",
    [input.email]
  );

  if (existing.rows.length > 0) {
    throw new AppError(
      "An account with this email already exists",
      409,
      "EMAIL_EXISTS"
    );
  }

  // Hashed before storing in the pending table because pending rows
  // contain real credentials that must be protected even temporarily.
  const passwordHash = await argon2.hash(input.password);

  // ---------------------------------------------------------------------------
  // Path A. verification disabled (development and testing)
  // ---------------------------------------------------------------------------
  if (!env.REQUIRE_EMAIL_VERIFICATION) {
    const result = await pgPool.query(
      `INSERT INTO users (email, password_hash, display_name, provider)
       VALUES ($1, $2, $3, 'local')
       RETURNING id, email, display_name, role, is_verified, created_at`,
      [input.email, passwordHash, input.display_name]
    );

    const user: SafeUser = result.rows[0];

    const familyId = generateToken(16);
    const refreshToken = await generateAndStoreRefreshToken(user.id, familyId);
    const accessToken = generateAccessToken(user.id, user.role);

    console.log(
      `DEVELOPMENT MODE: User registered without verification. ${user.id}`
    );

    return { verified: true, user, tokens: { accessToken, refreshToken } };
  }

  // ---------------------------------------------------------------------------
  // Path B. verification enabled (production)
  // ---------------------------------------------------------------------------

  // Generate a 6-digit numeric OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpHash = hashToken(otp);
  const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  // Upsert into pending_registrations.
  // If the user previously tried to register with this email but did not verify,
  // we overwrite the old row with fresh details and a new OTP.
  const pendingResult = await pgPool.query(
    `INSERT INTO pending_registrations
       (email, display_name, password_hash, otp_hash, otp_expires_at)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (email) DO UPDATE SET
       display_name   = EXCLUDED.display_name,
       password_hash  = EXCLUDED.password_hash,
       otp_hash       = EXCLUDED.otp_hash,
       otp_expires_at = EXCLUDED.otp_expires_at,
       attempts       = 0,
       created_at     = NOW()
     RETURNING id`,
    [input.email, input.display_name, passwordHash, otpHash, otpExpiresAt]
  );

  const pendingId: number = pendingResult.rows[0].id;

  await sendOtpEmail(input.email, input.display_name, otp);

  console.log(
    `[REMOVE LOG LATER] Pending registration created. OTP sent. pendingId. ${pendingId}`
  );

  return {
    verified: false,
    pendingId,
    message:
      "A verification code has been sent to your email. Please enter it to complete registration.",
  };
};

// ---------------------------------------------------------------------------
// Login User
// ---------------------------------------------------------------------------
export const loginUser = async (input: LoginInput): Promise<{
  user: SafeUser;
  tokens: TokenPair;
}> => {
  // Fetch user by email
  const result = await pgPool.query(
    `SELECT id, email, display_name, role, is_verified, created_at, password_hash, provider
     FROM users
     WHERE email = $1`,
    [input.email]
  );

  const user = result.rows[0];

  if (!user) {
    throw new AppError("Invalid credentials", 401, "INVALID_CREDENTIALS");
  }

  // Block OAuth users from logging in with a password. They registered via Google and have no password_hash.
  if (user.provider !== "local" || !user.password_hash) {
    throw new AppError(
      "This account uses Google sign-in. Please continue with Google.",
      401,
      "OAUTH_ACCOUNT"
    );
  }

  // Verify password against stored Argon2id hash
  const passwordValid = await argon2.verify(user.password_hash, input.password);

  if (!passwordValid) {
    throw new AppError("Invalid credentials", 401, "INVALID_CREDENTIALS");
  }

  // Update last login timestamp, useful for analytics and security audits
  await pgPool.query(
    "UPDATE users SET last_login_at = NOW() WHERE id = $1",
    [user.id]
  );

  // Issue a fresh token pair with a new family
  const familyId = generateToken(16);
  const refreshToken = await generateAndStoreRefreshToken(user.id, familyId);
  const accessToken = generateAccessToken(user.id, user.role);

  // Build safe user object, to strip password_hash and provider before returning
  const safeUser: SafeUser = {
    id: user.id,
    email: user.email,
    display_name: user.display_name,
    role: user.role,
    is_verified: user.is_verified,
    created_at: user.created_at,
  };

  return { user: safeUser, tokens: { accessToken, refreshToken } };
}

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------
export const refreshTokens = async (rawToken: string): Promise<TokenPair> => {
  const tokenHash = hashToken(rawToken);

  // find the token by its hash
  const result = await pgPool.query(
    `SELECT id, user_id, family_id, is_revoked, expires_at
     FROM refresh_tokens
     WHERE token_hash = $1`,
    [tokenHash]
  );

  const storedToken = result.rows[0];

  if (!storedToken) {
    throw new AppError("Invalid refresh token", 401, "INVALID_TOKEN");
  }

  // Token reuse detected, a revoked token was used again. Meaning someone may have stolen and already used this token.
  // Then we revoke the entire family to log out all devices for this user.
  if (storedToken.is_revoked) {
    console.error(
      `[REMOVE LOG LATER] Refresh token reuse detected, revoking family: ${storedToken.family_id}. ` +
      `Possible token theft for user: ${storedToken.user_id}`
    );

    // Revoke the entire familyId
    await pgPool.query(
      "UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = NOW() WHERE family_id = $1",
      [storedToken.family_id]
    );

    throw new AppError(
      "Session expired. Please log in again.",
      401,
      "TOKEN_REUSED"
    );
  }

  // For valid expiry and valid stored token not yet revoked
  // For if Token is expired
  if (new Date() > new Date(storedToken.expires_at)) {
    throw new AppError(
      "Session expired. Please log in again.",
      401,
      "TOKEN_EXPIRED"
    );
  }

  // Fetch the user to include role in the new access token
  const userResult = await pgPool.query(
    "SELECT id, role FROM users WHERE id = $1 ",
    [storedToken.user_id]
  );

  const user = userResult.rows[0];

  if (!user) {
    throw new AppError("User not found", 401, "USER_NOT_FOUND");
  }

  // Revoke the current token, it is single use
  await pgPool.query(
    "UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = NOW() WHERE id = $1",
    [storedToken.id]
  );

  // Issue a new token pair under the same family. Same familyId will keeps the revocation chain intact
  const refreshToken = await generateAndStoreRefreshToken(
    user.id,
    storedToken.family_id
  );
  const accessToken = generateAccessToken(user.id, user.role);

  return { accessToken, refreshToken };
}

// ---------------------------------------------------------------------------
// Google sign in
// Handles both new account creation and returning user login through
// Google OAuth. Applies the account linking rules.
// ---------------------------------------------------------------------------
export const googleAuth = async (code: string): Promise<{ user: SafeUser; tokens: TokenPair; isNewUser: boolean; }> => {
  const profile = await exchangeCodeForProfile(code);

  const result = await pgPool.query(
    `SELECT id, email, display_name, role, is_verified, created_at, provider
     FROM users
     WHERE email = $1 `,
    [profile.email]
  );

  const existing = result.rows[0];
  let user: typeof existing;
  let isNewUser = false;

  if (existing) {
    // Account exists. check the provider to apply linking rules.
    if (existing.provider !== "google") {
      throw new AppError(
        "An account already exists with this email. Please log in with your password instead.",
        409,
        "ACCOUNT_USES_PASSWORD"
      );
    }

    // Returning Google user, that signed up with google
    user = existing;
  } else {
    // New account via Google.
    const insertResult = await pgPool.query(
      `INSERT INTO users (email, display_name, provider, provider_id, is_verified)
       VALUES ($1, $2, 'google', $3, TRUE)
       RETURNING id, email, display_name, role, is_verified, created_at, provider`,
      [profile.email, profile.name, profile.sub]
    );

    user = insertResult.rows[0];
    isNewUser = true;

    // Fire and forget. never blocks the auth response.
    void sendWelcomeEmail(user.email, user.display_name);
  }

  // Update last login timestamp for both new and returning users.
  await pgPool.query(
    "UPDATE users SET last_login_at = NOW() WHERE id = $1",
    [user.id]
  );

  // Issue our own token pair, identical to password login.
  // Google's tokens are not stored or used again past this point.
  const familyId = generateToken(16);
  const refreshToken = await generateAndStoreRefreshToken(user.id, familyId);
  const accessToken = generateAccessToken(user.id, user.role);

  const safeUser: SafeUser = {
    id: user.id,
    email: user.email,
    display_name: user.display_name,
    role: user.role,
    is_verified: user.is_verified,
    created_at: user.created_at,
  };

  console.log(`[REMOVE LOG LATER] User authenticated via Google. ${user.id}. new account. ${isNewUser}`);

  return { user: safeUser, tokens: { accessToken, refreshToken }, isNewUser };
};

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------
export const logoutUser = async (rawToken: string): Promise<void> => {
  if (!rawToken) return;

  const tokenHash = hashToken(rawToken);

  await pgPool.query(
    "UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = NOW() WHERE token_hash = $1",
    [tokenHash]
  );
}

// ---------------------------------------------------------------------------
// Forgot password. Generates a reset token and emails it to the user.
// ---------------------------------------------------------------------------
export const requestPasswordReset = async (input: ForgotPasswordInput): Promise<void> => {
  // Look up the user. Intentionally not returning error if email not found.
  const result = await pgPool.query(
    "SELECT id, display_name FROM users WHERE email = $1 ",
    [input.email]
  );

  const user = result.rows[0];

  if (!user) {
    // Silently return even if the email is not found, to prevent email enumeration. The caller will send success response regardless.
    return;
  }

  // Invalidate any existing unused reset tokens for this user so only one valid reset link exists at a time.
  await pgPool.query(
    `UPDATE password_reset_tokens
     SET used_at = NOW()
     WHERE user_id = $1 AND used_at IS NULL`,
    [user.id]
  );

  // Generate a short-lived reset token. 15 minute expiry. single use enforced by used_at column.
  const rawToken = generateToken(32);    // 64-character hex string
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

  await pgPool.query(
    `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)`,
    [user.id, tokenHash, expiresAt]
  );

  await sendPasswordResetEmail(input.email, user.display_name, rawToken);

  console.log(`[REMOVE LOG LATER] Password reset email sent to user. ${user.id}`);

};

// ---------------------------------------------------------------------------
// Reset password. Verifies the token, updates the password, and invalidates all existing sessions forcing a fresh login.
// ---------------------------------------------------------------------------
export const resetPassword = async (input: ResetPasswordInput): Promise<void> => {
  const tokenHash = hashToken(input.token);

  // Look up the Hashed token in the database
  const result = await pgPool.query(
    `SELECT id, user_id, expires_at, used_at
     FROM password_reset_tokens
     WHERE token_hash = $1`,
    [tokenHash]
  );

  const resetToken = result.rows[0];

  if (!resetToken) {
    throw new AppError(
      "Invalid or expired request link. Please request a new one.",
      400,
      "INVALID_RESET_TOKEN"
    );
  }

  // Token already used
  if (resetToken.used_at !== null) {
    throw new AppError(
      "This reset link has already been used. Please request a new one.",
      400,
      "RESET_TOKEN_USED"
    );
  }

  // Token expired
  if (new Date() > new Date(resetToken.expires_at)) {
    throw new AppError(
      "This reset link has expired. Please request a new one.",
      400,
      "RESET_TOKEN_EXPIRED"
    );
  }

  // Hash the new password
  const newPasswordHash = await argon2.hash(input.password);

  // Marked the token as used first, before updating the password. to prevent a race condition where two simultaneous reset requests
  // could both succeed with the same token.
  await pgPool.query(
    "UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1",
    [resetToken.id]
  );

  // Update the password
  await pgPool.query(
    "UPDATE users SET password_hash = $1 WHERE id = $2",
    [newPasswordHash, resetToken.user_id]
  );

  // Revoke ALL refresh tokens for this user across all devices and families.
  // After a password reset, every existing session is invalid. The user must log in again with their new password.
  await pgPool.query(
    "UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = NOW() WHERE user_id = $1",
    [resetToken.user_id]
  );

  console.log(
    `Password reset successful. All sessions revoked for user. ${resetToken.user_id}`
  );
};

// ---------------------------------------------------------------------------
// Verify OTP. moves data from pending_registrations to users on success.
// ---------------------------------------------------------------------------
export const verifyRegistrationOtp = async (
  input: VerifyOtpInput
): Promise<{ user: SafeUser; tokens: TokenPair }> => {
  const pending = await pgPool.query(
    `SELECT id, email, display_name, password_hash, otp_hash, otp_expires_at, attempts
     FROM pending_registrations
     WHERE id = $1`,
    [input.pendingId]
  );

  const row = pending.rows[0];

  if (!row) {
    throw new AppError(
      "Registration session not found or expired. Please register again.",
      400,
      "PENDING_NOT_FOUND"
    );
  }

  // Block after 5 failed attempts to prevent OTP brute force
  if (row.attempts >= 5) {
    // Delete the pending row so the user must start over
    await pgPool.query(
      "DELETE FROM pending_registrations WHERE id = $1",
      [input.pendingId]
    );

    throw new AppError(
      "Too many incorrect attempts. Please register again.",
      429,
      "OTP_ATTEMPTS_EXCEEDED"
    );
  }

  // Check expiry
  if (new Date() > new Date(row.otp_expires_at)) {
    throw new AppError(
      "otp has expired! Please request a new one.",
      400,
      "OTP_EXPIRED"
    );
  }

  // Verify OTP by comparing hash
  const otpHash = hashToken(input.otp);

  if (otpHash !== row.otp_hash) {
    // Increment failed attempts counter
    await pgPool.query(
      "UPDATE pending_registrations SET attempts = attempts + 1 WHERE id = $1",
      [input.pendingId]
    );

    const remainingAttempts = 5 - (row.attempts + 1);

    throw new AppError(
      `Incorrect code. ${remainingAttempts} attempt${remainingAttempts === 1 ? "" : "s"} remaining.`,
      400,
      "INVALID_OTP"
    );
  }

  // OTP is valid. create the real user account.
  const userResult = await pgPool.query(
    `INSERT INTO users (email, password_hash, display_name, provider, is_verified)
     VALUES ($1, $2, $3, 'local', TRUE)
     RETURNING id, email, display_name, role, is_verified, created_at`,
    [row.email, row.password_hash, row.display_name]
  );

  const user: SafeUser = userResult.rows[0];

  // Delete the pending row immediately. no longer needed.
  await pgPool.query(
    "DELETE FROM pending_registrations WHERE id = $1",
    [input.pendingId]
  );

  // Issue tokens
  const familyId = generateToken(16);
  const refreshToken = await generateAndStoreRefreshToken(user.id, familyId);
  const accessToken = generateAccessToken(user.id, user.role);

  console.log(
    `OTP verified. user created successfully. ${user.id}`
  );

  // Fire and forget. does not block the response or affect registration outcome.
  // at larger scale queueing this email to a background worker would be more robust, but for now this is sufficient.
 void sendWelcomeEmail(user.email, user.display_name);

return { user, tokens: { accessToken, refreshToken } };
};

// ---------------------------------------------------------------------------
// Resend OTP. generates a fresh OTP for an existing pending registration.
// ---------------------------------------------------------------------------
export const resendOtp = async (input: ResendOtpInput): Promise<void> => {
  const pending = await pgPool.query(
    "SELECT id, email, display_name FROM pending_registrations WHERE id = $1",
    [input.pendingId]
  );

  const row = pending.rows[0];

  if (!row) {
    throw new AppError(
      "Registration session not found or expired. Please register again.",
      400,
      "PENDING_NOT_FOUND"
    );
  }

  // Generate a fresh OTP and reset the attempts counter
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpHash = hashToken(otp);
  const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);

  await pgPool.query(
    `UPDATE pending_registrations
     SET otp_hash = $1, otp_expires_at = $2, attempts = 0
     WHERE id = $3`,
    [otpHash, otpExpiresAt, input.pendingId]
  );

  await sendOtpEmail(row.email, row.display_name, otp);

  console.log(
    `[REMOVE LOG LATER] OTP resent for pendingId. ${input.pendingId}`
  );
};


// ---------------------------------------------------------------------------
// Get current user by ID, used by the /me endpoint
// ---------------------------------------------------------------------------
export const getUserById = async (userId: string): Promise<SafeUser> => {
  const result = await pgPool.query(
    `SELECT id, email, display_name, role, is_verified, created_at
     FROM users
     WHERE id = $1 `,
    [userId]
  );

  const user = result.rows[0];

  if (!user) {
    throw new AppError("User not found", 404, "USER_NOT_FOUND");
  }

  return user;
}