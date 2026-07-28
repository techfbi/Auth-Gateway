// src/config/email.ts
import { Resend } from "resend";
import { env } from "./env.js";

export const resend = new Resend(env.RESEND_API_KEY);

// Sends the password reset email containing the one-time raw token in link and hashed on arrival before we check db.
export const sendPasswordResetEmail = async (toEmail: string, displayName: string, rawToken: string): Promise<void> => {
  // The reset link points to frontend reset page with the token as a query param.
  // The frontend extracts the token and sends it to POST /api/auth/reset-password.
  const resetLink = `${env.CLIENT_URL}/reset-password?token=${rawToken}`;

  const { error } = await resend.emails.send({
    from: "(Brand name) <onboarding@resend.dev>", // Mail for testing with Resend, change to real email later
    to: toEmail,
    subject: "Reset your (Brand name) password",
    html: `
      <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
        <h2>Password reset request</h2>
        <p>Hi ${displayName},</p>
        <p>We received a request to reset your password. 
           Click the button below to set a new password.</p>
        <a href="${resetLink}"
           style="display: inline-block; padding: 12px 24px; background: #4F46E5;
                  color: white; text-decoration: none; border-radius: 6px; margin: 16px 0;">
          Reset password
        </a>
        <p>This link expires in 15 minutes.</p>
        <p>If you did not request a password reset, ignore this email. 
           Your password will not change.</p>
        <p>For security, do not share this link with anyone.</p>
      </div>
    `,
  });

  if (error) {
    // The forgot email endpoint willalways return 200 to avoid account enumeration, so I log the error here for debugging but do not throw.
    console.error("Failed to send password reset email.", error);
  }
};

//-------------------------------------------------------------------------------------------------------------------------------------------------
// Sends the 6-digit OTP to verify email ownership during registration.
export const sendOtpEmail = async ( toEmail: string, displayName: string, otp: string): Promise<void> => {

  const { error } = await resend.emails.send({
    from: "(Brand name) <onboarding@resend.dev>", // Mail for testing with Resend, change to real email later
    to: toEmail,
    subject: "Your (Brand name) verification code",
    html: `
      <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
        <h2>Verify your email address</h2>
        <p>Hi ${displayName},</p>
        <p>Enter the code below to complete your registration.</p>
        <div style="font-size: 36px; font-weight: bold; letter-spacing: 8px;
                    background: #F3F4F6; padding: 24px; text-align: center;
                    border-radius: 8px; margin: 24px 0;">
          ${otp}
        </div>
        <p>This code expires in 10 minutes.</p>
        <p>If you did not create a (Brand name) account, ignore this email.</p>
      </div>
    `,
  });

  if (error) {
    console.error("Failed to send OTP email.", error);
  }
};

// ---------------------------------------------------------------------------
// Sends a welcome email after successful registration.
// Always fire and forget. registration must never fail or be delayed because this email failed to send.
// Inline styles only and a table wrapper, since most email clients strip
// external stylesheets and Outlook specifically needs table based layout
// to render consistently. Brand fonts cannot load in email, so this falls
// back to a safe system sans-serif stack, which is standard practice.
// ---------------------------------------------------------------------------
export const sendWelcomeEmail = async (toEmail: string, displayName: string): Promise<void> => {
  const appLink = env.CLIENT_URL;

  const { error } = await resend.emails.send({
    from: "(Brand name) <onboarding@resend.dev>", // change to real domain email later
    to: toEmail,
    subject: "Welcome ----- ",
    html: `
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background: #F6F1E7; padding: 32px 16px;">
        <tr>
          <td align="center">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width: 520px; background: #FFFFFF; border-radius: 16px; overflow: hidden;">

              <!-- Header band -->
              <tr>
                <td style="background: #2F5D4B; padding: 28px 32px; text-align: center;">
                  <span style="font-family: Arial, Helvetica, sans-serif; font-size: 22px; font-weight: 700; letter-spacing: 2px; color: #FFFFFF;">(Brand name)</span>
                </td>
              </tr>

              <!-- Greeting -->
              <tr>
                <td style="padding: 32px 32px 8px 32px; font-family: Arial, Helvetica, sans-serif;">
                  <h2 style="margin: 0 0 8px 0; font-size: 22px; color: #1C1A17;">Welcome to (Brand name), ${displayName}</h2>
                  <p style="margin: 0; font-size: 15px; line-height: 1.6; color: #4B4640;">
                    Your account is ready. Here is what is waiting for you inside.
                  </p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    `,
  });

  if (error) {
    console.error(" Failed to send welcome email.", error);
  }
};