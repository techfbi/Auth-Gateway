import axios from "axios";
import { env } from "./env.js";
import { AppError } from "../shared/errors.js";

// ---------------------------------------------------------------------------
// Shape of the user info Google returns after we exchange the code.
// ---------------------------------------------------------------------------
export interface GoogleProfile {
  sub: string; // Google's permanent unique id for this account. never changes.
  email: string;
  email_verified: boolean;
  name: string;
}

// ---------------------------------------------------------------------------
// exchangeCodeForProfile
// Takes the authorization code the frontend received from Google and performs the full server side exchange in two steps.
// ---------------------------------------------------------------------------
export const exchangeCodeForProfile = async (code: string): Promise<GoogleProfile> => {
  let accessToken: string;

  // Exchange code from google for access token. This is a server-to-server call that securely uses the client secret, which is why we do this on the backend instead of the frontend.
  try {
    const tokenResponse = await axios.post("https://oauth2.googleapis.com/token", {
        code,
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: env.GOOGLE_REDIRECT_URI,
        grant_type: "authorization_code",
      },
      { headers: { "Content-Type": "application/json" } }
    );

    console.log("[REMOVE LOG LATER] Google token response:", tokenResponse.data);
    accessToken = tokenResponse.data.access_token;

    if (!accessToken) {
      throw new Error("No access token in Google response");
    }
  } catch (err: any) {
    console.error(
      "[REMOVE LOG LATER] Google code exchange failed.",
      err?.response?.data ?? err?.message ?? err
    );
    throw new AppError(
      "Google sign in failed. Please try again.",
      401,
      "GOOGLE_AUTH_FAILED"
    );
  }

  // Second step is to use the access token to fetch the user's profile from Google's userinfo endpoint.
  try {
    const profileResponse = await axios.get( "https://www.googleapis.com/oauth2/v3/userinfo", { 
        headers: { Authorization: `Bearer ${accessToken}` } 
        }
    );

    console.log("[REMOVE LOG LATER] Google profile response:", profileResponse.data);
    const { sub, email, email_verified, name } = profileResponse.data;

    if (!sub || !email) {
      throw new Error("Incomplete profile from Google");
    }

    return { sub, email, email_verified, name };
  } catch (err: any) {
    console.error(
      "[REMOVE LOG LATER] Google profile fetch failed.",
      err?.response?.data ?? err?.message ?? err
    );
    throw new AppError(
      "Google sign in failed. Please try again.",
      401,
      "GOOGLE_AUTH_FAILED"
    );
  }
};