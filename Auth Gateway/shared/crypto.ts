import crypto from "crypto";

//functions for generating and hashing tokens, used for things like password resets or email verification. 
export function generateToken(byteLength = 48): string {
  return crypto.randomBytes(byteLength).toString("hex");
}

export function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}