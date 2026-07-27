// Shared TypeScript types used across multiple modules.

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: string;
}

// Extends Express Request so TypeScript knows about req.user
// after the authenticate middleware has run.
declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}