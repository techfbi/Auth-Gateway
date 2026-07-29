# Auth Gateway

A self-contained authentication module built with Node.js, TypeScript, Express, OAuth, PostgreSQL, and Redis. It covers local registration with optional email verification, login, rotating refresh tokens with theft detection, Google sign-in, and password reset. No third-party auth service in the middle.

Clone it, point it at your own database, fill in your environment variables, and have one of the most advanced production-ready auth layer running.


## Prerequisites

Node.js 18 or higher, a PostgreSQL 14 or higher instance, a Redis instance, a Resend account for transactional email, and a Google Cloud project with OAuth 2.0 credentials if you want Google sign-in.

The pg_cron extension must be available on your PostgreSQL instance for the scheduled cleanup jobs. On Neon, enable it from the Extensions tab. On a self-managed instance run `CREATE EXTENSION IF NOT EXISTS pg_cron` before running the migration.


## Getting started

```bash
git clone https://github.com/techfbi/Auth-Gateway.git
cd Auth Gateway
npm install
```

Run the migration against your PostgreSQL database. Or just paste the full query in your db schema

```bash
psql -U your_user -d your_database -f src/migrations/initial_schema.sql
```

Copy the example env file and fill in your values.

```bash
cp .env
npm run dev
```


## Environment variables

```env
NODE_ENV=development
PORT=5000
DATABASE_URL=postgresql://user:password@host/database?sslmode=require
CLIENT_URL=http://localhost:5173
REDIS_URL=redis://default:password@host:port
ACCESS_TOKEN_SECRET=at_least_32_characters_here
REFRESH_TOKEN_SECRET=different_32_character_string_here
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxx
GOOGLE_CLIENT_ID=xxxxxxxxxxxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxxxxxxxxxxxxxxx
GOOGLE_REDIRECT_URI=http://localhost:5173/auth/callback
REQUIRE_EMAIL_VERIFICATION=false
```

`env.ts` validates every variable at startup using Zod. If anything is missing the process exits immediately with a clear list of what failed.

`REQUIRE_EMAIL_VERIFICATION` toggles the registration flow. When `true`, registration returns a `pendingId` and sends an OTP to the user's email. The account is not created until the OTP is verified. When `false`, tokens are returned directly from the register response. Set to `true` in production once you have a verified sending domain in Resend. Defaults to `false`.


## File structure
Auth Gateway/
src/
auth module/
+ auth.controller.ts Request handlers for all ten auth endpoints
+ auth.routes.ts Route definitions with rate limiter middleware assigned per route
+ auth.schema.ts Zod validation schemas for every request body
+ auth.service.ts All auth business logic

config/
+ db.postgres.ts PostgreSQL pool setup
+ db.redis.ts Redis client setup
+ email.ts Resend client, OTP email, password reset email, welcome email
+ env.ts Environment variable loader with Zod validation
+ google.ts Google OAuth2 client and token exchange

middleware/
+ authenticate.ts JWT verification middleware for protected routes
+ errorHandler.ts Global error handler, formats all errors into the standard envelope
+ rateLimiter.ts Per-endpoint rate limiters backed by Redis
+ validate.ts Request body validation middleware

migrations/
+ initial_schema.sql All table definitions, indexes, and pg_cron cleanup jobs

shared/
+ crypto.ts Token generation (crypto.randomBytes) and SHA-256 hashing
+ errors.ts AppError class and error code constants
+ response.ts Success and error response helpers
+ types.ts Shared TypeScript types

app.ts Express app, middleware, routes
server.ts HTTP server entry point
Auth Gateway/
index.html Standalone documentation site, open directly in a browser

## API endpoints

All routes are under `/api/auth`. Full request and response documentation is in `index.html`.
POST /api/auth/register Create an account
POST /api/auth/verify-otp Complete registration when verification is enabled
POST /api/auth/resend-otp Request a fresh OTP for a pending registration
POST /api/auth/login Log in with email and password
POST /api/auth/refresh Rotate the refresh token, get a new access token
POST /api/auth/logout Revoke the current session
GET /api/auth/me Return the currently authenticated user
POST /api/auth/forgot-password Send a password reset email
POST /api/auth/reset-password Set a new password using the reset token
POST /api/auth/google Complete Google sign-in or sign-up

## Response envelope

Every response uses the same shape.

```json
{
  "success": true,
  "message": "Optional message",
  "data": {}
}
```

```json
{
  "success": false,
  "message": "Human readable description",
  "code": "MACHINE_READABLE_CODE"
}
```
The code field is stable and intended for client-side logic. The message field is safe to show to users.

## Frontend integration

Include `credentials: "include"` on every fetch call or the refresh cookie will not be sent on cross-origin requests. Store the access token in memory only, never in localStorage. When a request returns `401`, call `POST /api/auth/refresh` first, then retry. If the refresh also fails, the session is expired and the user must log in again.


## Deployment

Any Node.js hosting platform works. Set all environment variables in the platform dashboard, No need to set `NODE_ENV=production` in deployment platform, deployment platform sets this to poduction by default if the env is not povided, then run the database migration once against your production instance before the first deploy.

```bash
npm run build
npm start
```


## Notes
Lines marked `[REMOVE LOG LATER]` are debug logs that output internal values to the console. Search for that string and remove every occurrence before going to production.

## Contact
femiwebfullstack@gmail.com
