//This is to create PostgreSQL connection pool using pg library and validated environment variables (env). With error handling for the pool.

import pg from "pg";
import { env } from "./env.js";

const { Pool } = pg;

// Neon connection string already contains ?sslmode=verify-full.
// The pg library reads SSL mode directly from the connection string parameter.
export const pgPool = new Pool({
  connectionString: env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 20000, // 
});

pgPool.on("error", (err) => {
  console.error("PostgreSQL pool idle client error:", err.message);
});

pgPool.on("connect", () => {
  console.log("PostgreSQL pool: new client connected");
});