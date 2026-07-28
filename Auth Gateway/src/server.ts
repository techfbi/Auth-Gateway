import "dotenv/config";
import { app } from "./app.js";
import { env } from "./config/env.js";
import { pgPool } from "./config/db.postgres.js";
import { connectRedis } from "./config/db.redis.js";

async function startServer(): Promise<void> {
  try {
    console.log(`Starting server in [${env.NODE_ENV}] mode...`);

    await pgPool.query("SELECT 1");
    console.log("PostgreSQL connected and responsive");

    await connectRedis();

    app.listen(env.PORT, () => {
      console.log(`Server listening on port ${env.PORT}`);
    });
  } catch (err) {
    console.error("FATAL: Server failed to start:", err);
    process.exit(1);
  }
}

startServer();