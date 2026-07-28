import { createClient } from "redis";
import { env } from "./env.js";

export const redis = createClient({ url: env.REDIS_URL });

redis.on("error", (err) => {
  console.error("Redis client error:", err.message);
});

export async function connectRedis(): Promise<void> {
  await redis.connect();
  console.log("Redis connected!");
}