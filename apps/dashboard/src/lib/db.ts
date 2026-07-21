/**
 * Database Client
 *
 * Connects to Neon Postgres using serverless HTTP client.
 */

import { neon } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-http';
import * as schema from './schema.js';

if (!process.env.DATABASE_URL) {
  // During build, Vercel might not provide DATABASE_URL.
  // We provide a dummy setup so Next.js build compilation doesn't crash.
  console.warn('DATABASE_URL is not set. Database operations will fail.');
}

const connectionString = process.env.DATABASE_URL || 'postgres://dummy:dummy@localhost:5432/dummy';
const sql = neon(connectionString);

export const db = drizzle(sql, { schema });
export type DbClient = typeof db;
