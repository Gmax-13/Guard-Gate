/**
 * Database Schema
 *
 * Drizzle ORM schema for Neon Postgres.
 * Tables: users, api_keys, scan_runs, findings
 */

import { pgTable, uuid, varchar, timestamp, jsonb, boolean, integer } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// ─── Users Table ──────────────────────────────────────────────────────
export const users = pgTable('users', {
  id: uuid('id').defaultRandom().primaryKey(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  passwordHash: varchar('password_hash', { length: 255 }).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

// ─── API Keys Table (for CI integrations) ──────────────────────────────
export const apiKeys = pgTable('api_keys', {
  id: uuid('id').defaultRandom().primaryKey(),
  userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  keyHash: varchar('key_hash', { length: 255 }).notNull().unique(),
  name: varchar('name', { length: 100 }).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

// ─── Scan Runs Table ──────────────────────────────────────────────────
export const scanRuns = pgTable('scan_runs', {
  id: uuid('id').defaultRandom().primaryKey(),
  userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  repo: varchar('repo', { length: 255 }).notNull(),
  commitSha: varchar('commit_sha', { length: 100 }).notNull(),
  branch: varchar('branch', { length: 100 }).notNull(),
  scannedAt: timestamp('scanned_at').defaultNow().notNull(),
  summary: jsonb('summary').notNull(), // Aggregated pass/fail + findings counts
  passed: boolean('passed').notNull(),
});

// ─── Findings Table ───────────────────────────────────────────────────
export const findings = pgTable('findings', {
  id: uuid('id').defaultRandom().primaryKey(),
  runId: uuid('run_id').references(() => scanRuns.id, { onDelete: 'cascade' }).notNull(),
  module: varchar('module', { length: 50 }).notNull(), // secrets, sbom, e2e
  severity: varchar('severity', { length: 50 }).notNull(), // info, low, medium, high, critical
  filePath: varchar('file_path', { length: 500 }),
  lineNumber: integer('line_number'),
  message: varchar('message', { length: 1000 }).notNull(),
  evidence: jsonb('evidence'), // list of evidence objects (screenshot path, text snippet)
  metadata: jsonb('metadata'), // module-specific metadata (cve details, cookie metadata, etc.)
});

// ─── Relations ────────────────────────────────────────────────────────
export const usersRelations = relations(users, ({ many }) => ({
  apiKeys: many(apiKeys),
  scanRuns: many(scanRuns),
}));

export const apiKeysRelations = relations(apiKeys, ({ one }) => ({
  user: one(users, {
    fields: [apiKeys.userId],
    references: [users.id],
  }),
}));

export const scanRunsRelations = relations(scanRuns, ({ one, many }) => ({
  user: one(users, {
    fields: [scanRuns.userId],
    references: [users.id],
  }),
  findings: many(findings),
}));

export const findingsRelations = relations(findings, ({ one }) => ({
  scanRun: one(scanRuns, {
    fields: [findings.runId],
    references: [scanRuns.id],
  }),
}));
