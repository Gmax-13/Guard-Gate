/**
 * Configuration Schema
 *
 * Zod schemas for validating guardgate.config.yml.
 * Defines the shape of all configurable options across modules.
 */

import { z } from 'zod';

/** Shared severity enum schema */
export const severityEnum = z.enum(['info', 'low', 'medium', 'high', 'critical']);

/** Secrets scanner configuration */
export const secretsConfigSchema = z
  .object({
    /** Whether to scan the secrets module */
    enabled: z.boolean().default(true),
    /** File patterns to ignore (glob) */
    allowlist: z.array(z.string()).default([]),
    /** Whether to scan git history */
    scanHistory: z.boolean().default(true),
    /** Maximum number of commits to scan in history (0 = unlimited) */
    maxCommits: z.number().int().min(0).default(100),
    /** Entropy threshold for high-entropy string detection (0 to disable) */
    entropyThreshold: z.number().min(0).max(8).default(4.5),
    /** Custom rule patterns to add */
    customRules: z
      .array(
        z.object({
          id: z.string(),
          name: z.string(),
          regex: z.string(),
          severity: severityEnum.default('high'),
        }),
      )
      .default([]),
  })
  .default({});

/** SBOM scanner configuration */
export const sbomConfigSchema = z
  .object({
    enabled: z.boolean().default(true),
    /** Severity threshold for failing the scan */
    severityThreshold: severityEnum.default('high'),
    /** Ecosystems to scan (empty = auto-detect all) */
    ecosystems: z.array(z.string()).default([]),
    /** Packages to ignore (name@version or just name) */
    ignoredPackages: z.array(z.string()).default([]),
    /** Whether to include transitive dependencies */
    includeTransitive: z.boolean().default(true),
    /** Whether to generate SBOM file */
    generateSbom: z.boolean().default(true),
    /** SBOM output format */
    sbomFormat: z.enum(['cyclonedx', 'spdx']).default('cyclonedx'),
  })
  .default({});

/** E2E scanner configuration */
export const e2eConfigSchema = z
  .object({
    enabled: z.boolean().default(true),
    /** Target URL for E2E testing */
    targetUrl: z.string().url().optional(),
    /** Paths to flow definition files (YAML/JSON) */
    flowFiles: z.array(z.string()).default([]),
    /** Directory containing flow files */
    flowDir: z.string().optional(),
    /** Variables for flow interpolation */
    variables: z.record(z.string(), z.string()).default({}),
    /** Which security plugins to enable (empty = all) */
    plugins: z.array(z.string()).default([]),
    /** Playwright browser to use */
    browser: z.enum(['chromium', 'firefox', 'webkit']).default('chromium'),
    /** Whether to run browser in headless mode */
    headless: z.boolean().default(true),
    /** Timeout for each flow step in milliseconds */
    stepTimeout: z.number().int().min(1000).default(30000),
    /** Screenshot on failure */
    screenshotOnFailure: z.boolean().default(true),
  })
  .default({});

/** API Fuzzer configuration */
export const apiConfigSchema = z
  .object({
    enabled: z.boolean().default(true),
    /** Target URL for API testing */
    targetUrl: z.string().url().optional(),
    /** Paths to API flow definition files (YAML) */
    flowFiles: z.array(z.string()).default([]),
    /** Variables for API flow interpolation */
    variables: z.record(z.string(), z.string()).default({}),
    /** Timeout for each request in milliseconds */
    timeout: z.number().int().min(1000).default(10000),
  })
  .default({});

/** Code scanner configuration */
export const codeConfigSchema = z
  .object({
    /** Enable code scanner */
    enabled: z.boolean().default(true),
    /** Minimum severity to report */
    severityThreshold: severityEnum.default('medium'),
    /** File extensions to scan */
    extensions: z.array(z.string()).default(['.py', '.js', '.ts']),
    /** Paths to exclude from scanning (glob) */
    exclude: z.array(z.string()).default(['**/node_modules/**', '**/dist/**', '**/build/**']),
    /** Custom JS rule files */
    ruleFiles: z.array(z.string()).default([]),
  })
  .default({});

/** Top-level GuardGate configuration */
export const guardgateConfigSchema = z
  .object({
    /** Global severity threshold (can be overridden per module) */
    severityThreshold: severityEnum.default('high'),
    /** Output directory for reports and artifacts */
    outputDir: z.string().default('.guardgate'),
    /** Output format */
    outputFormat: z.enum(['json', 'console', 'both']).default('both'),
    /** Module-specific configuration */
    secrets: secretsConfigSchema,
    sbom: sbomConfigSchema,
    e2e: e2eConfigSchema,
    api: apiConfigSchema,
    code: codeConfigSchema,
  })
  .default({});

/** Inferred TypeScript type from the schema */
export type GuardGateConfig = z.infer<typeof guardgateConfigSchema>;
export type SecretsConfig = z.infer<typeof secretsConfigSchema>;
export type SbomConfig = z.infer<typeof sbomConfigSchema>;
export type E2eConfig = z.infer<typeof e2eConfigSchema>;
export type ApiConfig = z.infer<typeof apiConfigSchema>;
export type CodeConfig = z.infer<typeof codeConfigSchema>;
