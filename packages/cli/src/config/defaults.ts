/**
 * Default Configuration
 *
 * Provides the default guardgate configuration when no config file is found.
 */

import type { GuardGateConfig } from './schema.js';

export const DEFAULT_CONFIG: GuardGateConfig = {
  severityThreshold: 'high',
  outputDir: '.guardgate',
  outputFormat: 'both',
  secrets: {
    enabled: true,
    allowlist: [
      '*.env.example',
      '*.test.*',
      '*.spec.*',
      '__tests__/**',
      '__mocks__/**',
      'test/**',
      'tests/**',
      'fixtures/**',
    ],
    scanHistory: true,
    maxCommits: 100,
    entropyThreshold: 4.5,
    customRules: [],
  },
  sbom: {
    enabled: true,
    severityThreshold: 'high',
    ecosystems: [],
    ignoredPackages: [],
    includeTransitive: true,
    generateSbom: true,
    sbomFormat: 'cyclonedx',
  },
  e2e: {
    enabled: true,
    targetUrl: undefined,
    flowFiles: [],
    flowDir: undefined,
    variables: {},
    plugins: [],
    browser: 'chromium',
    headless: true,
    stepTimeout: 30000,
    screenshotOnFailure: true,
  },
};
