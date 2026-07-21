/**
 * Configuration Loader
 *
 * Loads and validates guardgate.config.yml from the project root.
 * Falls back to defaults if no config file exists.
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { guardgateConfigSchema, type GuardGateConfig } from './schema.js';
import { DEFAULT_CONFIG } from './defaults.js';
import { logger } from '../utils/logger.js';

/** Config file names to search for, in priority order. */
const CONFIG_FILE_NAMES = [
  'guardgate.config.yml',
  'guardgate.config.yaml',
  'guardgate.config.json',
  '.guardgaterc.yml',
  '.guardgaterc.yaml',
  '.guardgaterc.json',
];

/**
 * Find the config file path by searching the project root.
 */
function findConfigFile(rootDir: string, explicitPath?: string): string | null {
  if (explicitPath) {
    const fullPath = resolve(rootDir, explicitPath);
    if (existsSync(fullPath)) {
      return fullPath;
    }
    logger.warn(`Config file not found at ${fullPath}`);
    return null;
  }

  for (const name of CONFIG_FILE_NAMES) {
    const fullPath = join(rootDir, name);
    if (existsSync(fullPath)) {
      return fullPath;
    }
  }

  return null;
}

/**
 * Load and validate the GuardGate configuration.
 *
 * @param rootDir - The project root directory to search for config
 * @param configPath - Optional explicit path to a config file
 * @returns Validated configuration object
 */
export function loadConfig(rootDir: string, configPath?: string): GuardGateConfig {
  const configFile = findConfigFile(rootDir, configPath);

  if (!configFile) {
    logger.info('No config file found, using defaults');
    return DEFAULT_CONFIG;
  }

  logger.info(`Loading config from ${configFile}`);

  try {
    const raw = readFileSync(configFile, 'utf-8');
    let parsed: unknown;

    if (configFile.endsWith('.json')) {
      parsed = JSON.parse(raw);
    } else {
      parsed = parseYaml(raw);
    }

    const result = guardgateConfigSchema.safeParse(parsed);

    if (!result.success) {
      logger.error('Invalid configuration:');
      for (const issue of result.error.issues) {
        logger.error(`  ${issue.path.join('.')}: ${issue.message}`);
      }
      logger.warn('Falling back to default configuration');
      return DEFAULT_CONFIG;
    }

    return result.data;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to read config file: ${message}`);
    logger.warn('Falling back to default configuration');
    return DEFAULT_CONFIG;
  }
}
