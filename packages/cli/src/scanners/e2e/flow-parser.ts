/**
 * Flow Parser
 *
 * Parses and validates YAML/JSON flow definition files.
 * Supports variable interpolation.
 */

import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { flowDefinitionSchema, type FlowDefinition } from './flow-schema.js';
import { logger } from '../../utils/logger.js';

/**
 * Parse a flow definition file (YAML or JSON).
 */
export function parseFlowFile(filePath: string): FlowDefinition {
  const content = readFileSync(filePath, 'utf-8');

  let raw: unknown;
  if (filePath.endsWith('.json')) {
    raw = JSON.parse(content);
  } else {
    raw = parseYaml(content);
  }

  const result = flowDefinitionSchema.safeParse(raw);

  if (!result.success) {
    const errors = result.error.issues
      .map((issue) => `  ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid flow definition in ${filePath}:\n${errors}`);
  }

  return result.data;
}

/**
 * Interpolate variables in a flow definition.
 * Replaces ${VAR_NAME} patterns with their values.
 *
 * Variable resolution order:
 * 1. Flow-level variables (from flow YAML)
 * 2. Config-level variables (from guardgate.config.yml)
 * 3. Environment variables
 */
export function interpolateVariables(
  flow: FlowDefinition,
  configVariables: Record<string, string> = {},
): FlowDefinition {
  const variables = {
    ...process.env,
    ...configVariables,
    ...flow.variables,
  };

  // Deep clone and interpolate
  const json = JSON.stringify(flow);
  const interpolated = json.replace(/\$\{([^}]+)\}/g, (match, varName: string) => {
    const value = variables[varName];
    if (value === undefined) {
      logger.warn(`Unresolved variable: ${match}`);
      return match;
    }
    // Escape for JSON string
    return value.replace(/"/g, '\\"');
  });

  return JSON.parse(interpolated) as FlowDefinition;
}
