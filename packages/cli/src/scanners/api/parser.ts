import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { logger } from '../../utils/logger.js';

export const apiEndpointSchema = z.object({
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']),
  path: z.string(),
  query: z.record(z.string(), z.string()).optional(),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.any().optional(),
  assert: z
    .object({
      status: z.number().optional(),
      plugin: z.string().optional(),
      matchBody: z.string().optional(),
      notMatchBody: z.string().optional(),
    })
    .default({ status: 200 }),
  differential: z
    .object({
      ruleId: z.string(),
      severity: z.string(),
      payloads: z.object({ true: z.string(), false: z.string() }),
      compare: z.object({
        statusDiffers: z.boolean().optional(),
        bodyLengthDeltaThreshold: z.number().optional(),
        bodyHashDiffers: z.boolean().optional(),
      }),
    })
    .optional(),
  massAssignmentProbe: z
    .object({
      ruleId: z.string(),
      severity: z.string(),
      injectFields: z.record(z.string(), z.any()),
      assert: z.object({
        jsonPathPresent: z.array(z.string()),
        statusNotIn: z.array(z.number()),
      }),
    })
    .optional(),
});

export const apiFlowSchema = z.object({
  name: z.string(),
  variables: z.record(z.string(), z.string()).optional(),
  endpoints: z.array(apiEndpointSchema),
});

export type ApiEndpoint = z.infer<typeof apiEndpointSchema>;
export type ApiFlow = z.infer<typeof apiFlowSchema>;

export function parseApiFlow(filePath: string): ApiFlow | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const parsed = parseYaml(content);
    const result = apiFlowSchema.safeParse(parsed);
    if (!result.success) {
      logger.error(`Invalid API flow in ${filePath}:`);
      for (const issue of result.error.issues) {
        logger.error(`  ${issue.path.join('.')}: ${issue.message}`);
      }
      return null;
    }
    return result.data;
  } catch (err) {
    logger.error(`Failed to read/parse API flow ${filePath}: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}
