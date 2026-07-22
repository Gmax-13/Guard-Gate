import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { logger } from '../../utils/logger.js';
import { severityEnum } from '../../config/schema.js';

export const sastCustomRuleSchema = z.object({
  id: z.string(),
  severity: severityEnum,
  message: z.string(),
  nodeType: z.string().optional(),
  pattern: z.string(),
});

export const sastRulesSchema = z.object({
  name: z.string(),
  rules: z.array(sastCustomRuleSchema),
});

export type SastCustomRule = z.infer<typeof sastCustomRuleSchema>;
export type SastRulesConfig = z.infer<typeof sastRulesSchema>;

export function parseSastRules(filePath: string): SastCustomRule[] {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const parsed = parseYaml(content);
    const result = sastRulesSchema.safeParse(parsed);
    if (!result.success) {
      logger.error(`Invalid SAST rules in ${filePath}:`);
      for (const issue of result.error.issues) {
        logger.error(`  ${issue.path.join('.')}: ${issue.message}`);
      }
      return [];
    }
    return result.data.rules;
  } catch (err) {
    logger.error(`Failed to read/parse SAST rules ${filePath}: ${err instanceof Error ? err.message : String(err)}`);
    return [];
  }
}
