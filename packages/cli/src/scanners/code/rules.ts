import { pathToFileURL } from 'node:url';
import { z } from 'zod';
import { logger } from '../../utils/logger.js';
import { severityEnum } from '../../config/schema.js';
import type ts from 'typescript';

export const codeCustomRuleSchema = z.object({
  id: z.string(),
  severity: severityEnum,
  message: z.string(),
  check: z.function().args(z.any(), z.any(), z.any()).returns(z.boolean()),
});

export type CodeCustomRule = {
  id: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  message: string;
  check: (node: ts.Node, tsApi: typeof ts, context: any) => boolean;
};

export async function loadCodeRules(filePath: string): Promise<CodeCustomRule[]> {
  try {
    const fileUrl = pathToFileURL(filePath).href;
    const module = await import(fileUrl);
    
    // Support module.exports or export default
    const ruleObj = module.default || module;
    
    const result = codeCustomRuleSchema.safeParse(ruleObj);
    if (!result.success) {
      logger.error(`Invalid JS Code rule in ${filePath}:`);
      for (const issue of result.error.issues) {
        logger.error(`  ${issue.path.join('.')}: ${issue.message}`);
      }
      return [];
    }
    return [ruleObj as CodeCustomRule];
  } catch (err) {
    logger.error(`Failed to load JS Code rule ${filePath}: ${err instanceof Error ? err.message : String(err)}`);
    return [];
  }
}
