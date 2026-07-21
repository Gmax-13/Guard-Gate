/**
 * Flow DSL Schema
 *
 * Zod schema for the YAML/JSON flow definition DSL.
 * Defines all supported step types for the generic flow runner.
 */

import { z } from 'zod';

/** Supported flow step actions */
export const flowStepSchema = z.discriminatedUnion('action', [
  z.object({
    action: z.literal('goto'),
    url: z.string(),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('fill'),
    selector: z.string(),
    value: z.string(),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('click'),
    selector: z.string(),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('waitForSelector'),
    selector: z.string(),
    timeout: z.number().optional(),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('waitForNavigation'),
    timeout: z.number().optional(),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('assertText'),
    selector: z.string(),
    text: z.string(),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('screenshot'),
    name: z.string().optional(),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('setHeader'),
    headers: z.record(z.string(), z.string()),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('clearCookies'),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('pause'),
    duration: z.number().default(1000),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('type'),
    selector: z.string(),
    text: z.string(),
    delay: z.number().optional(),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('select'),
    selector: z.string(),
    value: z.string(),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('check'),
    selector: z.string(),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('uncheck'),
    selector: z.string(),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('press'),
    key: z.string(),
    description: z.string().optional(),
  }),
  z.object({
    action: z.literal('evaluate'),
    script: z.string(),
    description: z.string().optional(),
  }),
]);

/** A single step in the flow */
export type FlowStep = z.infer<typeof flowStepSchema>;

/** The complete flow definition */
export const flowDefinitionSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  targetUrl: z.string(),
  /** Variables that can be interpolated in step values */
  variables: z.record(z.string(), z.string()).optional(),
  /** Tags for categorizing flows */
  tags: z.array(z.string()).optional(),
  /** Security plugins to run during this flow (empty = all) */
  plugins: z.array(z.string()).optional(),
  /** Steps to execute */
  steps: z.array(flowStepSchema).min(1),
});

export type FlowDefinition = z.infer<typeof flowDefinitionSchema>;
