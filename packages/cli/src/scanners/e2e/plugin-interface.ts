/**
 * Assertion Plugin Interface
 *
 * Defines the contract for assertion plugins (both security and functional).
 * This is the Layer 2 extension point — plugins implement this interface
 * and self-register via the plugin registry.
 *
 * CRITICAL DESIGN RULE: The flow runner (Layer 1) has ZERO knowledge of
 * what plugins do. It simply calls the hooks. Plugins decide their own
 * assertions and evidence collection.
 */

import type { Page, BrowserContext, Response } from 'playwright';
import type { FlowStep } from './flow-schema.js';

/** The type/category of an assertion plugin */
export type PluginType = 'security' | 'functional';

/** Result from a single assertion check */
export interface AssertionResult {
  /** Plugin that produced this result */
  pluginName: string;
  /** Type of the plugin */
  pluginType: PluginType;
  /** Check identifier */
  checkId: string;
  /** Human-readable check name */
  checkName: string;
  /** Whether the check passed */
  passed: boolean;
  /** Human-readable description of what happened */
  message: string;
  /** Severity of the finding (if failed) */
  severity: string;
  /** Evidence supporting the result */
  evidence?: Array<{
    type: string;
    label: string;
    data: string;
  }>;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/** Context passed to plugins during hook execution */
export interface PluginContext {
  /** The Playwright page instance */
  page: Page;
  /** The Playwright browser context */
  browserContext: BrowserContext;
  /** The current flow step being executed (null during beforeFlow/afterFlow) */
  currentStep?: FlowStep;
  /** Index of the current step */
  stepIndex?: number;
  /** All cookies at this point */
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    httpOnly: boolean;
    secure: boolean;
    sameSite: string;
  }>;
  /** Intercepted HTTP requests/responses during the flow */
  interceptedRequests: Array<{
    url: string;
    method: string;
    headers: Record<string, string>;
    status?: number;
    responseHeaders?: Record<string, string>;
  }>;
  /** The target base URL for the flow */
  targetUrl: string;
  /** Flow-level variables */
  variables: Record<string, string>;
  /** Output directory for screenshots/artifacts */
  outputDir: string;
}

/** The interface that all assertion plugins must implement */
export interface AssertionPlugin {
  /** Unique name of this plugin */
  readonly name: string;

  /** Display name */
  readonly displayName: string;

  /** Type: 'security' or 'functional' */
  readonly type: PluginType;

  /** Description of what this plugin checks */
  readonly description: string;

  /**
   * Called before the flow starts executing.
   * Use for setup (e.g., intercepting requests).
   */
  beforeFlow?(context: PluginContext): Promise<void>;

  /**
   * Called after each step completes.
   * Use for per-step assertions.
   */
  afterStep?(context: PluginContext): Promise<AssertionResult[]>;

  /**
   * Called after the entire flow completes.
   * Use for flow-level assertions (e.g., checking all captured cookies).
   */
  afterFlow?(context: PluginContext): Promise<AssertionResult[]>;
}
