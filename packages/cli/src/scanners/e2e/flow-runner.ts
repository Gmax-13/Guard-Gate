/**
 * Flow Runner (Layer 1)
 *
 * Generic Playwright-based flow executor. Reads a flow definition,
 * launches a browser, executes steps sequentially, and invokes
 * registered assertion plugins after each step.
 *
 * CRITICAL: This module has ZERO knowledge of security concepts.
 * It simply executes steps and calls plugin hooks.
 */

import { chromium, firefox, webkit, type Browser, type Page, type BrowserContext } from 'playwright';
import type { FlowDefinition, FlowStep } from './flow-schema.js';
import type { AssertionPlugin, AssertionResult } from './plugin-interface.js';
import { FlowContext } from './context.js';
import { logger } from '../../utils/logger.js';

export interface FlowRunnerOptions {
  /** Browser type to use */
  browser: 'chromium' | 'firefox' | 'webkit';
  /** Whether to run headless */
  headless: boolean;
  /** Timeout per step in milliseconds */
  stepTimeout: number;
  /** Whether to take screenshots on failure */
  screenshotOnFailure: boolean;
  /** Output directory for artifacts */
  outputDir: string;
}

export interface FlowRunResult {
  /** Flow name */
  flowName: string;
  /** Whether all steps completed successfully */
  stepsCompleted: boolean;
  /** Error message if a step failed */
  stepError?: string;
  /** Assertion results from all plugins */
  assertionResults: AssertionResult[];
  /** Duration in milliseconds */
  durationMs: number;
}

/**
 * Execute a flow definition with Playwright.
 */
export async function runFlow(
  flow: FlowDefinition,
  plugins: AssertionPlugin[],
  options: FlowRunnerOptions,
): Promise<FlowRunResult> {
  const startTime = Date.now();
  const assertionResults: AssertionResult[] = [];
  let stepsCompleted = false;
  let stepError: string | undefined;

  // Select browser
  const browserType = {
    chromium,
    firefox,
    webkit,
  }[options.browser];

  let browser: Browser | null = null;

  try {
    // Launch browser
    browser = await browserType.launch({ headless: options.headless });
    const context = await browser.newContext();
    const page = await context.newPage();

    // Set default timeout
    page.setDefaultTimeout(options.stepTimeout);

    // Create flow context
    const flowContext = new FlowContext(
      page,
      context,
      flow.targetUrl,
      flow.variables ?? {},
      options.outputDir,
    );
    await flowContext.setupInterception();

    // Call beforeFlow hooks on all plugins
    for (const plugin of plugins) {
      if (plugin.beforeFlow) {
        try {
          const ctx = await flowContext.buildPluginContext();
          await plugin.beforeFlow(ctx);
        } catch (err) {
          logger.warn(`Plugin ${plugin.name} beforeFlow error: ${err}`);
        }
      }
    }

    // Execute each step
    for (let i = 0; i < flow.steps.length; i++) {
      const step = flow.steps[i];
      flowContext.setCurrentStep(step, i);

      const stepDesc = step.description ?? `${step.action}`;
      logger.debug(`Step ${i + 1}/${flow.steps.length}: ${stepDesc}`);

      try {
        if (step.action === 'clearIntercepted') {
          flowContext.clearIntercepted();
        } else {
          await executeStep(page, context, step, flow.targetUrl);
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        stepError = `Step ${i + 1} (${step.action}) failed: ${message}`;
        logger.error(stepError);

        // Screenshot on failure
        if (options.screenshotOnFailure) {
          try {
            const screenshotPath = `${options.outputDir}/failure-step-${i + 1}.png`;
            await page.screenshot({ path: screenshotPath, fullPage: true });
            logger.debug(`Failure screenshot saved: ${screenshotPath}`);
          } catch {
            // Ignore screenshot errors
          }
        }
        break;
      }

      // Call afterStep hooks on all plugins
      for (const plugin of plugins) {
        if (plugin.afterStep) {
          try {
            const ctx = await flowContext.buildPluginContext();
            const results = await plugin.afterStep(ctx);
            assertionResults.push(...results);
          } catch (err) {
            logger.warn(`Plugin ${plugin.name} afterStep error: ${err}`);
          }
        }
      }
    }

    if (!stepError) {
      stepsCompleted = true;
    }

    // Call afterFlow hooks on all plugins
    for (const plugin of plugins) {
      if (plugin.afterFlow) {
        try {
          const ctx = await flowContext.buildPluginContext();
          const results = await plugin.afterFlow(ctx);
          assertionResults.push(...results);
        } catch (err) {
          logger.warn(`Plugin ${plugin.name} afterFlow error: ${err}`);
        }
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    stepError = `Flow execution failed: ${message}`;
    logger.error(stepError);
  } finally {
    if (browser) {
      await browser.close();
    }
  }

  return {
    flowName: flow.name,
    stepsCompleted,
    stepError,
    assertionResults,
    durationMs: Date.now() - startTime,
  };
}

/**
 * Execute a single flow step.
 * This function is security-agnostic — it just performs browser actions.
 */
async function executeStep(
  page: Page,
  context: BrowserContext,
  step: FlowStep,
  baseUrl: string,
): Promise<void> {
  switch (step.action) {
    case 'goto': {
      let url = step.url;
      if (!url.startsWith('http')) {
        const separator = baseUrl.endsWith('/') || url.startsWith('/') ? '' : '/';
        url = `${baseUrl}${separator}${url}`;
      }
      await page.goto(url, { waitUntil: 'domcontentloaded' });
      break;
    }

    case 'fill': {
      await page.fill(step.selector, step.value);
      break;
    }

    case 'click': {
      await page.click(step.selector);
      break;
    }

    case 'waitForSelector': {
      await page.waitForSelector(step.selector, {
        timeout: step.timeout,
      });
      break;
    }

    case 'waitForNavigation': {
      await page.waitForLoadState('domcontentloaded');
      break;
    }

    case 'assertText': {
      const element = await page.waitForSelector(step.selector);
      if (element) {
        const text = await element.textContent();
        if (!text?.includes(step.text)) {
          throw new Error(
            `Expected "${step.text}" in element "${step.selector}", got "${text}"`,
          );
        }
      } else {
        throw new Error(`Element not found: ${step.selector}`);
      }
      break;
    }

    case 'screenshot': {
      const name = step.name ?? `screenshot-${Date.now()}`;
      await page.screenshot({ path: `${name}.png`, fullPage: true });
      break;
    }

    case 'setHeader': {
      await context.setExtraHTTPHeaders(step.headers);
      break;
    }

    case 'clearCookies': {
      await context.clearCookies();
      break;
    }

    case 'clearIntercepted': {
      // Handled outside of executeStep
      break;
    }

    case 'pause': {
      await new Promise((resolve) => setTimeout(resolve, step.duration));
      break;
    }

    case 'type': {
      await page.type(step.selector, step.text, { delay: step.delay });
      break;
    }

    case 'select': {
      await page.selectOption(step.selector, step.value);
      break;
    }

    case 'check': {
      await page.check(step.selector);
      break;
    }

    case 'uncheck': {
      await page.uncheck(step.selector);
      break;
    }

    case 'press': {
      await page.keyboard.press(step.key);
      break;
    }

    case 'evaluate': {
      await page.evaluate(step.script);
      break;
    }

    default: {
      throw new Error(`Unknown action: ${(step as { action: string }).action}`);
    }
  }
}
