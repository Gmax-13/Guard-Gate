/**
 * Flow Context
 *
 * Manages shared state passed to plugins during flow execution.
 * Handles request interception and cookie tracking.
 */

import type { Page, BrowserContext } from 'playwright';
import type { PluginContext } from './plugin-interface.js';
import type { FlowStep } from './flow-schema.js';

/**
 * Create and manage the plugin context for a flow execution.
 */
export class FlowContext {
  private interceptedRequests: PluginContext['interceptedRequests'] = [];
  private currentStep?: FlowStep;
  private stepIndex?: number;

  constructor(
    private page: Page,
    private browserContext: BrowserContext,
    private targetUrl: string,
    private variables: Record<string, string>,
    private outputDir: string,
  ) {}

  /**
   * Set up request interception to capture HTTP traffic.
   */
  async setupInterception(): Promise<void> {
    this.page.on('response', async (response) => {
      try {
        const request = response.request();
        const requestHeaders: Record<string, string> = {};
        const responseHeaders: Record<string, string> = {};

        // Capture request headers
        const reqHeaders = await request.allHeaders();
        for (const [key, value] of Object.entries(reqHeaders)) {
          requestHeaders[key] = value;
        }

        // Capture response headers
        const resHeaders = await response.allHeaders();
        for (const [key, value] of Object.entries(resHeaders)) {
          responseHeaders[key] = value;
        }

        this.interceptedRequests.push({
          url: request.url(),
          method: request.method(),
          headers: requestHeaders,
          status: response.status(),
          responseHeaders,
        });
      } catch {
        // Ignore errors from closed pages
      }
    });
  }

  /**
   * Update the current step being executed.
   */
  setCurrentStep(step: FlowStep, index: number): void {
    this.currentStep = step;
    this.stepIndex = index;
  }

  /**
   * Build the PluginContext snapshot for plugin hooks.
   */
  async buildPluginContext(): Promise<PluginContext> {
    const cookies = await this.browserContext.cookies();

    return {
      page: this.page,
      browserContext: this.browserContext,
      currentStep: this.currentStep,
      stepIndex: this.stepIndex,
      cookies: cookies.map((c) => ({
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        httpOnly: c.httpOnly,
        secure: c.secure,
        sameSite: c.sameSite,
      })),
      interceptedRequests: [...this.interceptedRequests],
      targetUrl: this.targetUrl,
      variables: this.variables,
      outputDir: this.outputDir,
    };
  }

  /**
   * Clear intercepted requests (useful between distinct flow phases).
   */
  clearIntercepted(): void {
    this.interceptedRequests = [];
  }
}
