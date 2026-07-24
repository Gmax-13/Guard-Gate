/**
 * Login Rate Limit Check Plugin
 *
 * Verifies that repeated failed login attempts trigger rate-limiting or
 * account lockout. Sends N rapid failed login requests and checks for
 * 429 (Too Many Requests) or lockout response.
 */

import type { AssertionPlugin, AssertionResult, PluginContext } from '../plugin-interface.js';

/** Number of rapid failed login attempts to make */
const MAX_ATTEMPTS = 10;

export class LoginRateLimitPlugin implements AssertionPlugin {
  readonly name = 'loginRateLimitCheck';
  readonly displayName = 'Login Rate Limit Check';
  readonly type = 'security' as const;
  readonly description = 'Verifies failed login attempts trigger rate-limiting/lockout';

  private loginUrl: string | null = null;
  private loginMethod: string = 'POST';

  async beforeFlow(context: PluginContext): Promise<void> {
    this.loginUrl = null;
    this.loginMethod = 'POST';

    // Try to detect the login endpoint from intercepted requests
    context.page.on('request', (request) => {
      const url = request.url();
      if (
        (url.includes('login') || url.includes('signin') || url.includes('auth')) &&
        request.method() === 'POST'
      ) {
        this.loginUrl = url;
        this.loginMethod = request.method();
      }
    });
  }

  async afterFlow(context: PluginContext): Promise<AssertionResult[]> {
    const results: AssertionResult[] = [];

    // Try to find the login form on the page
    if (!this.loginUrl) {
      // Try to detect from the flow's intercepted requests
      const loginReq = context.interceptedRequests.find(
        (req) =>
          req.method === 'POST' &&
          (req.url.includes('login') || req.url.includes('signin') || req.url.includes('auth')),
      );

      if (loginReq) {
        this.loginUrl = loginReq.url;
      }
    }

    if (!this.loginUrl) {
      results.push({
        pluginName: this.name,
        pluginType: this.type,
        checkId: 'rate-limit-no-login',
        checkName: 'Rate Limit — No Login Endpoint',
        passed: true,
        message: 'No login endpoint detected, skipping rate limit check',
        severity: 'info',
      });
      return results;
    }

    // Send rapid failed login attempts
    let rateLimited = false;
    let lockout = false;
    const responses: Array<{ attempt: number; status: number }> = [];

    try {
      for (let i = 0; i < MAX_ATTEMPTS; i++) {
        try {
          const response = await context.page.evaluate(
            async ({ url, attempt }: { url: string; attempt: number }) => {
              const res = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  email: `attacker-${attempt}@example.com`,
                  username: `attacker-${attempt}`,
                  password: `wrong-password-${attempt}`,
                }),
                credentials: 'include',
              });
              return { status: res.status, body: await res.text() };
            },
            { url: this.loginUrl, attempt: i },
          );

          responses.push({ attempt: i + 1, status: response.status });

          if (response.status === 429) {
            rateLimited = true;
            break;
          }

          if (
            response.body.toLowerCase().includes('locked') ||
            response.body.toLowerCase().includes('too many') ||
            response.body.toLowerCase().includes('rate limit') ||
            response.body.toLowerCase().includes('try again later')
          ) {
            lockout = true;
            break;
          }
        } catch {
          // Ignore individual request errors
        }
      }
    } catch {
      // Ignore errors from page evaluation
    }

    if (!rateLimited && !lockout) {
      results.push({
        pluginName: this.name,
        pluginType: this.type,
        checkId: 'rate-limit-missing',
        checkName: 'No Login Rate Limiting',
        passed: false,
        message: `Sent ${MAX_ATTEMPTS} rapid failed login attempts to ${this.loginUrl} without triggering rate limiting or lockout. The login endpoint is vulnerable to brute-force attacks.`,
        severity: 'high',
        evidence: [
          {
            type: 'snippet',
            label: 'Login attempt results',
            data: JSON.stringify(responses),
          },
        ],
        metadata: {
          loginUrl: this.loginUrl,
          attempts: MAX_ATTEMPTS,
          responses,
        },
      });
    } else {
      const trigger = rateLimited ? 'HTTP 429 (Too Many Requests)' : 'lockout/rate limit message';
      const attemptCount = responses.length;

      results.push({
        pluginName: this.name,
        pluginType: this.type,
        checkId: 'rate-limit-ok',
        checkName: 'Login Rate Limiting OK',
        passed: true,
        message: `Login rate limiting detected after ${attemptCount} failed attempts (${trigger})`,
        severity: 'info',
        metadata: {
          loginUrl: this.loginUrl,
          attempts: attemptCount,
          trigger,
        },
      });
    }

    return results;
  }
}
