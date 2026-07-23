/**
 * Auth Bypass Check Plugin
 *
 * Attempts to access protected routes without a valid session.
 * Flags if access is granted (HTTP 200 with content) instead of
 * redirect/401/403.
 */

import type { AssertionPlugin, AssertionResult, PluginContext } from '../plugin-interface.js';

export class AuthBypassPlugin implements AssertionPlugin {
  readonly name = 'authBypassCheck';
  readonly displayName = 'Auth Bypass Check';
  readonly type = 'security' as const;
  readonly description = 'Checks if protected routes can be accessed without authentication';

  async afterFlow(context: PluginContext): Promise<AssertionResult[]> {
    const results: AssertionResult[] = [];

    // Look for responses to protected routes that returned 200
    // when no session cookies were present
    const protectedPatterns = [
      /\/admin/i,
      /\/dashboard/i,
      /\/profile/i,
      /\/settings/i,
      /\/account/i,
      /\/api\/private/i,
      /\/api\/admin/i,
    ];

    // Check intercepted requests for protected routes
    for (const req of context.interceptedRequests) {
      const url = new URL(req.url).pathname;
      const isProtected = protectedPatterns.some((pattern) => pattern.test(url));

      if (isProtected && req.status === 200) {
        // Check if the request had auth cookies
        const authCookies = context.cookies.filter(
          (c) =>
            c.name.toLowerCase().includes('session') ||
            c.name.toLowerCase().includes('token') ||
            c.name.toLowerCase().includes('auth') ||
            c.name.toLowerCase().includes('jwt'),
        );

        if (authCookies.length === 0) {
          results.push({
            pluginName: this.name,
            pluginType: this.type,
            checkId: 'auth-bypass-no-session',
            checkName: 'Auth Bypass — No Session',
            passed: false,
            message: `Protected route ${url} returned HTTP 200 without any session cookies. Possible authentication bypass.`,
            severity: 'critical',
            evidence: [
              {
                type: 'request',
                label: 'Request details',
                data: JSON.stringify({ url: req.url, method: req.method, status: req.status }),
              },
            ],
            metadata: { url: req.url, status: req.status },
          });
        }
      }
    }

    // Also test by clearing cookies and trying to access the page — only for protected routes
    try {
      const currentUrl = context.page.url();
      const currentPath = new URL(currentUrl).pathname;
      const isProtectedRoute = protectedPatterns.some((pattern) => pattern.test(currentPath));

      if (isProtectedRoute) {
        // Save current cookies
        const savedCookies = await context.browserContext.cookies();

        // Clear all cookies
        await context.browserContext.clearCookies();

        // Try to navigate to the current page
        const response = await context.page.goto(currentUrl, { waitUntil: 'domcontentloaded' });

        if (response && response.status() === 200) {
          // Check if we're redirected to a login page
          const finalUrl = context.page.url();
          const isLoginPage =
            finalUrl.includes('login') ||
            finalUrl.includes('signin') ||
            finalUrl.includes('auth');

          if (!isLoginPage) {
            results.push({
              pluginName: this.name,
              pluginType: this.type,
              checkId: 'auth-bypass-cleared-cookies',
              checkName: 'Auth Bypass — Cleared Cookies',
              passed: false,
              message: `Accessing ${currentUrl} after clearing cookies returned HTTP ${response.status()} and did not redirect to login. Possible auth bypass.`,
              severity: 'critical',
              evidence: [
                {
                  type: 'snippet',
                  label: 'Final URL after clearing cookies',
                  data: finalUrl,
                },
              ],
            });
          }
        }

        // Restore cookies
        if (savedCookies.length > 0) {
          await context.browserContext.addCookies(savedCookies);
        }
      }
    } catch {
      // Ignore navigation errors in auth bypass check
    }

    // If no issues found, report passing
    if (results.length === 0) {
      results.push({
        pluginName: this.name,
        pluginType: this.type,
        checkId: 'auth-bypass-check',
        checkName: 'Auth Bypass Check',
        passed: true,
        message: 'No authentication bypass vulnerabilities detected',
        severity: 'info',
      });
    }

    return results;
  }
}
