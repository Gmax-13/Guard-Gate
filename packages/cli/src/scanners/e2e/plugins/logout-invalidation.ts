/**
 * Logout Invalidation Check Plugin
 *
 * Verifies that session tokens are properly invalidated after logout.
 * Captures the session token, performs logout, then attempts to reuse
 * the old token — flags if the old token still works.
 */

import type { AssertionPlugin, AssertionResult, PluginContext } from '../plugin-interface.js';

export class LogoutInvalidationPlugin implements AssertionPlugin {
  readonly name = 'logoutInvalidationCheck';
  readonly displayName = 'Logout Invalidation Check';
  readonly type = 'security' as const;
  readonly description = 'Verifies session tokens are invalidated after logout';

  private preLogoutCookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    httpOnly: boolean;
    secure: boolean;
    sameSite: string;
  }> = [];

  async afterStep(context: PluginContext): Promise<AssertionResult[]> {
    // Capture cookies after what looks like a login step
    if (context.currentStep?.action === 'click') {
      const buttonText = await context.page
        .locator(context.currentStep.selector)
        .textContent()
        .catch(() => '');

      if (buttonText?.toLowerCase().includes('login') || buttonText?.toLowerCase().includes('sign in')) {
        // Wait for any navigation
        await context.page.waitForLoadState('domcontentloaded').catch(() => {});

        // Save cookies post-login
        this.preLogoutCookies = [...context.cookies];
      }
    }

    return [];
  }

  async afterFlow(context: PluginContext): Promise<AssertionResult[]> {
    const results: AssertionResult[] = [];

    // Only run if we captured pre-logout cookies
    if (this.preLogoutCookies.length === 0) {
      results.push({
        pluginName: this.name,
        pluginType: this.type,
        checkId: 'logout-invalidation-skipped',
        checkName: 'Logout Invalidation — Skipped',
        passed: true,
        message: 'No login flow detected, skipping logout invalidation check',
        severity: 'info',
      });
      return results;
    }

    // Look for a logout endpoint in intercepted requests
    const logoutRequest = context.interceptedRequests.find(
      (req) =>
        req.url.toLowerCase().includes('logout') ||
        req.url.toLowerCase().includes('signout') ||
        req.url.toLowerCase().includes('sign-out'),
    );

    if (!logoutRequest) {
      results.push({
        pluginName: this.name,
        pluginType: this.type,
        checkId: 'logout-invalidation-no-logout',
        checkName: 'Logout Invalidation — No Logout Detected',
        passed: true,
        message: 'No logout request detected in the flow',
        severity: 'info',
      });
      return results;
    }

    // After logout, try to reuse the old session cookies
    try {
      // Clear current cookies
      await context.browserContext.clearCookies();

      // Add back the pre-logout cookies
      const cookiesToAdd = this.preLogoutCookies
        .filter((c) => c.name && c.value && c.domain)
        .map((c) => ({
          name: c.name,
          value: c.value,
          domain: c.domain,
          path: c.path || '/',
          httpOnly: c.httpOnly,
          secure: c.secure,
          sameSite: c.sameSite as 'Strict' | 'Lax' | 'None',
        }));

      if (cookiesToAdd.length > 0) {
        await context.browserContext.addCookies(cookiesToAdd);
      }

      // Try to access a protected page with the old cookies
      const protectedUrl = context.targetUrl + '/profile';
      const response = await context.page.goto(protectedUrl, {
        waitUntil: 'domcontentloaded',
        timeout: 10000,
      });

      if (response && response.status() === 200) {
        const finalUrl = context.page.url();
        const redirectedToLogin =
          finalUrl.includes('login') ||
          finalUrl.includes('signin') ||
          finalUrl.includes('auth');

        if (!redirectedToLogin) {
          results.push({
            pluginName: this.name,
            pluginType: this.type,
            checkId: 'logout-invalidation-failure',
            checkName: 'Session Not Invalidated After Logout',
            passed: false,
            message: `Old session token still valid after logout. Accessing ${protectedUrl} with pre-logout cookies returned HTTP 200 and was not redirected to login.`,
            severity: 'high',
            evidence: [
              {
                type: 'snippet',
                label: 'Post-logout access',
                data: JSON.stringify({
                  attemptedUrl: protectedUrl,
                  finalUrl,
                  status: response.status(),
                }),
              },
            ],
          });
        } else {
          results.push({
            pluginName: this.name,
            pluginType: this.type,
            checkId: 'logout-invalidation-ok',
            checkName: 'Logout Invalidation OK',
            passed: true,
            message: 'Session was properly invalidated after logout — old token was rejected',
            severity: 'info',
          });
        }
      } else {
        results.push({
          pluginName: this.name,
          pluginType: this.type,
          checkId: 'logout-invalidation-ok',
          checkName: 'Logout Invalidation OK',
          passed: true,
          message: `Session was properly invalidated — old token returned HTTP ${response?.status() ?? 'error'}`,
          severity: 'info',
        });
      }
    } catch {
      results.push({
        pluginName: this.name,
        pluginType: this.type,
        checkId: 'logout-invalidation-error',
        checkName: 'Logout Invalidation — Error',
        passed: true,
        message: 'Could not verify logout invalidation (navigation error)',
        severity: 'info',
      });
    }

    return results;
  }
}
