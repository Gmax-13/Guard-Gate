/**
 * Session Cookie Flags Check Plugin
 *
 * Verifies that session/auth cookies have proper security attributes:
 * - HttpOnly (prevents XSS-based cookie theft)
 * - Secure (cookies only sent over HTTPS)
 * - SameSite (prevents CSRF attacks)
 */

import type { AssertionPlugin, AssertionResult, PluginContext } from '../plugin-interface.js';

export class SessionCookieFlagsPlugin implements AssertionPlugin {
  readonly name = 'sessionCookieFlagsCheck';
  readonly displayName = 'Session Cookie Flags Check';
  readonly type = 'security' as const;
  readonly description = 'Verifies session cookies have HttpOnly, Secure, and SameSite attributes';

  async afterFlow(context: PluginContext): Promise<AssertionResult[]> {
    const results: AssertionResult[] = [];

    // Identify session/auth cookies
    const sessionCookiePatterns = [
      /session/i,
      /token/i,
      /auth/i,
      /jwt/i,
      /\bsid\b/i,
      /connect\.sid/i,
      /PHPSESSID/i,
      /JSESSIONID/i,
      /ASP\.NET_SessionId/i,
    ];

    const sessionCookies = context.cookies.filter((cookie) =>
      sessionCookiePatterns.some((pattern) => pattern.test(cookie.name)),
    );

    if (sessionCookies.length === 0) {
      results.push({
        pluginName: this.name,
        pluginType: this.type,
        checkId: 'session-cookie-none',
        checkName: 'No Session Cookies Found',
        passed: true,
        message: 'No session/auth cookies detected to check',
        severity: 'info',
      });
      return results;
    }

    for (const cookie of sessionCookies) {
      // Check HttpOnly
      if (!cookie.httpOnly) {
        results.push({
          pluginName: this.name,
          pluginType: this.type,
          checkId: 'session-cookie-missing-httponly',
          checkName: 'Missing HttpOnly Flag',
          passed: false,
          message: `Session cookie "${cookie.name}" is missing the HttpOnly flag. This allows JavaScript access, making it vulnerable to XSS-based cookie theft.`,
          severity: 'high',
          evidence: [
            {
              type: 'snippet',
              label: 'Cookie details',
              data: JSON.stringify({
                name: cookie.name,
                domain: cookie.domain,
                path: cookie.path,
                httpOnly: cookie.httpOnly,
                secure: cookie.secure,
                sameSite: cookie.sameSite,
              }),
            },
          ],
          metadata: { cookieName: cookie.name },
        });
      }

      // Check Secure
      if (!cookie.secure) {
        results.push({
          pluginName: this.name,
          pluginType: this.type,
          checkId: 'session-cookie-missing-secure',
          checkName: 'Missing Secure Flag',
          passed: false,
          message: `Session cookie "${cookie.name}" is missing the Secure flag. This means it can be sent over unencrypted HTTP connections.`,
          severity: 'medium',
          evidence: [
            {
              type: 'snippet',
              label: 'Cookie details',
              data: JSON.stringify({
                name: cookie.name,
                domain: cookie.domain,
                secure: cookie.secure,
              }),
            },
          ],
          metadata: { cookieName: cookie.name },
        });
      }

      // Check SameSite
      if (cookie.sameSite === 'None' || cookie.sameSite === '') {
        results.push({
          pluginName: this.name,
          pluginType: this.type,
          checkId: 'session-cookie-weak-samesite',
          checkName: 'Weak SameSite Attribute',
          passed: false,
          message: `Session cookie "${cookie.name}" has SameSite=${cookie.sameSite || 'not set'}. This may make the application vulnerable to CSRF attacks.`,
          severity: 'medium',
          evidence: [
            {
              type: 'snippet',
              label: 'Cookie details',
              data: JSON.stringify({
                name: cookie.name,
                domain: cookie.domain,
                sameSite: cookie.sameSite,
              }),
            },
          ],
          metadata: { cookieName: cookie.name },
        });
      }

      // If all flags are present and correct
      if (cookie.httpOnly && cookie.secure && cookie.sameSite !== 'None' && cookie.sameSite !== '') {
        results.push({
          pluginName: this.name,
          pluginType: this.type,
          checkId: 'session-cookie-flags-ok',
          checkName: 'Cookie Flags OK',
          passed: true,
          message: `Session cookie "${cookie.name}" has proper security attributes`,
          severity: 'info',
        });
      }
    }

    return results;
  }
}
