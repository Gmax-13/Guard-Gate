/**
 * IDOR Check Plugin
 *
 * Attempts to access another user's resource by modifying ID parameters.
 * Flags if the application returns the resource without proper authorization.
 */

import type { AssertionPlugin, AssertionResult, PluginContext } from '../plugin-interface.js';

export class IdorPlugin implements AssertionPlugin {
  readonly name = 'idorCheck';
  readonly displayName = 'IDOR Check';
  readonly type = 'security' as const;
  readonly description = 'Checks for Insecure Direct Object Reference vulnerabilities';

  async afterFlow(context: PluginContext): Promise<AssertionResult[]> {
    const results: AssertionResult[] = [];

    // Look for requests with numeric/UUID-like IDs in the URL path or query
    const idPatterns = [
      /\/(\d+)(?:\/|$|\?)/g,                  // Numeric IDs in path
      /[?&]id=(\d+)/gi,                        // id= query param
      /[?&]userId?=(\d+)/gi,                    // userId query param
      /[?&]user_id=(\d+)/gi,                    // user_id query param
      /\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi, // UUID
    ];

    for (const req of context.interceptedRequests) {
      if (req.status !== 200) continue;

      const url = req.url;

      for (const pattern of idPatterns) {
        pattern.lastIndex = 0;
        const match = pattern.exec(url);

        if (match) {
          const originalId = match[1];

          // Try modifying the ID
          const modifiedId = this.modifyId(originalId);
          const modifiedUrl = url.substring(0, match.index) + url.substring(match.index).replace(originalId, modifiedId);

          try {
            const response = await context.page.goto(modifiedUrl, {
              waitUntil: 'domcontentloaded',
              timeout: 10000,
            });

            if (response && response.status() === 200) {
              // Check if we got actual content (not an error page)
              const pageContent = await context.page.content();
              const isErrorPage =
                pageContent.includes('not found') ||
                pageContent.includes('Not Found') ||
                pageContent.includes('404') ||
                pageContent.includes('unauthorized') ||
                pageContent.includes('forbidden') ||
                pageContent.includes('access denied');

              if (!isErrorPage && pageContent.length > 500) {
                results.push({
                  pluginName: this.name,
                  pluginType: this.type,
                  checkId: 'idor-id-modification',
                  checkName: 'IDOR — ID Modification',
                  passed: false,
                  message: `Modifying ID in ${url} from ${originalId} to ${modifiedId} returned HTTP 200 with content. Possible IDOR vulnerability.`,
                  severity: 'high',
                  evidence: [
                    {
                      type: 'request',
                      label: 'Modified request',
                      data: JSON.stringify({
                        originalUrl: url,
                        modifiedUrl,
                        originalId,
                        modifiedId,
                        status: response.status(),
                      }),
                    },
                  ],
                  metadata: {
                    originalUrl: url,
                    modifiedUrl,
                    originalId,
                    modifiedId,
                  },
                });
              }
            }
          } catch {
            // Ignore navigation errors
          }

          // Navigate back
          try {
            await context.page.goBack();
          } catch {
            // Ignore
          }
        }
      }
    }

    if (results.length === 0) {
      results.push({
        pluginName: this.name,
        pluginType: this.type,
        checkId: 'idor-check',
        checkName: 'IDOR Check',
        passed: true,
        message: 'No IDOR vulnerabilities detected',
        severity: 'info',
      });
    }

    return results;
  }

  /**
   * Modify an ID to test for IDOR.
   * For numeric IDs: increment by 1.
   * For UUIDs: change the last character.
   */
  private modifyId(id: string): string {
    // Numeric ID
    if (/^\d+$/.test(id)) {
      return String(parseInt(id, 10) + 1);
    }

    // UUID — change last char
    if (id.length > 1) {
      const lastChar = id[id.length - 1];
      const newChar = lastChar === '0' ? '1' : '0';
      return id.slice(0, -1) + newChar;
    }

    return id + '1';
  }
}
