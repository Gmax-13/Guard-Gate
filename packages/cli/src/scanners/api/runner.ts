import type { ApiEndpoint } from './parser.js';
import type { Finding } from '../../types/report.js';
import { Severity } from '../../types/report.js';
import { logger } from '../../utils/logger.js';

export async function runApiEndpoint(
  endpoint: ApiEndpoint,
  targetUrl: string,
  timeoutMs: number
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const fullUrl = `${targetUrl.replace(/\/$/, '')}${endpoint.path.startsWith('/') ? '' : '/'}${endpoint.path}`;

  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(fullUrl, {
      method: endpoint.method,
      headers: endpoint.headers,
      body: endpoint.body ? (typeof endpoint.body === 'string' ? endpoint.body : JSON.stringify(endpoint.body)) : undefined,
      signal: controller.signal,
    });
    clearTimeout(id);

    const status = res.status;
    const body = await res.text();

    // Check assertions
    let vulnerable = false;
    let reason = '';

    const expectedStatus = endpoint.assert.status;
    const { matchBody, notMatchBody } = endpoint.assert;

    // Determine vulnerability based on conditions provided
    if (matchBody) {
      if (new RegExp(matchBody).test(body)) {
        vulnerable = true;
        reason = `Response body matched vulnerable pattern /${matchBody}/`;
      }
    } else if (notMatchBody) {
      if (!new RegExp(notMatchBody).test(body)) {
        vulnerable = true;
        reason = `Response body failed to match safe pattern /${notMatchBody}/`;
      }
    } else if (expectedStatus !== undefined) {
      // Fallback: If only status is provided (weak check)
      if (status === expectedStatus) {
        vulnerable = true;
        reason = `Endpoint returned vulnerable status code ${status} (Weak indicator)`;
      }
    }

    // Narrow down with status if it was provided alongside body matches
    if (vulnerable && expectedStatus !== undefined && (matchBody || notMatchBody)) {
      if (status !== expectedStatus) {
        vulnerable = false; // Overridden because status didn't match
      } else {
        reason += ` and status code ${status}`;
      }
    }

    if (vulnerable) {
      findings.push({
        id: `api-${endpoint.assert.plugin || 'fuzz'}-${Date.now()}`,
        module: 'api',
        ruleId: endpoint.assert.plugin || 'body-match',
        ruleName: `API Vulnerability`,
        severity: Severity.HIGH,
        message: reason,
        evidence: [
          {
            type: 'request',
            label: 'Request Data',
            data: JSON.stringify({ method: endpoint.method, url: fullUrl, body: endpoint.body }),
          },
          {
            type: 'response',
            label: 'Response Body',
            data: body.slice(0, 1000),
          }
        ],
      });
    }

  } catch (err) {
    logger.debug(`API request failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  return findings;
}
