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
    if (endpoint.assert.status !== undefined && status === endpoint.assert.status) {
      findings.push({
        id: `api-${endpoint.assert.plugin || 'fuzz'}-${Date.now()}`,
        module: 'api',
        ruleId: endpoint.assert.plugin || 'status-match',
        ruleName: `API Status Match (${status})`,
        severity: Severity.HIGH,
        message: `Endpoint returned expected vulnerable status code ${status}`,
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
