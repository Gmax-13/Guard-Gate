import type { ApiEndpoint } from './parser.js';
import type { Finding } from '../../types/report.js';
import { Severity } from '../../types/report.js';
import { randomUUID, createHash } from 'node:crypto';
import { logger } from '../../utils/logger.js';

export async function runApiEndpoint(
  endpoint: ApiEndpoint,
  targetUrl: string,
  timeoutMs: number
): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  try {
    if (endpoint.differential) {
      await runDifferential(endpoint, targetUrl, timeoutMs, findings);
    } else if (endpoint.massAssignmentProbe) {
      await runMassAssignment(endpoint, targetUrl, timeoutMs, findings);
    } else {
      await runStandard(endpoint, targetUrl, timeoutMs, findings);
    }
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    logger.warn(`API request failed (is the server running?): ${errMsg}`);
  }

  return findings;
}

function buildUrl(targetUrl: string, path: string, query?: Record<string, string>): string {
  const baseUrl = `${targetUrl.replace(/\/$/, '')}${path.startsWith('/') ? '' : '/'}${path}`;
  if (!query || Object.keys(query).length === 0) return baseUrl;
  
  const url = new URL(baseUrl);
  for (const [k, v] of Object.entries(query)) {
    url.searchParams.append(k, v);
  }
  return url.toString();
}

function substitutePayload(obj: any, payload: string): any {
  if (typeof obj === 'string') return obj.replace(/\{\{payload\}\}/g, payload);
  if (Array.isArray(obj)) return obj.map(item => substitutePayload(item, payload));
  if (obj !== null && typeof obj === 'object') {
    const res: any = {};
    for (const [k, v] of Object.entries(obj)) {
      res[k] = substitutePayload(v, payload);
    }
    return res;
  }
  return obj;
}

async function fetchEndpoint(endpoint: ApiEndpoint, url: string, timeoutMs: number, payload?: string) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  const finalUrl = payload ? substitutePayload(url, payload) : url;
  const finalHeaders = payload && endpoint.headers ? substitutePayload(endpoint.headers, payload) : endpoint.headers;
  const finalBody = payload && endpoint.body ? substitutePayload(endpoint.body, payload) : endpoint.body;

  try {
    const res = await fetch(finalUrl, {
      method: endpoint.method,
      headers: finalHeaders,
      body: finalBody ? (typeof finalBody === 'string' ? finalBody : JSON.stringify(finalBody)) : undefined,
      signal: controller.signal,
    });
    const status = res.status;
    const body = await res.text();
    return { status, body, requestUrl: finalUrl, requestBody: finalBody };
  } finally {
    clearTimeout(id);
  }
}

async function runDifferential(endpoint: ApiEndpoint, targetUrl: string, timeoutMs: number, findings: Finding[]) {
  const diff = endpoint.differential!;
  const url = buildUrl(targetUrl, endpoint.path, endpoint.query);

  const resTrue = await fetchEndpoint(endpoint, url, timeoutMs, diff.payloads.true);
  const resFalse = await fetchEndpoint(endpoint, url, timeoutMs, diff.payloads.false);

  let vulnerable = false;
  let reason = '';

  if (diff.compare.statusDiffers && resTrue.status !== resFalse.status) {
    vulnerable = true;
    reason = `Status codes differ (${resTrue.status} vs ${resFalse.status})`;
  } else if (diff.compare.bodyLengthDeltaThreshold !== undefined) {
    const delta = Math.abs(resTrue.body.length - resFalse.body.length);
    if (delta > diff.compare.bodyLengthDeltaThreshold) {
      vulnerable = true;
      reason = `Body length difference (${delta}) exceeds threshold (${diff.compare.bodyLengthDeltaThreshold})`;
    }
  } else if (diff.compare.bodyHashDiffers) {
    const hashTrue = createHash('sha256').update(resTrue.body).digest('hex');
    const hashFalse = createHash('sha256').update(resFalse.body).digest('hex');
    if (hashTrue !== hashFalse) {
      vulnerable = true;
      reason = 'Response body hashes differ completely';
    }
  }

  if (vulnerable) {
    findings.push({
      id: `api-diff-${diff.ruleId}-${randomUUID()}`,
      module: 'api',
      ruleId: diff.ruleId,
      ruleName: 'Differential API Vulnerability',
      severity: diff.severity as Severity,
      message: `Differential testing triggered: ${reason}`,
      evidence: [
        { type: 'request', label: 'True Payload Request', data: JSON.stringify({ url: resTrue.requestUrl, body: resTrue.requestBody }) },
        { type: 'response', label: 'True Payload Response', data: resTrue.body.slice(0, 500) },
        { type: 'request', label: 'False Payload Request', data: JSON.stringify({ url: resFalse.requestUrl, body: resFalse.requestBody }) },
        { type: 'response', label: 'False Payload Response', data: resFalse.body.slice(0, 500) },
      ],
    });
  }
}

// Very basic JSONPath subset evaluator (only $.key, $.key.subkey, or $['key'])
function checkJsonPath(obj: any, path: string): boolean {
  try {
    let current = obj;
    // Strip $. or $[
    const parts = path.replace(/^\$\.?/, '').replace(/\[['"]/g, '.').replace(/['"]\]/g, '').split('.');
    for (const part of parts) {
      if (!part) continue;
      if (current === undefined || current === null) return false;
      current = current[part];
    }
    return current !== undefined;
  } catch {
    return false;
  }
}

async function runMassAssignment(endpoint: ApiEndpoint, targetUrl: string, timeoutMs: number, findings: Finding[]) {
  const probe = endpoint.massAssignmentProbe!;
  const url = buildUrl(targetUrl, endpoint.path, endpoint.query);

  const res = await fetchEndpoint(endpoint, url, timeoutMs);

  if (probe.assert.statusNotIn && probe.assert.statusNotIn.includes(res.status)) {
    return; // Rejected by validation, safe
  }

  try {
    const jsonBody = JSON.parse(res.body);
    let matchedPaths: string[] = [];

    for (const path of probe.assert.jsonPathPresent) {
      if (checkJsonPath(jsonBody, path)) {
        matchedPaths.push(path);
      }
    }

    if (matchedPaths.length > 0) {
      findings.push({
        id: `api-mass-${probe.ruleId}-${randomUUID()}`,
        module: 'api',
        ruleId: probe.ruleId,
        ruleName: 'Mass Assignment Vulnerability',
        severity: probe.severity as Severity,
        message: `Mass assignment detected! Injected fields persisted/echoed: ${matchedPaths.join(', ')}`,
        evidence: [
          { type: 'request', label: 'Request Data', data: JSON.stringify({ url: res.requestUrl, body: res.requestBody }) },
          { type: 'response', label: 'Response Body', data: res.body.slice(0, 1000) },
        ],
      });
    }
  } catch {
    // If not JSON, we can't reliably assert structured assignment.
  }
}

async function runStandard(endpoint: ApiEndpoint, targetUrl: string, timeoutMs: number, findings: Finding[]) {
  const url = buildUrl(targetUrl, endpoint.path, endpoint.query);
  const res = await fetchEndpoint(endpoint, url, timeoutMs);

  let vulnerable = false;
  let reason = '';

  const expectedStatus = endpoint.assert.status;
  const { matchBody, notMatchBody } = endpoint.assert;

  if (matchBody) {
    if (new RegExp(matchBody).test(res.body)) {
      vulnerable = true;
      reason = `Response body matched vulnerable pattern /${matchBody}/`;
    }
  } else if (notMatchBody) {
    if (!new RegExp(notMatchBody).test(res.body)) {
      vulnerable = true;
      reason = `Response body failed to match safe pattern /${notMatchBody}/`;
    }
  } else if (expectedStatus !== undefined) {
    if (res.status === expectedStatus) {
      vulnerable = true;
      reason = `Endpoint returned vulnerable status code ${res.status} (Weak indicator)`;
    }
  }

  if (vulnerable && expectedStatus !== undefined && (matchBody || notMatchBody)) {
    if (res.status !== expectedStatus) {
      vulnerable = false;
    } else {
      reason += ` and status code ${res.status}`;
    }
  }

  if (vulnerable) {
    findings.push({
      id: `api-${endpoint.assert.plugin || 'fuzz'}-${randomUUID()}`,
      module: 'api',
      ruleId: endpoint.assert.plugin || 'body-match',
      ruleName: `API Vulnerability`,
      severity: Severity.HIGH,
      message: reason,
      evidence: [
        { type: 'request', label: 'Request Data', data: JSON.stringify({ url: res.requestUrl, body: res.requestBody }) },
        { type: 'response', label: 'Response Body', data: res.body.slice(0, 1000) },
      ],
    });
  }
}
