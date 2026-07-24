import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { logger } from '../../utils/logger.js';
import type { ApiFlow, ApiEndpoint } from './parser.js';
import type { AuthState } from './runner.js';

type OpenApiDoc = any;
type OpenApiOperation = any;

interface FuzzTarget {
  path: string;
  method: string;
  location: 'query' | 'path' | 'body';
  paramName: string;
  type: string;
}

export function generateOpenApiFlows(specPath: string, authStates?: Record<string, AuthState>): ApiFlow | null {
  try {
    const content = readFileSync(specPath, 'utf-8');
    const spec = parseYaml(content) as OpenApiDoc;

    if (!spec || !spec.paths) {
      logger.error(`Invalid OpenAPI spec at ${specPath}`);
      return null;
    }

    spec = resolveRefs(spec, spec);

    const endpoints: ApiEndpoint[] = [];
    const targets = extractFuzzTargets(spec);

    // 1. Generate Differential SQLi Flows
    for (const target of targets) {
      const op = spec.paths[target.path][target.method];
      endpoints.push(buildDifferentialSqliFlow(target, op));
    }

    // 2. Generate Mass Assignment Flows
    for (const [path, pathItem] of Object.entries(spec.paths)) {
      for (const method of ['post', 'put', 'patch']) {
        const op = (pathItem as any)[method];
        if (!op) continue;

        const flow = buildMassAssignmentFlow(op, spec, path, method);
        if (flow) {
          endpoints.push(flow);
        }
      }
    }

    // 3. Generate IDOR Cross-Tenant Flows
    if (authStates && Object.keys(authStates).length >= 2) {
      const authProfiles = Object.keys(authStates) as [string, string, ...string[]];
      for (const [path, pathItem] of Object.entries(spec.paths)) {
        for (const method of ['get', 'put', 'patch', 'delete']) {
          const op = (pathItem as any)[method];
          if (!op) continue;

          // If the endpoint has a path parameter (likely an ID), it's a good IDOR candidate
          const hasPathParam = (op.parameters ?? []).some((p: any) => p.in === 'path');
          if (hasPathParam) {
            const flow = buildIdorCrossTenantFlow(op, path, method, authProfiles);
            endpoints.push(flow);
          }
        }
      }
    }

    return {
      name: `Auto-generated OpenAPI Flow`,
      endpoints,
    };
  } catch (err) {
    logger.error(`Failed to generate OpenAPI flow from ${specPath}: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}

function resolveRefs(obj: any, root: any, path: string[] = []): any {
  if (!obj || typeof obj !== 'object') return obj;

  if (obj.$ref && typeof obj.$ref === 'string' && obj.$ref.startsWith('#/')) {
    if (path.includes(obj.$ref)) return {}; // Prevent infinite loop on circular ref

    const parts = obj.$ref.substring(2).split('/');
    let current = root;
    for (const part of parts) {
      if (current === undefined) break;
      const decodedPart = part.replace(/~1/g, '/').replace(/~0/g, '~');
      current = current[decodedPart];
    }
    
    return resolveRefs(current, root, [...path, obj.$ref]);
  }

  if (Array.isArray(obj)) {
    return obj.map(item => resolveRefs(item, root, path));
  }

  const result: any = {};
  for (const [key, value] of Object.entries(obj)) {
    result[key] = resolveRefs(value, root, path);
  }
  return result;
}

function extractFuzzTargets(spec: OpenApiDoc): FuzzTarget[] {
  const targets: FuzzTarget[] = [];

  for (const [path, pathItem] of Object.entries(spec.paths)) {
    for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
      const op = (pathItem as any)[method];
      if (!op) continue;

      for (const p of op.parameters ?? []) {
        if (p.schema?.type === 'string' && !p.schema?.format) {
          targets.push({ path, method, location: p.in, paramName: p.name, type: 'string' });
        }
      }

      const bodySchema = op.requestBody?.content?.['application/json']?.schema;
      if (bodySchema?.properties) {
        for (const [key, propSchema] of Object.entries(bodySchema.properties)) {
          if ((propSchema as any).type === 'string' && !(propSchema as any).format) {
            targets.push({ path, method, location: 'body', paramName: key, type: 'string' });
          }
        }
      }
    }
  }
  return targets;
}

function synthesizeValueForField(schema: any): any {
  if (!schema) return 'test';
  if (schema.example !== undefined) return schema.example;
  if (schema.default !== undefined) return schema.default;
  switch (schema.type) {
    case 'string': return schema.format === 'uuid' ? '123e4567-e89b-12d3-a456-426614174000' : 'test_string';
    case 'integer':
    case 'number': return 1;
    case 'boolean': return true;
    case 'array': return [synthesizeValueForField(schema.items)];
    case 'object':
      const obj: any = {};
      if (schema.properties) {
        for (const [k, v] of Object.entries(schema.properties)) {
          obj[k] = synthesizeValueForField(v);
        }
      }
      return obj;
    default: return 'test';
  }
}

function synthesizeValidRequest(op: OpenApiOperation) {
  const query: Record<string, string> = {};
  let path = ''; // placeholder, we'll replace the full path string
  const body: any = {};
  const headers: Record<string, string> = {
    'Content-Type': 'application/json'
  };

  for (const p of op.parameters ?? []) {
    const val = synthesizeValueForField(p.schema);
    if (p.in === 'query') query[p.name] = String(val);
    if (p.in === 'header') headers[p.name] = String(val);
    // path params are usually string-replaced directly on the URL string.
  }

  const bodySchema = op.requestBody?.content?.['application/json']?.schema;
  if (bodySchema?.properties) {
    for (const [key, propSchema] of Object.entries(bodySchema.properties)) {
      body[key] = synthesizeValueForField(propSchema);
    }
  }

  return { query, body, headers };
}

function buildDifferentialSqliFlow(target: FuzzTarget, op: OpenApiOperation): ApiEndpoint {
  const baseline = synthesizeValidRequest(op);
  let resolvedPath = target.path;

  // Pre-fill all path parameters with valid dummy values
  for (const p of op.parameters ?? []) {
    if (p.in === 'path') {
      const val = target.location === 'path' && p.name === target.paramName 
        ? '{{payload}}' 
        : String(synthesizeValueForField(p.schema));
      resolvedPath = resolvedPath.replace(`{${p.name}}`, val);
    }
  }

  if (target.location === 'query') baseline.query[target.paramName] = '{{payload}}';
  if (target.location === 'body') baseline.body[target.paramName] = '{{payload}}';

  return {
    method: target.method.toUpperCase() as any,
    path: resolvedPath,
    query: baseline.query,
    headers: baseline.headers,
    body: Object.keys(baseline.body).length > 0 ? baseline.body : undefined,
    differential: {
      ruleId: 'sql-injection-blind',
      severity: 'critical',
      payloads: { true: "' OR '1'='1' -- ", false: "' AND '1'='2' -- " },
      compare: { statusDiffers: true, bodyLengthDeltaThreshold: 50 },
    },
  };
}

const DEFAULT_PRIVILEGED_FIELDS = { isAdmin: true, role: 'admin' };

function getPrivilegedFieldCandidates(spec: OpenApiDoc, resourcePath: string, targetMethod: string): Record<string, unknown> {
  const getSchema = spec.paths[resourcePath]?.get?.responses?.['200']?.content?.['application/json']?.schema;
  const postSchema = spec.paths[resourcePath]?.[targetMethod]?.requestBody?.content?.['application/json']?.schema;

  const readableFields = Object.keys(getSchema?.properties ?? {});
  const writableFields = new Set(Object.keys(postSchema?.properties ?? {}));

  const candidates: Record<string, unknown> = {};
  for (const field of readableFields) {
    if (!writableFields.has(field)) {
      candidates[field] = synthesizeValueForField(getSchema.properties[field]);
    }
  }

  return Object.keys(candidates).length ? candidates : DEFAULT_PRIVILEGED_FIELDS;
}

function buildMassAssignmentFlow(op: OpenApiOperation, spec: OpenApiDoc, path: string, method: string): ApiEndpoint | null {
  const bodySchema = op.requestBody?.content?.['application/json']?.schema;
  if (!bodySchema) return null; // No JSON body to inject into

  const baseline = synthesizeValidRequest(op);
  const injectFields = getPrivilegedFieldCandidates(spec, path, method);

  let resolvedPath = path;
  for (const p of op.parameters ?? []) {
    if (p.in === 'path') {
      resolvedPath = resolvedPath.replace(`{${p.name}}`, String(synthesizeValueForField(p.schema)));
    }
  }

  return {
    method: method.toUpperCase() as any,
    path: resolvedPath,
    query: baseline.query,
    headers: baseline.headers,
    body: { ...baseline.body, ...injectFields },
    massAssignmentProbe: {
      ruleId: 'mass-assignment',
      severity: 'high',
      injectFields,
      assert: {
        jsonPathPresent: Object.keys(injectFields).map(f => `$.${f}`),
        statusNotIn: [400, 422],
      },
    },
  };
}

function buildIdorCrossTenantFlow(op: OpenApiOperation, path: string, method: string, authProfiles: [string, string, ...string[]]): ApiEndpoint {
  const baseline = synthesizeValidRequest(op);
  let resolvedPath = path;

  // Pre-fill path parameters (which acts as the simulated resource ID)
  for (const p of op.parameters ?? []) {
    if (p.in === 'path') {
      resolvedPath = resolvedPath.replace(`{${p.name}}`, String(synthesizeValueForField(p.schema)));
    }
  }

  return {
    method: method.toUpperCase() as any,
    path: resolvedPath,
    query: baseline.query,
    headers: baseline.headers,
    body: Object.keys(baseline.body).length > 0 ? baseline.body : undefined,
    idorCrossTenant: {
      ruleId: 'idor-cross-tenant',
      severity: 'high',
      authProfiles: [authProfiles[0], authProfiles[1]],
    },
  };
}
