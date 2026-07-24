import { createHmac, createHash } from 'node:crypto';
import type { Finding } from '../../types/report.js';

export type VerificationStatus = 'ACTIVE' | 'REVOKED' | 'UNKNOWN';

export async function verifySecret(
  ruleId: string,
  secret: string,
  contextFindings: Finding[],
): Promise<VerificationStatus> {
  try {
    switch (ruleId) {
      case 'github-personal-access-token':
      case 'github-fine-grained-token':
        return await verifyGitHubToken(secret);
      
      case 'stripe-secret-key':
        return await verifyStripeKey(secret);

      case 'aws-secret-access-key':
        return await verifyAwsKey(secret, contextFindings);

      default:
        return 'UNKNOWN';
    }
  } catch (err) {
    return 'UNKNOWN';
  }
}

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs = 5000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    return response;
  } finally {
    clearTimeout(id);
  }
}

async function verifyGitHubToken(token: string): Promise<VerificationStatus> {
  try {
    const res = await fetchWithTimeout('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${token}`,
        'User-Agent': 'guardgate-scanner',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });
    if (res.status === 200) return 'ACTIVE';
    if (res.status === 401) return 'REVOKED';
    return 'UNKNOWN';
  } catch {
    return 'UNKNOWN';
  }
}

async function verifyStripeKey(key: string): Promise<VerificationStatus> {
  try {
    const res = await fetchWithTimeout('https://api.stripe.com/v1/balance', {
      headers: {
        Authorization: `Bearer ${key}`,
      },
    });
    if (res.status === 200) return 'ACTIVE';
    if (res.status === 401) return 'REVOKED';
    return 'UNKNOWN';
  } catch {
    return 'UNKNOWN';
  }
}

async function verifyAwsKey(secretKey: string, contextFindings: Finding[]): Promise<VerificationStatus> {
  // Find a matching AWS Access Key in the same context (file/commit)
  const accessKeyFinding = contextFindings.find(f => f.ruleId === 'aws-access-key-id');
  if (!accessKeyFinding) return 'UNKNOWN';

  // We only have the masked message, but wait, contextFindings here shouldn't just be the finding objects
  // Wait, in file-scanner.ts, findings only contain the masked secret.
  // We need the raw access key!
  // I will modify file-scanner.ts to pass raw context, or extract it.
  // Since we haven't modified file-scanner.ts yet, let's assume contextFindings contains a metadata.rawSecret field for AWS access keys.
  const accessKey = (accessKeyFinding.metadata?.rawSecret as string) || '';
  if (!accessKey) return 'UNKNOWN';

  try {
    // AWS SigV4 implementation for sts:GetCallerIdentity
    const region = 'us-east-1';
    const service = 'sts';
    const host = 'sts.amazonaws.com';
    const endpoint = `https://${host}/`;

    const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.substring(0, 8);

    const canonicalUri = '/';
    const canonicalQuerystring = 'Action=GetCallerIdentity&Version=2011-06-15';
    const canonicalHeaders = `host:${host}\nx-amz-date:${amzDate}\n`;
    const signedHeaders = 'host;x-amz-date';
    
    // empty body hash
    const payloadHash = createHash('sha256').update('').digest('hex');
    const canonicalRequest = `GET\n${canonicalUri}\n${canonicalQuerystring}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;

    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
    const stringToSign = `${algorithm}\n${amzDate}\n${credentialScope}\n${createHash('sha256').update(canonicalRequest).digest('hex')}`;

    const sign = (key: Buffer, msg: string) => createHmac('sha256', key).update(msg).digest();
    
    const kDate = sign(Buffer.from(`AWS4${secretKey}`, 'utf8'), dateStamp);
    const kRegion = sign(kDate, region);
    const kService = sign(kRegion, service);
    const kSigning = sign(kService, 'aws4_request');
    
    const signature = sign(kSigning, stringToSign).toString('hex');
    
    const authorizationHeader = `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const res = await fetchWithTimeout(`${endpoint}?${canonicalQuerystring}`, {
      method: 'GET',
      headers: {
        'x-amz-date': amzDate,
        'Authorization': authorizationHeader,
      },
    });

    if (res.status === 200) return 'ACTIVE';
    if (res.status === 401 || res.status === 403) return 'REVOKED';
    return 'UNKNOWN';
  } catch {
    return 'UNKNOWN';
  }
}
