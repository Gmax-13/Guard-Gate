/**
 * Reports API Route
 *
 * POST: Ingest scan reports (authenticated via JWT or API Key).
 * GET: Retrieve list of scan runs.
 */

import { NextResponse } from 'next/server';
import { createHash } from 'node:crypto';
import { db } from '../../../lib/db.js';
import { scanRuns, findings, apiKeys } from '../../../lib/schema.js';
import { getAuthUser, verifyJWT } from '../../../lib/auth.js';
import { eq, desc } from 'drizzle-orm';
import type { ScanReport } from '../../../../packages/cli/src/types/report.js';

/**
 * Authenticate request using JWT or API Key.
 */
async function authenticate(req: Request): Promise<string | null> {
  // Try JWT first
  const user = await getAuthUser(req);
  if (user) return user.id;

  // Fallback to API Key
  const authHeader = req.headers.get('authorization') || '';
  if (authHeader.startsWith('Bearer ')) {
    const key = authHeader.substring(7);
    const hash = createHash('sha256').update(key).digest('hex');
    
    const [apiKeyRecord] = await db
      .select()
      .from(apiKeys)
      .where(eq(apiKeys.keyHash, hash))
      .limit(1);

    if (apiKeyRecord) {
      return apiKeyRecord.userId;
    }
  }

  return null;
}

export async function POST(req: Request) {
  try {
    const userId = await authenticate(req);
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const report = (await req.json()) as ScanReport;

    if (!report.repository || !report.summary || !report.modules) {
      return NextResponse.json({ error: 'Invalid report schema' }, { status: 400 });
    }

    // Insert Scan Run
    const [insertedRun] = await db
      .insert(scanRuns)
      .values({
        userId,
        repo: report.repository.url,
        commitSha: report.repository.commitSha,
        branch: report.repository.branch,
        scannedAt: report.timestamp ? new Date(report.timestamp) : new Date(),
        summary: report.summary,
        passed: report.summary.passed,
      })
      .returning();

    // Insert Findings
    const findingsToInsert = report.modules.flatMap((m) =>
      m.findings.map((f) => ({
        runId: insertedRun.id,
        module: f.module,
        severity: f.severity,
        filePath: f.filePath || null,
        lineNumber: f.lineNumber || null,
        message: f.message,
        evidence: f.evidence || null,
        metadata: f.metadata || null,
      }))
    );

    if (findingsToInsert.length > 0) {
      await db.insert(findings).values(findingsToInsert);
    }

    return NextResponse.json(
      { message: 'Report processed successfully', runId: insertedRun.id },
      { status: 201 }
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('Report ingestion error:', err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function GET(req: Request) {
  try {
    const user = await getAuthUser(req);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // List runs ordered by date desc
    const runs = await db
      .select()
      .from(scanRuns)
      .where(eq(scanRuns.userId, user.id))
      .orderBy(desc(scanRuns.scannedAt));

    return NextResponse.json({ runs });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
