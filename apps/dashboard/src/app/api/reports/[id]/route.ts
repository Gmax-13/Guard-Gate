/**
 * Report Details API Route
 *
 * GET: Retrieve details of a specific scan run including findings.
 */

import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { scanRuns, findings } from '@/lib/schema';
import { getAuthUser } from '@/lib/auth';
import { eq, and } from 'drizzle-orm';

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const user = await getAuthUser(req);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await params;

    // Get the run
    const [run] = await db
      .select()
      .from(scanRuns)
      .where(and(eq(scanRuns.id, id), eq(scanRuns.userId, user.id)))
      .limit(1);

    if (!run) {
      return NextResponse.json({ error: 'Scan run not found' }, { status: 404 });
    }

    // Get findings
    const runFindings = await db
      .select()
      .from(findings)
      .where(eq(findings.runId, id));

    return NextResponse.json({ run, findings: runFindings });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
