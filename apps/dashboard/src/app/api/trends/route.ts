/**
 * Trends API Route
 *
 * GET: Retrieve runs history for trends charting.
 */

import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { scanRuns } from '@/lib/schema';
import { getAuthUser } from '@/lib/auth';
import { eq, desc } from 'drizzle-orm';

export async function GET(req: Request) {
  try {
    const user = await getAuthUser(req);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(req.url);
    const repo = searchParams.get('repo');

    let query = db
      .select({
        id: scanRuns.id,
        repo: scanRuns.repo,
        scannedAt: scanRuns.scannedAt,
        passed: scanRuns.passed,
      })
      .from(scanRuns)
      .where(eq(scanRuns.userId, user.id))
      .orderBy(desc(scanRuns.scannedAt));

    const runs = await query;

    return NextResponse.json({ runs });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
