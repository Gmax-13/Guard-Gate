/**
 * API Keys Settings Route
 *
 * GET: List API keys for user.
 * POST: Create a new API key.
 * DELETE: Revoke an API key.
 */

import { NextResponse } from 'next/server';
import { randomBytes, createHash } from 'node:crypto';
import { db } from '../../../../lib/db.js';
import { apiKeys } from '../../../../lib/schema.js';
import { getAuthUser } from '../../../../lib/auth.js';
import { eq, and } from 'drizzle-orm';

export async function GET(req: Request) {
  try {
    const user = await getAuthUser(req);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const keys = await db
      .select({
        id: apiKeys.id,
        name: apiKeys.name,
        createdAt: apiKeys.createdAt,
      })
      .from(apiKeys)
      .where(eq(apiKeys.userId, user.id));

    return NextResponse.json({ keys });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function POST(req: Request) {
  try {
    const user = await getAuthUser(req);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { name } = await req.json();
    if (!name) {
      return NextResponse.json({ error: 'API key name is required' }, { status: 400 });
    }

    // Generate random API key (starts with "gg_")
    const rawKey = 'gg_' + randomBytes(24).toString('hex');
    const hash = createHash('sha256').update(rawKey).digest('hex');

    await db.insert(apiKeys).values({
      userId: user.id,
      keyHash: hash,
      name,
    });

    // Return the raw key to the user (once)
    return NextResponse.json({ rawKey, name }, { status: 201 });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function DELETE(req: Request) {
  try {
    const user = await getAuthUser(req);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(req.url);
    const keyId = searchParams.get('id');

    if (!keyId) {
      return NextResponse.json({ error: 'API key ID is required' }, { status: 400 });
    }

    await db
      .delete(apiKeys)
      .where(and(eq(apiKeys.id, keyId), eq(apiKeys.userId, user.id)));

    return NextResponse.json({ message: 'API key revoked' });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
