/**
 * Login API Route
 */

import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { users } from '@/lib/schema';
import { verifyPassword, createJWT } from '@/lib/auth';
import { eq } from 'drizzle-orm';

export async function POST(req: Request) {
  try {
    const { email, password } = await req.json();

    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      );
    }

    // Find user
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (!user) {
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      );
    }

    // Verify password
    const isPasswordValid = await verifyPassword(password, user.passwordHash);
    if (!isPasswordValid) {
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      );
    }

    // Generate JWT token
    const token = await createJWT({
      id: user.id,
      email: user.email,
    });

    const response = NextResponse.json({
      message: 'Login successful',
      user: { id: user.id, email: user.email },
    });

    // Set cookie
    response.headers.set(
      'Set-Cookie',
      `session_token=${token}; Path=/; HttpOnly; Max-Age=604800; SameSite=Lax; ${
        process.env.NODE_ENV === 'production' ? 'Secure' : ''
      }`
    );

    return response;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('Login error:', err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
