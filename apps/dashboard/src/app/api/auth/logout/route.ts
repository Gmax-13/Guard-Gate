/**
 * Logout API Route
 */

import { NextResponse } from 'next/server';

export async function POST() {
  const response = NextResponse.json({ message: 'Logout successful' });

  // Clear cookie
  response.headers.set(
    'Set-Cookie',
    'session_token=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax'
  );

  return response;
}
