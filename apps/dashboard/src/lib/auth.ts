/**
 * Authentication Utilities
 *
 * Password hashing (bcryptjs) and JWT validation (jose).
 * Safe for use in Next.js Edge Middleware and Route Handlers.
 */

import bcrypt from 'bcryptjs';
import { SignJWT, jwtVerify } from 'jose';

const JWT_SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET || 'guardgate-super-default-secret-key-change-me'
);

/**
 * Hash a password.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}

/**
 * Verify a password.
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Sign a JWT token.
 */
export async function createJWT(payload: { id: string; email: string }): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(JWT_SECRET);
}

/**
 * Verify a JWT token.
 */
export async function verifyJWT(token: string): Promise<{ id: string; email: string } | null> {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    return payload as unknown as { id: string; email: string };
  } catch {
    return null;
  }
}

/**
 * Authenticate a request.
 * Resolves user from cookie or Authorization header.
 */
export async function getAuthUser(req: Request): Promise<{ id: string; email: string } | null> {
  let token: string | null = null;

  // Check Cookie header
  const cookieHeader = req.headers.get('cookie') || '';
  const match = cookieHeader.match(/session_token=([^;]+)/);
  if (match) {
    token = match[1];
  }

  // Fallback to Authorization Header
  if (!token) {
    const authHeader = req.headers.get('authorization') || '';
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }
  }

  if (!token) return null;

  return verifyJWT(token);
}
