/**
 * Authentication Utilities (Node.js/Route Handler Specific)
 *
 * Password hashing and validation using bcryptjs.
 */

import bcrypt from 'bcryptjs';

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

// Re-export Edge-compatible JWT helpers for convenience in API routes
export { createJWT, verifyJWT, getAuthUser } from './auth-edge';
