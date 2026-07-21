/**
 * Authentication Middleware
 *
 * Protects dashboard pages and routes from unauthorized access.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verifyJWT } from './lib/auth-edge';

// Paths that do not require authentication
const PUBLIC_PATHS = [
  '/login',
  '/register',
  '/api/auth/login',
  '/api/auth/register',
];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Let API reports pass through to handle API Key auth inside the route itself
  if (pathname === '/api/reports' && request.method === 'POST') {
    return NextResponse.next();
  }

  // Check if the path is public
  const isPublic = PUBLIC_PATHS.some((path) => pathname.startsWith(path));

  // Retrieve session token from cookie
  const tokenCookie = request.cookies.get('session_token');
  const token = tokenCookie?.value;

  const user = token ? await verifyJWT(token) : null;

  if (!user && !isPublic) {
    // Redirect to login if unauthenticated on a protected path
    const loginUrl = new URL('/login', request.url);
    return NextResponse.redirect(loginUrl);
  }

  if (user && (pathname === '/login' || pathname === '/register')) {
    // Redirect to dashboard home if already logged in and visiting login/register
    const homeUrl = new URL('/', request.url);
    return NextResponse.redirect(homeUrl);
  }

  return NextResponse.next();
}

// Config to specify matching paths
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
