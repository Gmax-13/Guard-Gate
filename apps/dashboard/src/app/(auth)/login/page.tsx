'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Shield } from 'lucide-react';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (res.ok) {
        router.push('/');
        router.refresh();
      } else {
        setError(data.error || 'Login failed');
      }
    } catch {
      setError('An unexpected error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        backgroundColor: 'var(--bg-primary)',
        padding: '24px',
      }}
    >
      <div
        style={{
          maxWidth: '400px',
          width: '100%',
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          boxShadow: 'var(--shadow-lg)',
          padding: '40px 32px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          animation: 'fadeIn 0.3s ease-out',
        }}
      >
        {/* Brand/Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '24px' }}>
          <Shield size={36} style={{ color: 'var(--accent)' }} />
          <span style={{ fontWeight: 800, fontSize: '26px' }}>GuardGate</span>
        </div>

        <h2 style={{ fontSize: '20px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-primary)' }}>
          Welcome back
        </h2>
        <p style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '32px', textAlign: 'center' }}>
          Sign in to access your security dashboard
        </p>

        {error && (
          <div
            style={{
              width: '100%',
              backgroundColor: 'var(--critical-light)',
              border: '1px solid var(--critical)',
              color: 'var(--critical)',
              borderRadius: '8px',
              padding: '12px 16px',
              fontSize: '14px',
              marginBottom: '20px',
            }}
          >
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label htmlFor="email" style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-secondary)' }}>
              Email address
            </label>
            <input
              type="email"
              id="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              style={{
                width: '100%',
                padding: '10px 14px',
                borderRadius: '8px',
                border: '1px solid var(--border)',
                backgroundColor: 'var(--bg-primary)',
                color: 'var(--text-primary)',
                fontSize: '14px',
                outline: 'none',
                transition: 'border-color 0.2s',
              }}
              placeholder="you@example.com"
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label htmlFor="password" style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-secondary)' }}>
              Password
            </label>
            <input
              type="password"
              id="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{
                width: '100%',
                padding: '10px 14px',
                borderRadius: '8px',
                border: '1px solid var(--border)',
                backgroundColor: 'var(--bg-primary)',
                color: 'var(--text-primary)',
                fontSize: '14px',
                outline: 'none',
                transition: 'border-color 0.2s',
              }}
              placeholder="••••••••"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%',
              padding: '12px',
              borderRadius: '8px',
              border: 'none',
              backgroundColor: 'var(--accent)',
              color: '#ffffff',
              fontSize: '14px',
              fontWeight: 600,
              marginTop: '8px',
              transition: 'background-color 0.2s',
            }}
            className="hover-scale"
          >
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>

        <p style={{ fontSize: '14px', color: 'var(--text-secondary)', marginTop: '28px' }}>
          Don&apos;t have an account?{' '}
          <Link href="/register" style={{ fontWeight: 600 }}>
            Sign up
          </Link>
        </p>
      </div>
    </div>
  );
}
