'use client';

import { useState, useEffect } from 'react';
import Navigation from '@/components/Navigation';
import { Key, Plus, Trash2, Copy, Check, Terminal, Shield, RefreshCw } from 'lucide-react';

interface ApiKey {
  id: string;
  name: string;
  createdAt: string;
}

export default function SettingsPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [newKeyName, setNewKeyName] = useState('');
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [generatedKey, setGeneratedKey] = useState('');
  const [copied, setCopied] = useState(false);
  const [origin, setOrigin] = useState('https://your-dashboard.com');

  useEffect(() => {
    if (typeof window !== 'undefined') {
      setOrigin(window.location.origin);
    }
  }, []);

  const fetchKeys = async () => {
    try {
      const res = await fetch('/api/settings/keys');
      const data = await res.json();
      if (data.keys) {
        setKeys(data.keys);
      }
    } catch (err) {
      console.error('Failed to fetch API keys:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKeys();
  }, []);

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName.trim()) return;

    setCreating(true);
    setGeneratedKey('');
    setCopied(false);

    try {
      const res = await fetch('/api/settings/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName }),
      });
      const data = await res.json();

      if (res.ok && data.rawKey) {
        setGeneratedKey(data.rawKey);
        setNewKeyName('');
        fetchKeys();
      }
    } catch (err) {
      console.error('Failed to create API key:', err);
    } finally {
      setCreating(false);
    }
  };

  const handleRevokeKey = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this API key? Any CI scan using this key will fail.')) return;

    try {
      const res = await fetch(`/api/settings/keys?id=${id}`, {
        method: 'DELETE',
      });

      if (res.ok) {
        setKeys(keys.filter((k) => k.id !== id));
      }
    } catch (err) {
      console.error('Failed to revoke API key:', err);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(generatedKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const formatDate = (isoStr: string) => {
    const d = new Date(isoStr);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <>
      <Navigation />
      <main style={{ padding: '40px 0', flex: 1 }}>
        <div className="container" style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
          {/* Header */}
          <div>
            <h1 style={{ fontSize: '28px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '6px' }}>
              Settings
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: '15px' }}>
              Manage credentials and view CI/CD pipeline integration guides.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 350px', gap: '32px', alignItems: 'start' }}>
            {/* Left Column: API Keys Management */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
              {/* Form card */}
              <div
                style={{
                  backgroundColor: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: '28px',
                  boxShadow: 'var(--shadow-sm)',
                }}
              >
                <h3 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Key size={20} style={{ color: 'var(--accent)' }} />
                  <span>CI/CD API Keys</span>
                </h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '24px', lineHeight: 1.5 }}>
                  API keys allow the GuardGate GitHub Action and CLI to authenticate and upload security scan reports directly to your dashboard.
                </p>

                {generatedKey && (
                  <div
                    style={{
                      backgroundColor: 'var(--accent-light)',
                      border: '1px solid var(--accent)',
                      borderRadius: '8px',
                      padding: '16px',
                      marginBottom: '24px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '12px',
                    }}
                  >
                    <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
                      ⚠️ Copy your new API key
                    </div>
                    <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                      For security reasons, this key will only be shown once. If you lose it, you will need to generate a new one.
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <code
                        style={{
                          flex: 1,
                          padding: '10px 14px',
                          backgroundColor: 'var(--bg-secondary)',
                          border: '1px solid var(--border)',
                          borderRadius: '6px',
                          fontFamily: 'monospace',
                          fontSize: '13px',
                          color: 'var(--text-primary)',
                        }}
                      >
                        {generatedKey}
                      </code>
                      <button
                        onClick={handleCopy}
                        style={{
                          padding: '10px 14px',
                          borderRadius: '6px',
                          border: 'none',
                          backgroundColor: 'var(--accent)',
                          color: '#ffffff',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px',
                          fontSize: '13px',
                          fontWeight: 600,
                        }}
                        className="hover-scale"
                      >
                        {copied ? <Check size={16} /> : <Copy size={16} />}
                        <span>{copied ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>
                )}

                <form onSubmit={handleCreateKey} style={{ display: 'flex', gap: '12px' }}>
                  <input
                    type="text"
                    required
                    placeholder="e.g. GitHub Actions Production"
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    style={{
                      flex: 1,
                      padding: '10px 14px',
                      borderRadius: '8px',
                      border: '1px solid var(--border)',
                      backgroundColor: 'var(--bg-primary)',
                      color: 'var(--text-primary)',
                      fontSize: '14px',
                      outline: 'none',
                    }}
                  />
                  <button
                    type="submit"
                    disabled={creating}
                    style={{
                      padding: '10px 20px',
                      borderRadius: '8px',
                      border: 'none',
                      backgroundColor: 'var(--accent)',
                      color: '#ffffff',
                      fontSize: '14px',
                      fontWeight: 600,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                    }}
                    className="hover-scale"
                  >
                    <Plus size={16} />
                    <span>{creating ? 'Creating...' : 'Generate Key'}</span>
                  </button>
                </form>
              </div>

              {/* List card */}
              <div
                style={{
                  backgroundColor: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  boxShadow: 'var(--shadow-sm)',
                  overflow: 'hidden',
                }}
              >
                <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', backgroundColor: 'var(--bg-primary)' }}>
                  <h4 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>Active API Keys</h4>
                </div>

                {loading ? (
                  <div style={{ padding: '40px 24px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                    Loading API keys...
                  </div>
                ) : keys.length === 0 ? (
                  <div style={{ padding: '40px 24px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '14px' }}>
                    No API keys created yet. Generate one above to integrate with CI pipelines.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    {keys.map((key) => (
                      <div
                        key={key.id}
                        style={{
                          padding: '16px 24px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          borderBottom: '1px solid var(--border)',
                        }}
                      >
                        <div>
                          <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>{key.name}</div>
                          <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                            Created: {formatDate(key.createdAt)}
                          </div>
                        </div>

                        <button
                          onClick={() => handleRevokeKey(key.id)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: 'var(--critical)',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px',
                            fontSize: '13px',
                            fontWeight: 600,
                            padding: '8px 12px',
                            borderRadius: '6px',
                          }}
                          className="hover-scale hover-bg-primary"
                        >
                          <Trash2 size={16} />
                          <span>Revoke</span>
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Right Column: CI/CD Documentation */}
            <div
              style={{
                backgroundColor: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: '28px',
                boxShadow: 'var(--shadow-sm)',
                display: 'flex',
                flexDirection: 'column',
                gap: '20px',
              }}
            >
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Terminal size={18} style={{ color: 'var(--accent)' }} />
                <span>Integration Guide</span>
              </h3>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>GitHub Action Setup</div>
                <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  Add your GuardGate API key as a Repository Secret named <code style={{ fontFamily: 'monospace' }}>GUARDGATE_API_KEY</code>.
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  Create a workflow file <code style={{ fontFamily: 'monospace' }}>.github/workflows/security.yml</code>:
                </div>
                <pre
                  style={{
                    padding: '12px',
                    backgroundColor: 'var(--bg-primary)',
                    border: '1px solid var(--border)',
                    borderRadius: '8px',
                    fontSize: '11px',
                    fontFamily: 'monospace',
                    overflowX: 'auto',
                    color: 'var(--text-primary)',
                  }}
                >
{`name: GuardGate Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./packages/github-action
        with:
          dashboard-url: '${origin}'
          dashboard-api-key: \`\${{ secrets.GUARDGATE_API_KEY }}\`
`}
                </pre>
              </div>
            </div>
          </div>
        </div>
      </main>
    </>
  );
}
