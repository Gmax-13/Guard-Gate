'use client';

import { use, useEffect, useState } from 'react';
import Link from 'next/link';
import Navigation from '@/components/Navigation';
import { ArrowLeft, Shield, AlertTriangle, Info, Terminal, ChevronDown, ChevronUp, FileCode } from 'lucide-react';

interface Finding {
  id: string;
  module: string;
  severity: string;
  filePath?: string;
  lineNumber?: number;
  message: string;
  evidence?: Array<{ type: string; label: string; data: string }>;
  metadata?: Record<string, any>;
}

interface ScanRun {
  id: string;
  repo: string;
  commitSha: string;
  branch: string;
  scannedAt: string;
  passed: boolean;
  summary: {
    passed: boolean;
    totalFindings: number;
    findingsBySeverity: Record<string, number>;
    moduleStatus: Record<string, boolean>;
  };
}

export default function RunDetailsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [run, setRun] = useState<ScanRun | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'all' | 'secrets' | 'sbom' | 'code' | 'api' | 'e2e'>('all');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  useEffect(() => {
    const fetchDetails = async () => {
      try {
        const res = await fetch(`/api/reports/${id}`);
        const data = await res.json();
        if (data.run) {
          setRun(data.run);
          setFindings(data.findings);
        }
      } catch (err) {
        console.error('Failed to fetch details:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchDetails();
  }, [id]);

  const toggleExpand = (findingId: string) => {
    setExpandedFindings((prev) => ({
      ...prev,
      [findingId]: !prev[findingId],
    }));
  };

  const getSeverityStyle = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return { color: 'var(--critical)', bg: 'var(--critical-light)' };
      case 'high':
        return { color: 'var(--high)', bg: 'var(--high-light)' };
      case 'medium':
        return { color: 'var(--medium)', bg: 'var(--medium-light)' };
      case 'low':
        return { color: 'var(--low)', bg: 'var(--low-light)' };
      default:
        return { color: 'var(--info)', bg: 'var(--info-light)' };
    }
  };

  const filteredFindings = findings.filter(
    (f) => activeTab === 'all' || f.module.toLowerCase() === activeTab.toLowerCase()
  );

  const formatDate = (isoStr: string) => {
    const d = new Date(isoStr);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  if (loading) {
    return (
      <>
        <Navigation />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '50vh', color: 'var(--text-secondary)' }}>
          Loading details...
        </div>
      </>
    );
  }

  if (!run) {
    return (
      <>
        <Navigation />
        <div className="container" style={{ padding: '80px 24px', textAlign: 'center' }}>
          <Shield size={48} style={{ color: 'var(--critical)', marginBottom: '16px' }} />
          <h2>Scan run not found</h2>
          <p style={{ color: 'var(--text-secondary)', marginTop: '8px' }}>
            The requested scan report does not exist or has been deleted.
          </p>
          <Link href="/" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', marginTop: '24px', fontWeight: 600 }}>
            <ArrowLeft size={16} /> Back to dashboard
          </Link>
        </div>
      </>
    );
  }

  return (
    <>
      <Navigation />
      <main style={{ padding: '40px 0', flex: 1 }}>
        <div className="container" style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
          {/* Header Action */}
          <div>
            <Link
              href="/"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '14px',
                fontWeight: 600,
                color: 'var(--text-secondary)',
                marginBottom: '16px',
              }}
              className="hover-scale"
            >
              <ArrowLeft size={16} />
              <span>Back to runs</span>
            </Link>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
              <div>
                <h1 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Scan Details: {run.repo.split('/').slice(-1)[0]}
                </h1>
                <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginTop: '6px', fontFamily: 'monospace' }}>
                  Run ID: {run.id}
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '8px 16px',
                    borderRadius: 'var(--radius)',
                    fontSize: '14px',
                    fontWeight: 700,
                    backgroundColor: run.passed ? 'var(--success-light)' : 'var(--failure-light)',
                    color: run.passed ? 'var(--success)' : 'var(--failure)',
                  }}
                >
                  {run.passed ? 'PASSED' : 'FAILED'}
                </span>
              </div>
            </div>
          </div>

          {/* Meta Info Panel */}
          <div
            style={{
              backgroundColor: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: '24px',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: '24px',
            }}
          >
            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Repository URL</div>
              <div style={{ fontSize: '15px', color: 'var(--text-primary)', marginTop: '6px', overflowWrap: 'anywhere' }}>{run.repo}</div>
            </div>
            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Branch & Commit</div>
              <div style={{ fontSize: '15px', color: 'var(--text-primary)', marginTop: '6px', display: 'flex', gap: '12px', alignItems: 'center' }}>
                <span style={{ fontWeight: 600 }}>{run.branch}</span>
                <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>{run.commitSha.substring(0, 8)}</span>
              </div>
            </div>
            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Scanned At</div>
              <div style={{ fontSize: '15px', color: 'var(--text-primary)', marginTop: '6px' }}>{formatDate(run.scannedAt)}</div>
            </div>
            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Total Findings</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '6px' }}>
                {run.summary.totalFindings}
              </div>
            </div>
          </div>

          {/* Tab Navigation */}
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', gap: '24px' }}>
            {(['all', 'secrets', 'sbom', 'code', 'api', 'e2e'] as const).map((tab) => {
              const isActive = activeTab === tab;
              const count = tab === 'all' ? findings.length : findings.filter((f) => f.module === tab).length;

              return (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  style={{
                    padding: '12px 4px',
                    border: 'none',
                    background: 'none',
                    borderBottom: isActive ? '2px solid var(--accent)' : '2px solid transparent',
                    color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
                    fontWeight: isActive ? 600 : 500,
                    fontSize: '15px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    transition: 'color 0.2s, border-color 0.2s',
                  }}
                >
                  <span style={{ textTransform: 'capitalize' }}>{tab}</span>
                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      backgroundColor: isActive ? 'var(--accent-light)' : 'var(--border)',
                      color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
                      borderRadius: '10px',
                      padding: '2px 8px',
                      fontSize: '11px',
                      fontWeight: 600,
                    }}
                  >
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Findings List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {filteredFindings.length === 0 ? (
              <div style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '60px 24px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                No findings detected in this category.
              </div>
            ) : (
              filteredFindings.map((finding) => {
                const isExpanded = !!expandedFindings[finding.id];
                const styles = getSeverityStyle(finding.severity);

                return (
                  <div
                    key={finding.id}
                    style={{
                      backgroundColor: 'var(--bg-secondary)',
                      border: '1px solid var(--border)',
                      borderRadius: 'var(--radius)',
                      overflow: 'hidden',
                      boxShadow: 'var(--shadow-sm)',
                    }}
                  >
                    {/* Header */}
                    <div
                      onClick={() => toggleExpand(finding.id)}
                      style={{
                        padding: '18px 24px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        cursor: 'pointer',
                        userSelect: 'none',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flex: 1, minWidth: 0 }}>
                        <span
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            padding: '4px 10px',
                            borderRadius: '12px',
                            fontSize: '11px',
                            fontWeight: 700,
                            color: styles.color,
                            backgroundColor: styles.bg,
                            textTransform: 'uppercase',
                            letterSpacing: '0.5px',
                          }}
                        >
                          {finding.severity}
                        </span>
                        <div style={{ minWidth: 0, flex: 1 }}>
                          <h4 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {finding.message}
                          </h4>
                          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                            Module: <strong style={{ textTransform: 'uppercase' }}>{finding.module}</strong>
                          </span>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', color: 'var(--text-secondary)' }}>
                        {finding.filePath && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '13px' }}>
                            <FileCode size={14} />
                            <span>{finding.filePath.split('/').slice(-1)[0]}</span>
                          </div>
                        )}
                        {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                      </div>
                    </div>

                    {/* Details Panel */}
                    {isExpanded && (
                      <div style={{ padding: '24px', borderTop: '1px solid var(--border)', backgroundColor: 'var(--bg-primary)', display: 'flex', flexDirection: 'column', gap: '20px' }}>
                        {/* File Details */}
                        {finding.filePath && (
                          <div>
                            <h5 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '6px' }}>Location</h5>
                            <code style={{ fontSize: '13px', backgroundColor: 'var(--bg-secondary)', padding: '4px 8px', borderRadius: '4px', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
                              {finding.filePath}{finding.lineNumber ? `:${finding.lineNumber}` : ''}
                            </code>
                          </div>
                        )}

                        {/* Evidence */}
                        {finding.evidence && finding.evidence.length > 0 && (
                          <div>
                            <h5 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '8px' }}>Evidence</h5>
                            {finding.evidence.map((ev, idx) => (
                              <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                                <div style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-secondary)' }}>{ev.label}</div>
                                {ev.type === 'snippet' ? (
                                  <pre style={{ margin: 0, padding: '12px', backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '8px', overflowX: 'auto', fontSize: '13px', fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                                    <code>{ev.data}</code>
                                  </pre>
                                ) : (
                                  <div style={{ padding: '8px 12px', backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '8px', fontSize: '13px', color: 'var(--text-primary)' }}>
                                    {ev.data}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        )}

                        {/* Metadata Details */}
                        {finding.metadata && Object.keys(finding.metadata).length > 0 && (
                          <div>
                            <h5 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '8px' }}>Metadata</h5>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                              {Object.entries(finding.metadata).map(([key, val]) => {
                                if (val === null || val === undefined || typeof val === 'object') return null;
                                return (
                                  <div key={key} style={{ backgroundColor: 'var(--bg-secondary)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 500 }}>{key}</div>
                                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '4px', overflowWrap: 'anywhere' }}>{String(val)}</div>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </main>
    </>
  );
}
