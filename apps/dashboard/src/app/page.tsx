'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import Navigation from '@/components/Navigation';
import { Play, Shield, ShieldCheck, ShieldAlert, GitBranch, GitCommit, ArrowRight, RefreshCw, Layers } from 'lucide-react';

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

export default function DashboardHome() {
  const [runs, setRuns] = useState<ScanRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterRepo, setFilterRepo] = useState('');

  const fetchRuns = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/reports');
      const data = await res.json();
      if (data.runs) {
        setRuns(data.runs);
      }
    } catch (err) {
      console.error('Failed to fetch runs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRuns();
  }, []);

  const uniqueRepos = Array.from(new Set(runs.map((r) => r.repo)));
  const filteredRuns = runs.filter((r) => (filterRepo ? r.repo === filterRepo : true));

  const totalRuns = runs.length;
  const passedRuns = runs.filter((r) => r.passed).length;
  const failedRuns = totalRuns - passedRuns;

  const formatDate = (isoStr: string) => {
    const d = new Date(isoStr);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const getModuleBadge = (passed: boolean | undefined) => {
    if (passed === undefined) return <span style={{ color: 'var(--text-secondary)' }}>N/A</span>;
    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '4px',
          padding: '4px 8px',
          borderRadius: '20px',
          fontSize: '12px',
          fontWeight: 600,
          backgroundColor: passed ? 'var(--success-light)' : 'var(--failure-light)',
          color: passed ? 'var(--success)' : 'var(--failure)',
        }}
      >
        {passed ? 'Pass' : 'Fail'}
      </span>
    );
  };

  return (
    <>
      <Navigation />
      <main style={{ padding: '40px 0', flex: 1, transition: 'background-color 0.3s' }}>
        <div className="container" style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h1 style={{ fontSize: '28px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '6px' }}>
                Security Scans
              </h1>
              <p style={{ color: 'var(--text-secondary)', fontSize: '15px' }}>
                Review past scan reports, trends, and app vulnerability findings.
              </p>
            </div>
            <button
              onClick={fetchRuns}
              disabled={loading}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '10px 18px',
                borderRadius: 'var(--radius)',
                border: '1px solid var(--border)',
                backgroundColor: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                fontSize: '14px',
                fontWeight: 600,
              }}
              className="hover-scale"
            >
              <RefreshCw size={16} className={loading ? 'animate-spin' : undefined} />
              <span>Refresh</span>
            </button>
          </div>

          {/* Summary Widgets */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
            {/* Widget 1 */}
            <div
              style={{
                backgroundColor: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: '24px',
                display: 'flex',
                alignItems: 'center',
                gap: '20px',
              }}
              className="hover-scale"
            >
              <div
                style={{
                  backgroundColor: 'var(--accent-light)',
                  color: 'var(--accent)',
                  width: '56px',
                  height: '56px',
                  borderRadius: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Layers size={24} />
              </div>
              <div>
                <div style={{ fontSize: '14px', color: 'var(--text-secondary)', fontWeight: 500 }}>Total Runs</div>
                <div style={{ fontSize: '28px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                  {totalRuns}
                </div>
              </div>
            </div>

            {/* Widget 2 */}
            <div
              style={{
                backgroundColor: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: '24px',
                display: 'flex',
                alignItems: 'center',
                gap: '20px',
              }}
              className="hover-scale"
            >
              <div
                style={{
                  backgroundColor: 'var(--success-light)',
                  color: 'var(--success)',
                  width: '56px',
                  height: '56px',
                  borderRadius: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <ShieldCheck size={24} />
              </div>
              <div>
                <div style={{ fontSize: '14px', color: 'var(--text-secondary)', fontWeight: 500 }}>Passed Runs</div>
                <div style={{ fontSize: '28px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                  {passedRuns}
                </div>
              </div>
            </div>

            {/* Widget 3 */}
            <div
              style={{
                backgroundColor: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: '24px',
                display: 'flex',
                alignItems: 'center',
                gap: '20px',
              }}
              className="hover-scale"
            >
              <div
                style={{
                  backgroundColor: 'var(--failure-light)',
                  color: 'var(--failure)',
                  width: '56px',
                  height: '56px',
                  borderRadius: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <ShieldAlert size={24} />
              </div>
              <div>
                <div style={{ fontSize: '14px', color: 'var(--text-secondary)', fontWeight: 500 }}>Failed Runs</div>
                <div style={{ fontSize: '28px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                  {failedRuns}
                </div>
              </div>
            </div>
          </div>

          {/* Filter Tools */}
          <div
            style={{
              backgroundColor: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: '16px 24px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '16px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-secondary)' }}>Filter Repo:</span>
              <select
                value={filterRepo}
                onChange={(e) => setFilterRepo(e.target.value)}
                style={{
                  padding: '8px 12px',
                  borderRadius: '8px',
                  border: '1px solid var(--border)',
                  backgroundColor: 'var(--bg-primary)',
                  color: 'var(--text-primary)',
                  fontSize: '14px',
                  outline: 'none',
                }}
              >
                <option value="">All Repositories</option>
                {uniqueRepos.map((repo) => (
                  <option key={repo} value={repo}>
                    {repo.split('/').slice(-1)[0]}
                  </option>
                ))}
              </select>
            </div>
            <div style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
              Showing {filteredRuns.length} of {totalRuns} runs
            </div>
          </div>

          {/* Table list */}
          <div
            style={{
              backgroundColor: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              boxShadow: 'var(--shadow-sm)',
              overflow: 'hidden',
            }}
          >
            {loading ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '80px', color: 'var(--text-secondary)' }}>
                Loading scan runs...
              </div>
            ) : filteredRuns.length === 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '80px 24px', textAlign: 'center' }}>
                <Shield size={48} style={{ color: 'var(--text-secondary)', marginBottom: '16px' }} />
                <h3 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>No scan runs found</h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginTop: '8px', maxWidth: '320px' }}>
                  Run GuardGate from CLI or set up GitHub Actions integration to populate the dashboard.
                </p>
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)', backgroundColor: 'var(--bg-primary)' }}>
                      <th style={{ padding: '16px 24px', fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>Repository</th>
                      <th style={{ padding: '16px 24px', fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>Commit</th>
                      <th style={{ padding: '16px 24px', fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>Date</th>
                      <th style={{ padding: '16px 24px', fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>Secrets</th>
                      <th style={{ padding: '16px 24px', fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>SBOM</th>
                      <th style={{ padding: '16px 24px', fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>E2E</th>
                      <th style={{ padding: '16px 24px', fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>Overall</th>
                      <th style={{ padding: '16px 24px', fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredRuns.map((run) => (
                      <tr
                        key={run.id}
                        style={{ borderBottom: '1px solid var(--border)', transition: 'background-color 0.2s' }}
                        className="hover-bg-primary"
                      >
                        {/* Repository name */}
                        <td style={{ padding: '20px 24px' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            <span style={{ fontWeight: 600, fontSize: '14px', color: 'var(--text-primary)' }}>
                              {run.repo.split('/').slice(-1)[0]}
                            </span>
                            <span style={{ fontSize: '12px', color: 'var(--text-secondary)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {run.repo}
                            </span>
                          </div>
                        </td>

                        {/* Commit metadata */}
                        <td style={{ padding: '20px 24px' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', color: 'var(--text-primary)' }}>
                              <GitBranch size={14} style={{ color: 'var(--text-secondary)' }} />
                              <span style={{ fontWeight: 500 }}>{run.branch}</span>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                              <GitCommit size={14} />
                              <span style={{ fontFamily: 'monospace' }}>{run.commitSha.substring(0, 7)}</span>
                            </div>
                          </div>
                        </td>

                        {/* Scanned date */}
                        <td style={{ padding: '20px 24px', fontSize: '14px', color: 'var(--text-secondary)' }}>
                          {formatDate(run.scannedAt)}
                        </td>

                        {/* Secrets module status */}
                        <td style={{ padding: '20px 24px' }}>
                          {getModuleBadge(run.summary.moduleStatus?.secrets)}
                        </td>

                        {/* SBOM module status */}
                        <td style={{ padding: '20px 24px' }}>
                          {getModuleBadge(run.summary.moduleStatus?.sbom)}
                        </td>

                        {/* E2E module status */}
                        <td style={{ padding: '20px 24px' }}>
                          {getModuleBadge(run.summary.moduleStatus?.e2e)}
                        </td>

                        {/* Overall status */}
                        <td style={{ padding: '20px 24px' }}>
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '6px',
                              padding: '6px 12px',
                              borderRadius: 'var(--radius)',
                              fontSize: '13px',
                              fontWeight: 700,
                              backgroundColor: run.passed ? 'var(--success-light)' : 'var(--failure-light)',
                              color: run.passed ? 'var(--success)' : 'var(--failure)',
                            }}
                          >
                            {run.passed ? 'PASSED' : 'FAILED'}
                          </span>
                        </td>

                        {/* Action link */}
                        <td style={{ padding: '20px 24px', textAlign: 'right' }}>
                          <Link
                            href={`/runs/${run.id}`}
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '6px',
                              fontSize: '14px',
                              fontWeight: 600,
                              color: 'var(--accent)',
                            }}
                            className="hover-scale"
                          >
                            <span>Details</span>
                            <ArrowRight size={16} />
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </main>
    </>
  );
}
