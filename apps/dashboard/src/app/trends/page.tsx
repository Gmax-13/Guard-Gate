'use client';

import { useState, useEffect } from 'react';
import Navigation from '@/components/Navigation';
import { TrendingUp, ShieldCheck, ShieldAlert, Calendar, BarChart2 } from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Legend,
} from 'recharts';

interface RunItem {
  id: string;
  repo: string;
  scannedAt: string;
  passed: boolean;
}

export default function TrendsPage() {
  const [runs, setRuns] = useState<RunItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedRepo, setSelectedRepo] = useState('');
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const fetchTrends = async () => {
      try {
        const res = await fetch('/api/trends');
        const data = await res.json();
        if (data.runs) {
          setRuns(data.runs);
        }
      } catch (err) {
        console.error('Failed to fetch trends:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchTrends();
  }, []);

  const uniqueRepos = Array.from(new Set(runs.map((r) => r.repo)));
  const filteredRuns = runs.filter((r) => !selectedRepo || r.repo === selectedRepo);

  // Group and format data for Recharts
  // Let's group runs by day (last 7 days of scans)
  const getChartData = () => {
    const sorted = [...filteredRuns].sort(
      (a, b) => new Date(a.scannedAt).getTime() - new Date(b.scannedAt).getTime()
    );

    // Group by date
    const groups: Record<string, { date: string; passed: number; failed: number }> = {};

    sorted.forEach((run) => {
      const dateStr = new Date(run.scannedAt).toLocaleDateString([], {
        month: 'short',
        day: 'numeric',
      });
      if (!groups[dateStr]) {
        groups[dateStr] = { date: dateStr, passed: 0, failed: 0 };
      }
      if (run.passed) {
        groups[dateStr].passed += 1;
      } else {
        groups[dateStr].failed += 1;
      }
    });

    return Object.values(groups);
  };

  const chartData = getChartData();

  // Metrics
  const passedCount = filteredRuns.filter((r) => r.passed).length;
  const failedCount = filteredRuns.length - passedCount;
  const passRate = filteredRuns.length > 0 ? Math.round((passedCount / filteredRuns.length) * 100) : 0;

  return (
    <>
      <Navigation />
      <main style={{ padding: '40px 0', flex: 1 }}>
        <div className="container" style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
            <div>
              <h1 style={{ fontSize: '28px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '6px' }}>
                Scan Trends & Analytics
              </h1>
              <p style={{ color: 'var(--text-secondary)', fontSize: '15px' }}>
                Monitor build pass/fail rates and vulnerability frequency over time.
              </p>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-secondary)' }}>Select Repository:</span>
              <select
                value={selectedRepo}
                onChange={(e) => setSelectedRepo(e.target.value)}
                style={{
                  padding: '8px 12px',
                  borderRadius: '8px',
                  border: '1px solid var(--border)',
                  backgroundColor: 'var(--bg-secondary)',
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
          </div>

          {loading ? (
            <div style={{ padding: '80px 0', textAlign: 'center', color: 'var(--text-secondary)' }}>
              Loading trend data...
            </div>
          ) : runs.length === 0 ? (
            <div style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '80px 24px', textAlign: 'center', color: 'var(--text-secondary)' }}>
              No scan run history found to plot trends.
            </div>
          ) : (
            <>
              {/* Micro-Metrics Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px' }}>
                <div style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '20px 24px', display: 'flex', gap: '16px', alignItems: 'center' }}>
                  <div style={{ color: 'var(--success)', backgroundColor: 'var(--success-light)', padding: '10px', borderRadius: '8px' }}>
                    <ShieldCheck size={20} />
                  </div>
                  <div>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 600, textTransform: 'uppercase' }}>Passed Runs</div>
                    <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>{passedCount}</div>
                  </div>
                </div>

                <div style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '20px 24px', display: 'flex', gap: '16px', alignItems: 'center' }}>
                  <div style={{ color: 'var(--failure)', backgroundColor: 'var(--failure-light)', padding: '10px', borderRadius: '8px' }}>
                    <ShieldAlert size={20} />
                  </div>
                  <div>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 600, textTransform: 'uppercase' }}>Failed Runs</div>
                    <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>{failedCount}</div>
                  </div>
                </div>

                <div style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '20px 24px', display: 'flex', gap: '16px', alignItems: 'center' }}>
                  <div style={{ color: 'var(--accent)', backgroundColor: 'var(--accent-light)', padding: '10px', borderRadius: '8px' }}>
                    <TrendingUp size={20} />
                  </div>
                  <div>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 600, textTransform: 'uppercase' }}>Pass Success Rate</div>
                    <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>{passRate}%</div>
                  </div>
                </div>
              </div>

              {/* Chart Block */}
              <div
                style={{
                  backgroundColor: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: '28px',
                  boxShadow: 'var(--shadow-sm)',
                }}
              >
                <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <BarChart2 size={18} style={{ color: 'var(--accent)' }} />
                  <span>Scan Run History (Grouped by Day)</span>
                </h3>

                <div style={{ width: '100%', height: '360px' }}>
                  {mounted && chartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                        <XAxis dataKey="date" stroke="var(--text-secondary)" fontSize={12} tickLine={false} />
                        <YAxis stroke="var(--text-secondary)" fontSize={12} tickLine={false} allowDecimals={false} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: 'var(--bg-secondary)',
                            borderColor: 'var(--border)',
                            borderRadius: '8px',
                            color: 'var(--text-primary)',
                          }}
                        />
                        <Legend verticalAlign="top" height={36} />
                        <Bar name="Passed" dataKey="passed" fill="var(--success)" radius={[4, 4, 0, 0]} />
                        <Bar name="Failed" dataKey="failed" fill="var(--critical)" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
                      No chart data available.
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      </main>
    </>
  );
}
