import React, { useState, useEffect } from 'react';
import { Search, Loader2, ShieldCheck, ExternalLink, Activity, Network } from 'lucide-react';
import './index.css';

// Polling bounds for the job-status loop: stop after ~3 minutes or after
// several consecutive network/HTTP failures, then surface a message instead
// of polling forever against a stuck job.
const POLL_INTERVAL_MS = 2000;
const MAX_POLL_ATTEMPTS = 90;
const MAX_CONSECUTIVE_POLL_FAILURES = 5;

// Mock types
type ScanStatus = 'idle' | 'pending' | 'running' | 'completed' | 'failed';

// Empty base = same-origin: the Vite dev server proxies /api to the backend.
// Override with VITE_API_BASE_URL for production or a remote backend.
const API_BASE = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/+$/, '');

interface Finding {
  id: string;
  module: string;
  title: string;
  description: string;
  raw_data: Record<string, unknown>;
}

interface ScanResult {
  target: string;
  finding_count: number;
  findings: Finding[];
}

/** Allow only absolute http(s) links coming from finding raw_data. */
function isSafeHttpUrl(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function App() {
  const [target, setTarget] = useState('');
  const [status, setStatus] = useState<ScanStatus>('idle');
  const [jobId, setJobId] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const startScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setStatus('pending');
    setResult(null);
    setJobId(null);
    setErrorMessage(null);

    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, fast: true, max_iterations: 3 })
      });
      const data = await res.json();
      if (!res.ok || !data.job_id) {
        throw new Error(typeof data.detail === 'string' ? data.detail : 'Scan request failed');
      }
      setJobId(data.job_id);
      setStatus('running');
    } catch (err) {
      console.error(err);
      setStatus('failed');
      setErrorMessage(err instanceof Error ? err.message : 'Scan request failed');
    }
  };

  useEffect(() => {
    if (status !== 'running' || !jobId) return;

    let attempts = 0;
    let consecutiveFailures = 0;
    let stopped = false;
    let timeout: number | undefined;

    const poll = async () => {
      if (stopped) return;
      attempts += 1;
      try {
        const res = await fetch(`${API_BASE}/api/scan/${jobId}`);
        if (!res.ok) {
          throw new Error(`Poll failed: ${res.status}`);
        }
        const data = await res.json();
        consecutiveFailures = 0;

        if (data.status === 'completed') {
          stopped = true;
          setStatus('completed');
          setResult(data.result);
          return;
        }
        if (data.status === 'failed') {
          stopped = true;
          setStatus('failed');
          setErrorMessage(
            typeof data.error === 'string' ? data.error : 'Backend reported a scan failure'
          );
          return;
        }
      } catch (err) {
        // Transient network/HTTP errors are retried, up to a bound.
        consecutiveFailures += 1;
        console.error(err);
      }

      if (stopped) return;
      if (consecutiveFailures >= MAX_CONSECUTIVE_POLL_FAILURES) {
        stopped = true;
        setStatus('failed');
        setErrorMessage(
          'Lost connection to the backend while polling. The scan may still be running on the server.'
        );
        return;
      }
      if (attempts >= MAX_POLL_ATTEMPTS) {
        stopped = true;
        setStatus('failed');
        setErrorMessage(
          'Scan is taking too long; the job may be stuck. Please try scanning again.'
        );
        return;
      }
      timeout = window.setTimeout(poll, POLL_INTERVAL_MS);
    };

    timeout = window.setTimeout(poll, POLL_INTERVAL_MS);
    return () => {
      stopped = true;
      clearTimeout(timeout);
    };
  }, [status, jobId]);

  return (
    <div className="app-container">
      {/* Hero Section */}
      <header className={`hero-section ${status !== 'idle' ? 'compact' : ''}`}>
        <h1 className="hero-title">ZKIT Engine</h1>
        <p className="hero-subtitle">Advanced Identity Correlation & OSINT Platform</p>
      </header>

      {/* Search Bar */}
      <div className="search-container">
        <form onSubmit={startScan} className="search-box glass-panel">
          <input
            type="text"
            className="glass-input"
            placeholder="Enter name, username, email, or domain..."
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={status === 'running' || status === 'pending'}
          />
          <button
            type="submit"
            className="glass-button"
            disabled={status === 'running' || status === 'pending'}
          >
            {status === 'running' || status === 'pending' ? (
              <Loader2 className="spinner" size={20} />
            ) : (
              <Search size={20} />
            )}
            <span>Scan</span>
          </button>
        </form>
      </div>

      {/* Status indicator */}
      {status === 'running' && (
        <div className="flex-center" style={{ gap: '12px', marginTop: '40px' }}>
          <Activity className="text-gradient pulse" size={32} />
          <h3 className="text-muted">Correlating identity data...</h3>
        </div>
      )}

      {/* Results Dashboard */}
      {status === 'completed' && result && (
        <main className="dashboard-grid">
          {/* Left Column: Stats & Graph */}
          <div className="dashboard-col" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

            <div className="dashboard-card glass-panel">
              <div className="card-header">
                <h3 className="card-title">
                  <ShieldCheck size={20} className="text-gradient" />
                  Identity Dossier
                </h3>
              </div>
              <div style={{ padding: '8px 0' }}>
                <p><strong>Target:</strong> {result.target}</p>
                <p><strong>Total Findings:</strong> {result.finding_count}</p>
              </div>
            </div>

            <div className="dashboard-card glass-panel" style={{ flex: 1 }}>
              <div className="card-header">
                <h3 className="card-title">
                  <Network size={20} className="text-gradient" />
                  ZKIT Identity Graph
                </h3>
              </div>
              <div className="graph-container">
                <p className="text-muted" style={{ zIndex: 2 }}>Interactive Graph Coming Soon</p>
                {/* Visual background placeholder for graph */}
                <div style={{ position: 'absolute', opacity: 0.1 }}>
                   <Network size={200} />
                </div>
              </div>
            </div>

          </div>

          {/* Right Column: Findings Timeline */}
          <div className="dashboard-card glass-panel">
            <div className="card-header">
              <h3 className="card-title">OSINT Findings</h3>
              <span className="badge badge-info">{result.findings.length} Discovered</span>
            </div>

            <div className="findings-list">
              {result.findings.map((f, i) => {
                const raw = f.raw_data ?? {};
                const verified = raw.verified === true;
                const sourceUrl =
                  typeof raw.url === 'string' && isSafeHttpUrl(raw.url) ? raw.url : null;
                return (
                  <div key={f.id || `${f.module}-${i}`} className="finding-item">
                    <div className="finding-header">
                      <span className="finding-title">{f.title}</span>
                      {verified && (
                        <span className="badge badge-success">Verified</span>
                      )}
                    </div>
                    <div className="finding-module">{f.module.toUpperCase()}</div>
                    {f.description && <p className="finding-desc">{f.description}</p>}

                    {sourceUrl && (
                      <a href={sourceUrl} target="_blank" rel="noopener noreferrer" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '0.85rem', color: 'var(--accent-primary)', textDecoration: 'none', marginTop: '4px' }}>
                        <ExternalLink size={14} /> Open Link
                      </a>
                    )}
                  </div>
                );
              })}
              {result.findings.length === 0 && (
                <p className="text-muted text-center" style={{ padding: '40px 0' }}>No findings discovered.</p>
              )}
            </div>
          </div>
        </main>
      )}

      {status === 'failed' && (
        <div className="dashboard-card glass-panel" style={{ borderColor: 'var(--danger)', textAlign: 'center', padding: '40px' }}>
          <h3 style={{ color: 'var(--danger)', marginBottom: '8px' }}>Scan Failed</h3>
          {errorMessage ? (
            <p className="text-muted">{errorMessage}</p>
          ) : (
            <p className="text-muted">An error occurred while processing the deep scan. Check backend logs.</p>
          )}
        </div>
      )}

    </div>
  );
}

export default App;
