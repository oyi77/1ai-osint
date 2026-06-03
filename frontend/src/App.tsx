import React, { useState, useEffect } from 'react';
import { Search, Loader2, ShieldCheck, ExternalLink, Activity, Network } from 'lucide-react';
import './index.css';

// Mock types
type ScanStatus = 'idle' | 'pending' | 'running' | 'completed' | 'failed';

interface Finding {
  id: string;
  module: string;
  title: string;
  description: string;
  raw_data: any;
}

interface ScanResult {
  target: string;
  finding_count: number;
  findings: Finding[];
}

function App() {
  const [target, setTarget] = useState('');
  const [status, setStatus] = useState<ScanStatus>('idle');
  const [jobId, setJobId] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  const startScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setStatus('pending');
    setResult(null);

    try {
      const res = await fetch('http://127.0.0.1:8000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, fast: true, max_iterations: 3 })
      });
      const data = await res.json();
      setJobId(data.job_id);
      setStatus('running');
    } catch (err) {
      console.error(err);
      setStatus('failed');
    }
  };

  useEffect(() => {
    let interval: number;
    
    if (status === 'running' && jobId) {
      interval = setInterval(async () => {
        try {
          const res = await fetch(`http://127.0.0.1:8000/api/scan/${jobId}`);
          const data = await res.json();
          
          if (data.status === 'completed') {
            setStatus('completed');
            setResult(data.result);
            clearInterval(interval);
          } else if (data.status === 'failed') {
            setStatus('failed');
            clearInterval(interval);
          }
        } catch (err) {
          console.error(err);
        }
      }, 2000) as unknown as number;
    }

    return () => clearInterval(interval);
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
              {result.findings.map((f, i) => (
                <div key={i} className="finding-item">
                  <div className="finding-header">
                    <span className="finding-title">{f.title}</span>
                    {f.raw_data?.verified && (
                      <span className="badge badge-success">Verified</span>
                    )}
                  </div>
                  <div className="finding-module">{f.module.toUpperCase()}</div>
                  {f.description && <p className="finding-desc">{f.description}</p>}
                  
                  {f.raw_data?.url && (
                    <a href={f.raw_data.url} target="_blank" rel="noopener noreferrer" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '0.85rem', color: 'var(--accent-primary)', textDecoration: 'none', marginTop: '4px' }}>
                      <ExternalLink size={14} /> Open Link
                    </a>
                  )}
                </div>
              ))}
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
          <p className="text-muted">An error occurred while processing the deep scan. Check backend logs.</p>
        </div>
      )}

    </div>
  );
}

export default App;
