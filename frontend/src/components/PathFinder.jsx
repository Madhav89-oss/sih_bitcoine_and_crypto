import React, { useState, useEffect } from 'react';
import { Compass, Zap, ArrowRight, ShieldCheck, AlertCircle, CheckCircle2 } from 'lucide-react';

export default function PathFinder({ onHopToNode }) {
  const [wallets, setWallets] = useState({ sources: [], targets: [] });
  const [selectedSource, setSelectedSource] = useState('');
  const [selectedTarget, setSelectedTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch('/api/graph/wallets')
      .then(res => res.json())
      .then(data => {
        setWallets(data);
        if (data.sources.length > 0) setSelectedSource(data.sources[0].address);
        if (data.targets.length > 0) setSelectedTarget(data.targets[0].address);
      })
      .catch(err => console.error("Failed to load pathfinder wallets:", err));
  }, []);

  const handleFindTrail = async () => {
    if (!selectedSource || !selectedTarget) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/graph/path?source=${encodeURIComponent(selectedSource)}&target=${encodeURIComponent(selectedTarget)}`);
      const data = await res.json();
      if (res.ok && data.success) {
        setResult(data);
      } else {
        setError(data.message || data.detail || "No direct on-chain path found in the loaded graph component.");
        setResult(null);
      }
    } catch (err) {
      setError("Pathfinding request failed. Please check network connectivity.");
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '20px 24px', marginTop: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
        <Compass className="text-cyan-400" size={20} color="#38bdf8" />
        <h3 style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc', letterSpacing: '-0.01em' }}>
          Money Trail & Cash-Out Path Finder
        </h3>
      </div>
      <p style={{ fontSize: 13, color: '#94a3b8', marginBottom: 16 }}>
        Identify algorithmic shortest-path laundering trajectories connecting suspect threat actor clusters to cash-out exchanges and tumblers.
      </p>

      {/* Selectors and Action */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr)) 140px', gap: 16, alignItems: 'flex-end' }}>
        {/* Source Wallet */}
        <div>
          <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#94a3b8', marginBottom: 6 }}>
            Suspect Source Wallet:
          </label>
          <select
            value={selectedSource}
            onChange={e => setSelectedSource(e.target.value)}
            className="cyber-input"
            style={{ width: '100%' }}
          >
            {wallets.sources.map((s, idx) => (
              <option key={idx} value={s.address}>
                {s.label}
              </option>
            ))}
          </select>
        </div>

        {/* Target Cash-Out */}
        <div>
          <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#94a3b8', marginBottom: 6 }}>
            Target Cash-Out / Mixer Wallet:
          </label>
          <select
            value={selectedTarget}
            onChange={e => setSelectedTarget(e.target.value)}
            className="cyber-input"
            style={{ width: '100%' }}
          >
            {wallets.targets.map((t, idx) => (
              <option key={idx} value={t.address}>
                {t.label}
              </option>
            ))}
          </select>
        </div>

        {/* Submit Button */}
        <div>
          <button
            onClick={handleFindTrail}
            disabled={loading}
            className="cyber-btn cyber-btn-primary"
            style={{ width: '100%', height: 38 }}
          >
            <Zap size={15} /> {loading ? "Tracing..." : "Find Trail"}
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div style={{
          marginTop: 16,
          padding: '12px 16px',
          background: 'rgba(239, 68, 68, 0.12)',
          border: '1px solid rgba(239, 68, 68, 0.35)',
          borderRadius: 8,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          color: '#f87171',
          fontSize: 13
        }}>
          <AlertCircle size={18} />
          {error}
        </div>
      )}

      {/* Discovered Path Card */}
      {result && (
        <div style={{
          marginTop: 20,
          background: 'rgba(11, 17, 32, 0.75)',
          border: '1px solid rgba(56, 189, 248, 0.35)',
          borderRadius: 10,
          padding: '16px 20px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#38bdf8', fontWeight: 700, fontSize: 14 }}>
              <CheckCircle2 size={18} color="#34d399" />
              Direct Laundering Money Trail Found ({result.hops} Hops)
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                onClick={() => onHopToNode && onHopToNode(result.source)}
                className="cyber-btn"
                style={{ padding: '4px 10px', fontSize: 12 }}
              >
                Focus Source
              </button>
              <button
                onClick={() => onHopToNode && onHopToNode(result.target)}
                className="cyber-btn"
                style={{ padding: '4px 10px', fontSize: 12 }}
              >
                Focus Target
              </button>
            </div>
          </div>

          {/* Hop Steps Horizontal Scroller */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, overflowX: 'auto', paddingBottom: 6 }}>
            {result.steps.map((step, idx) => (
              <React.Fragment key={idx}>
                <div 
                  onClick={() => onHopToNode && onHopToNode(step.id)}
                  style={{
                    background: 'rgba(30, 41, 59, 0.6)',
                    border: '1px solid rgba(51, 65, 85, 0.6)',
                    borderRadius: 8,
                    padding: '8px 12px',
                    minWidth: 140,
                    cursor: 'pointer',
                    transition: 'all 0.2s ease'
                  }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = '#38bdf8'}
                  onMouseLeave={e => e.currentTarget.style.borderColor = 'rgba(51, 65, 85, 0.6)'}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, fontWeight: 700, color: '#64748b', marginBottom: 2 }}>
                    <span>STEP {step.step + 1}</span>
                    <span style={{ color: step.color }}>{String(step.category).toUpperCase()}</span>
                  </div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: '#f8fafc', whiteSpace: 'nowrap' }}>
                    {step.label}
                  </div>
                </div>

                {idx < result.steps.length - 1 && (
                  <ArrowRight size={14} color="#64748b" style={{ flexShrink: 0 }} />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
