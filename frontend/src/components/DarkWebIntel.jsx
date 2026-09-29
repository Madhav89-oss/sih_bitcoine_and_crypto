import React, { useState, useEffect } from 'react';
import { Globe, ShieldAlert, ExternalLink, Terminal, ShieldCheck } from 'lucide-react';

export default function DarkWebIntel({ onSelectWallet }) {
  const [intel, setIntel] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/intel')
      .then(res => res.json())
      .then(d => {
        setIntel(d.feeds || []);
        setLoading(false);
      })
      .catch(err => {
        console.error("Failed to load intel:", err);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div style={{ color: '#94a3b8', padding: '40px 0', textAlign: 'center' }}>Connecting to Tor Onion Daemon...</div>;
  }

  return (
    <div className="glass-panel" style={{ padding: '24px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 20 }}>🧅</span>
            <h3 style={{ fontSize: 18, fontWeight: 700, color: '#f8fafc' }}>
              Dark Web Onion Intelligence Feeds & Ransomware Negotiation Seeds
            </h3>
          </div>
          <p style={{ fontSize: 13, color: '#94a3b8', marginTop: 4 }}>
            Monitored in real-time via Tor hidden service crawler endpoints and OFAC sanctions attribution feeds.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.3)', padding: '6px 12px', borderRadius: 8 }}>
          <span className="pulse-dot"></span>
          <span style={{ fontSize: 12, fontWeight: 700, color: '#34d399' }}>25 SEEDS CRAWLING</span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 16 }}>
        {intel.map((feed, idx) => (
          <div 
            key={idx} 
            className="glass-panel" 
            style={{ 
              padding: '16px 18px', 
              borderLeft: `3px solid ${feed.threat_level === 'CRITICAL' ? '#ef4444' : '#f59e0b'}`,
              background: 'rgba(11, 17, 32, 0.7)'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
              <div>
                <span className="badge" style={{ background: 'rgba(217,70,239,0.15)', color: '#d946ef', borderColor: 'rgba(217,70,239,0.3)' }}>
                  {feed.category ? feed.category.toUpperCase() : 'DARKNET'}
                </span>
                <div style={{ fontSize: 15, fontWeight: 700, color: '#f8fafc', marginTop: 4 }}>
                  {feed.target_entity}
                </div>
              </div>
              <span className={`badge badge-${String(feed.threat_level).toLowerCase()}`}>
                {feed.threat_level}
              </span>
            </div>

            <div style={{ fontSize: 12, color: '#cbd5e1', marginBottom: 12, lineHeight: 1.5 }}>
              {feed.intel_summary}
            </div>

            <div style={{ background: 'rgba(6,9,19,0.8)', padding: '8px 10px', borderRadius: 6, marginBottom: 12, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
              <div style={{ color: '#94a3b8', marginBottom: 2 }}>Tor Onion Endpoint:</div>
              <div style={{ color: '#d946ef', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {feed.onion_url}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: 11, color: '#64748b' }}>
                Credibility: <strong style={{ color: '#38bdf8' }}>{feed.source_credibility || 'HIGH'}</strong>
              </div>
              <button
                onClick={() => onSelectWallet && onSelectWallet(feed.bitcoin_address)}
                className="cyber-btn cyber-btn-primary"
                style={{ padding: '4px 10px', fontSize: 11 }}
              >
                🕸️ Trace Seed Wallet
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
