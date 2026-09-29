import React, { useState, useEffect } from 'react';
import { ShieldAlert, Target, Globe, Network, Zap, ArrowUpRight, Search, Filter } from 'lucide-react';

export default function OverviewMetrics({ onTraceTx }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    fetch('/api/overview')
      .then(res => res.json())
      .then(d => {
        setData(d);
        setLoading(false);
      })
      .catch(err => {
        console.error("Failed to load overview data:", err);
        setLoading(false);
      });
  }, []);

  if (loading || !data) {
    return (
      <div style={{ padding: '40px 0', textAlign: 'center', color: '#94a3b8' }}>
        Loading SOC Ingestion Telemetry...
      </div>
    );
  }

  const { metrics, threat_distribution, recent_alerts } = data;

  const filteredAlerts = recent_alerts.filter(a => 
    a.txid.toLowerCase().includes(searchQuery.toLowerCase()) ||
    a.attributed_entity.toLowerCase().includes(searchQuery.toLowerCase()) ||
    a.src_ip.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div>
      {/* 5 Headline KPI Cards */}
      <div className="kpi-grid">
        {/* Card 1: Total Alerts */}
        <div className="glass-panel kpi-card" style={{ color: '#f43f5e' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ 
                width: 32, 
                height: 32, 
                borderRadius: 8, 
                background: 'rgba(244,63,94,0.15)', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                fontSize: 16 
              }}>
                🚨
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', color: '#cbd5e1' }}>
                TOTAL ALERTS FLAGGED
              </span>
            </div>
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            {metrics.total_alerts.toLocaleString()}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6, fontSize: 12 }}>
            <span style={{ color: '#f43f5e', fontWeight: 600 }}>+14.2%</span>
            <span style={{ color: '#64748b' }}>last 24h</span>
          </div>
        </div>

        {/* Card 2: Known Threats */}
        <div className="glass-panel kpi-card" style={{ color: '#f59e0b' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ 
                width: 32, 
                height: 32, 
                borderRadius: 8, 
                background: 'rgba(245,158,11,0.15)', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                fontSize: 16 
              }}>
                🎯
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', color: '#cbd5e1' }}>
                KNOWN THREATS
              </span>
            </div>
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            35,977
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6, fontSize: 12 }}>
            <span style={{ color: '#fbbf24', fontWeight: 600 }}>3.6% conv rate</span>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#fbbf24' }}></span>
          </div>
        </div>

        {/* Card 3: Onion Intel Seeds */}
        <div className="glass-panel kpi-card" style={{ color: '#06b6d4' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ 
                width: 32, 
                height: 32, 
                borderRadius: 8, 
                background: 'rgba(6,182,212,0.15)', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                fontSize: 16 
              }}>
                🧅
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', color: '#cbd5e1' }}>
                ONION INTEL SEEDS
              </span>
            </div>
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            {metrics.onion_seeds}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6, fontSize: 12 }}>
            <span className="pulse-dot"></span>
            <span style={{ color: '#34d399', fontWeight: 600 }}>Crawler Active</span>
          </div>
        </div>

        {/* Card 4: Graph Nodes */}
        <div className="glass-panel kpi-card" style={{ color: '#8b5cf6' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ 
                width: 32, 
                height: 32, 
                borderRadius: 8, 
                background: 'rgba(139,92,246,0.15)', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                fontSize: 16 
              }}>
                🕸️
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', color: '#cbd5e1' }}>
                ENTITY GRAPH NODES
              </span>
            </div>
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            {metrics.graph_nodes.toLocaleString()}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6, fontSize: 12 }}>
            <span style={{ color: '#94a3b8' }}>14 clusters mapped</span>
          </div>
        </div>

        {/* Card 5: Max Suspicion Score */}
        <div className="glass-panel kpi-card" style={{ color: '#ef4444' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ 
                width: 32, 
                height: 32, 
                borderRadius: 8, 
                background: 'rgba(239,68,68,0.15)', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                fontSize: 16 
              }}>
                ⚡
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', color: '#cbd5e1' }}>
                MAX SUSPICION SCORE
              </span>
            </div>
            <span className="badge badge-critical">CRITICAL</span>
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, color: '#fb7185', fontFamily: 'var(--font-mono)' }}>
            100.0
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6, fontSize: 12 }}>
            <span style={{ color: 'rgba(251,113,133,0.9)', fontFamily: 'var(--font-mono)' }}>
              Anomaly Threshold 100/100
            </span>
          </div>
        </div>
      </div>

      {/* Threat Level Distribution Chips */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', 
        gap: 12, 
        marginBottom: 24 
      }}>
        <div className="glass-panel" style={{ padding: '12px 16px', borderLeft: '3px solid #ef4444' }}>
          <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600 }}>CRITICAL SEVERITY</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: '#f87171', fontFamily: 'var(--font-mono)' }}>
            {threat_distribution.CRITICAL.toLocaleString()}
          </div>
        </div>
        <div className="glass-panel" style={{ padding: '12px 16px', borderLeft: '3px solid #f59e0b' }}>
          <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600 }}>HIGH RISK</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: '#fbbf24', fontFamily: 'var(--font-mono)' }}>
            {threat_distribution.HIGH.toLocaleString()}
          </div>
        </div>
        <div className="glass-panel" style={{ padding: '12px 16px', borderLeft: '3px solid #38bdf8' }}>
          <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600 }}>MEDIUM ANOMALY</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>
            {threat_distribution.MEDIUM.toLocaleString()}
          </div>
        </div>
        <div className="glass-panel" style={{ padding: '12px 16px', borderLeft: '3px solid #94a3b8' }}>
          <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600 }}>MONITORED BASELINE</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            {threat_distribution.LOW.toLocaleString()}
          </div>
        </div>
      </div>

      {/* Recent Alerts Table */}
      <div className="glass-panel" style={{ padding: '20px 24px' }}>
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          marginBottom: 16,
          flexWrap: 'wrap',
          gap: 12
        }}>
          <div>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc' }}>
              🚨 Real-Time Ingestion & Anomaly Telemetry
            </h3>
            <p style={{ fontSize: 12, color: '#94a3b8' }}>
              Evaluated via Isolation Forest pipeline against 1,000,000 on-chain Bitcoin transactions.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ position: 'relative' }}>
              <Search size={14} color="#64748b" style={{ position: 'absolute', left: 10, top: 11 }} />
              <input
                type="text"
                placeholder="Search TXID, entity, or IP..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="cyber-input"
                style={{ paddingLeft: 30, width: 240 }}
              />
            </div>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(51,65,85,0.6)', color: '#94a3b8', textAlign: 'left' }}>
                <th style={{ padding: '10px 12px' }}>TRANSACTION HASH</th>
                <th style={{ padding: '10px 12px' }}>THREAT LEVEL</th>
                <th style={{ padding: '10px 12px' }}>ANOMALY SCORE</th>
                <th style={{ padding: '10px 12px' }}>ENTITY ATTRIBUTION</th>
                <th style={{ padding: '10px 12px' }}>VALUE (BTC)</th>
                <th style={{ padding: '10px 12px' }}>BROADCAST IP</th>
                <th style={{ padding: '10px 12px', textAlign: 'right' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((alert, i) => (
                <tr 
                  key={i}
                  style={{ 
                    borderBottom: '1px solid rgba(51,65,85,0.3)',
                    transition: 'background 0.15s ease'
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(30,41,59,0.4)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>
                    {alert.txid.slice(0, 14)}…
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <span className={`badge badge-${alert.threat_level.toLowerCase()}`}>
                      {alert.threat_level}
                    </span>
                  </td>
                  <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                    {alert.suspicion_score.toFixed(1)} / 100
                  </td>
                  <td style={{ padding: '10px 12px', color: '#cbd5e1' }}>
                    {alert.attributed_entity}
                  </td>
                  <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)' }}>
                    {alert.total_in.toFixed(4)} BTC
                  </td>
                  <td style={{ padding: '10px 12px', color: '#10b981', fontFamily: 'var(--font-mono)' }}>
                    {alert.src_ip}
                  </td>
                  <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                    <button
                      onClick={() => onTraceTx && onTraceTx(alert.txid)}
                      className="cyber-btn cyber-btn-primary"
                      style={{ padding: '4px 10px', fontSize: 11 }}
                    >
                      🕸️ Trace in Graph
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
