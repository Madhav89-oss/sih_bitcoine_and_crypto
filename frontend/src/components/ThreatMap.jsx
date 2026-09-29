import React, { useState, useEffect, useRef } from 'react';
import { MapContainer, TileLayer, CircleMarker, Polyline, Popup, useMap } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import { Shield, Globe, Wifi, AlertTriangle, Target, Radio } from 'lucide-react';

// ─── animated pulsing marker via SVG overlay ───────────────────────────────
function PulsingMarker({ position, color = '#ef4444', label }) {
  const markerRef = useRef(null);
  const map = useMap();

  useEffect(() => {
    if (!map) return;
    const L = window.L || require('leaflet');
    const icon = L.divIcon({
      className: '',
      iconSize: [30, 30],
      iconAnchor: [15, 15],
      html: `<div style="position:relative;width:30px;height:30px;display:flex;align-items:center;justify-content:center;">
        <div style="position:absolute;width:30px;height:30px;border-radius:50%;background:${color};opacity:0.25;animation:pulseRing 2s ease-out infinite;"></div>
        <div style="position:absolute;width:18px;height:18px;border-radius:50%;background:${color};opacity:0.5;animation:pulseRing 2s ease-out infinite 0.5s;"></div>
        <div style="width:10px;height:10px;border-radius:50%;background:${color};border:2px solid white;box-shadow:0 0 8px ${color};position:relative;z-index:2;"></div>
        ${label ? `<div style="position:absolute;top:-20px;left:50%;transform:translateX(-50%);background:rgba(0,0,0,0.8);color:white;font-size:10px;padding:2px 6px;border-radius:3px;white-space:nowrap;border:1px solid ${color};">${label}</div>` : ''}
      </div>`,
    });
    const marker = L.marker(position, { icon }).addTo(map);
    markerRef.current = marker;
    return () => marker.remove();
  }, [map, position, color, label]);

  return null;
}

// ─── dot marker colors per type ────────────────────────────────────────────
const TYPE_CONFIG = {
  target:    { color: '#ef4444', radius: 10, label: 'Target (Pulsing)' },
  high_risk: { color: '#f97316', radius: 7,  label: 'High Risk IP' },
  wallet:    { color: '#fbbf24', radius: 6,  label: 'Wallet / Exchange' },
  flow:      { color: '#60a5fa', radius: 5,  label: 'Transaction Flow' },
};

// ─── Threat Level badge styling ─────────────────────────────────────────────
function ThreatBadge({ level }) {
  const colors = {
    CRITICAL: { bg: 'rgba(239,68,68,0.2)', color: '#f87171', border: 'rgba(239,68,68,0.5)' },
    HIGH:     { bg: 'rgba(249,115,22,0.2)', color: '#fb923c', border: 'rgba(249,115,22,0.5)' },
    MEDIUM:   { bg: 'rgba(251,191,36,0.2)', color: '#fbbf24', border: 'rgba(251,191,36,0.5)' },
    LOW:      { bg: 'rgba(148,163,184,0.2)', color: '#94a3b8', border: 'rgba(148,163,184,0.5)' },
  };
  const c = colors[level?.toUpperCase()] || colors.MEDIUM;
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 4,
      fontSize: 11, fontWeight: 700, fontFamily: 'monospace',
      background: c.bg, color: c.color, border: `1px solid ${c.border}`,
    }}>
      {level?.toUpperCase() || 'MEDIUM'}
    </span>
  );
}

// ─── inject pulse CSS once ──────────────────────────────────────────────────
const PULSE_CSS = `
@keyframes pulseRing {
  0%   { transform: scale(0.8); opacity: 0.7; }
  70%  { transform: scale(2.2); opacity: 0; }
  100% { transform: scale(2.2); opacity: 0; }
}
.leaflet-tile-pane { filter: brightness(0.80) saturate(0.85); }
`;

function InjectCSS() {
  useEffect(() => {
    const id = 'threat-map-css';
    if (document.getElementById(id)) return;
    const s = document.createElement('style');
    s.id = id; s.textContent = PULSE_CSS;
    document.head.appendChild(s);
    return () => s.remove();
  }, []);
  return null;
}

// ─── Main ThreatMap Component ───────────────────────────────────────────────
export default function ThreatMap() {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [tick, setTick]       = useState(0);

  // refresh data every 30 s to simulate live feed
  useEffect(() => {
    const load = () => {
      fetch('/api/map/threats')
        .then(r => r.json())
        .then(d => {
          setData(d);
          setSelected(d.selected || (d.markers[0] ?? null));
          setLoading(false);
        })
        .catch(() => setLoading(false));
    };
    load();
    const iv = setInterval(() => { setTick(t => t + 1); load(); }, 30000);
    return () => clearInterval(iv);
  }, []);

  if (loading) {
    return (
      <div style={{ height: 660, display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: '#060913', color: '#38bdf8', fontSize: 15, fontWeight: 600, gap: 10 }}>
        <Radio size={20} /> Connecting to live threat feed...
      </div>
    );
  }

  const { markers = [], connections = [], jurisdiction_table = [] } = data || {};
  const targetMarkers = markers.filter(m => m.type === 'target');

  return (
    <div style={{ position: 'relative', width: '100%', height: 660, borderRadius: 14, overflow: 'hidden',
        border: '1px solid rgba(56,189,248,0.3)', boxShadow: '0 0 40px rgba(56,189,248,0.08)' }}>
      <InjectCSS />

      {/* ── Header Bar ── */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, zIndex: 500,
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '10px 18px',
        background: 'rgba(6,9,19,0.88)', backdropFilter: 'blur(14px)',
        borderBottom: '1px solid rgba(51,65,85,0.5)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Shield size={18} color="#38bdf8" />
          <span style={{ fontWeight: 700, fontSize: 15, color: '#f8fafc', letterSpacing: '-0.01em' }}>
            Syntax Errors AI
          </span>
          <span style={{ color: '#475569' }}>|</span>
          <span style={{ fontSize: 13, color: '#94a3b8' }}>
            AI-Powered Bitcoin Forensics &amp; Dark Web Intelligence
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444',
                boxShadow: '0 0 8px #ef4444', display: 'inline-block', animation: 'pulseRing 2s infinite' }} />
            <span style={{ fontSize: 13, fontWeight: 600, color: '#f87171' }}>Live Threat Map</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 10px',
              background: 'rgba(30,41,59,0.6)', borderRadius: 6, border: '1px solid rgba(51,65,85,0.5)' }}>
            <Globe size={13} color="#94a3b8" />
            <span style={{ fontSize: 12, color: '#94a3b8' }}>Global View</span>
          </div>
        </div>
      </div>

      {/* ── Leaflet Map ── */}
      <MapContainer
        center={[20, 40]}
        zoom={3}
        minZoom={2}
        maxZoom={8}
        style={{ width: '100%', height: '100%', background: '#060b14' }}
        zoomControl={false}
        attributionControl={false}
      >
        {/* Dark satellite-style tile from CartoDB Dark Matter */}
        <TileLayer
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
        />

        {/* Connection lines */}
        {connections.map((c, i) => (
          <Polyline
            key={i}
            positions={[c.from, c.to]}
            pathOptions={{ color: c.color || '#ef4444', weight: 1.2, opacity: 0.6, dashArray: '6 4' }}
          />
        ))}

        {/* Threat Markers */}
        {markers.map((m, i) => {
          const cfg = TYPE_CONFIG[m.type] || TYPE_CONFIG.flow;
          const isTarget = m.type === 'target';
          return (
            <CircleMarker
              key={i}
              center={[m.lat, m.lon]}
              radius={cfg.radius}
              pathOptions={{
                color: cfg.color,
                fillColor: cfg.color,
                fillOpacity: isTarget ? 0.95 : 0.75,
                weight: isTarget ? 2.5 : 1.5,
              }}
              eventHandlers={{ click: () => setSelected(m) }}
            >
              <Popup>
                <div style={{ background: '#0b1120', color: '#f8fafc', padding: 2, minWidth: 180, fontFamily: 'monospace' }}>
                  <div style={{ fontWeight: 700, marginBottom: 4, color: cfg.color }}>{m.attributed_entity || m.ip}</div>
                  <div style={{ fontSize: 11, color: '#94a3b8' }}>{m.ip} · {m.country_name}</div>
                  <div style={{ marginTop: 4, fontSize: 11 }}>Score: <strong style={{ color: '#f87171' }}>{m.suspicion_score}/100</strong></div>
                </div>
              </Popup>
            </CircleMarker>
          );
        })}

        {/* Pulsing rings for high-priority targets */}
        {targetMarkers.map((m, i) => (
          <PulsingMarker key={`p-${i}`} position={[m.lat, m.lon]} color="#ef4444" />
        ))}
      </MapContainer>

      {/* ── Floating Info Panel (top-right) ── */}
      {selected && (
        <div style={{
          position: 'absolute', top: 60, right: 18, width: 290, zIndex: 500,
          background: 'rgba(8,12,28,0.92)', backdropFilter: 'blur(18px)',
          border: '1px solid rgba(56,189,248,0.35)', borderRadius: 12,
          boxShadow: '0 8px 32px rgba(0,0,0,0.7), 0 0 24px rgba(56,189,248,0.1)',
          overflow: 'hidden',
        }}>
          {/* panel header */}
          <div style={{ padding: '12px 16px', borderBottom: '1px solid rgba(51,65,85,0.5)',
              display: 'flex', alignItems: 'center', gap: 8 }}>
            <Target size={15} color="#ef4444" />
            <span style={{ fontWeight: 700, fontSize: 14, color: '#f8fafc' }}>Target Case Location</span>
          </div>
          {/* details */}
          <div style={{ padding: '14px 16px', fontSize: 13 }}>
            {[
              ['IP Address',   selected.ip],
              ['Location',     selected.country_name],
              ['ISP / Org',    selected.asn_org || 'Unknown'],
              ['ASN',          selected.asn ? `AS${selected.asn}` : 'Unknown'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between',
                  alignItems: 'center', marginBottom: 10 }}>
                <span style={{ color: '#64748b', fontWeight: 500 }}>{k}</span>
                <span style={{ color: '#cbd5e1', fontFamily: 'monospace', fontSize: 12,
                    maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v}</span>
              </div>
            ))}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <span style={{ color: '#64748b', fontWeight: 500 }}>Risk Score</span>
              <span style={{ color: '#f87171', fontWeight: 700, fontFamily: 'monospace' }}>
                {selected.suspicion_score} / 100
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <span style={{ color: '#64748b', fontWeight: 500 }}>Threat Level</span>
              <ThreatBadge level={selected.threat_level} />
            </div>
            {/* mini score bar */}
            <div style={{ width: '100%', height: 4, background: '#1e293b', borderRadius: 2, overflow: 'hidden', marginBottom: 14 }}>
              <div style={{
                width: `${selected.suspicion_score}%`, height: '100%',
                background: selected.suspicion_score >= 90 ? '#ef4444' : selected.suspicion_score >= 70 ? '#f97316' : '#38bdf8',
              }} />
            </div>

            {/* Jurisdiction Table */}
            <div style={{ borderTop: '1px solid rgba(51,65,85,0.5)', paddingTop: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                <Globe size={13} color="#94a3b8" />
                <span style={{ fontSize: 12, fontWeight: 700, color: '#94a3b8', letterSpacing: '0.05em' }}>
                  TOP OPERATIONAL JURISDICTIONS
                </span>
              </div>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(51,65,85,0.4)' }}>
                    <th style={{ textAlign: 'left', padding: '4px 0', color: '#64748b', fontWeight: 600 }}>Jurisdiction</th>
                    <th style={{ textAlign: 'right', padding: '4px 0', color: '#64748b', fontWeight: 600 }}>Threat Alerts</th>
                  </tr>
                </thead>
                <tbody>
                  {jurisdiction_table.slice(0, 6).map((row, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid rgba(51,65,85,0.2)' }}>
                      <td style={{ padding: '5px 0', color: '#cbd5e1' }}>{row.country_name}</td>
                      <td style={{ padding: '5px 0', textAlign: 'right', color: '#38bdf8', fontFamily: 'monospace', fontWeight: 700 }}>
                        {row.threat_alerts.toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Bottom Legend ── */}
      <div style={{
        position: 'absolute', bottom: 18, left: 18, zIndex: 500,
        display: 'flex', alignItems: 'center', gap: 18, flexWrap: 'wrap',
        background: 'rgba(6,9,19,0.88)', backdropFilter: 'blur(12px)',
        border: '1px solid rgba(51,65,85,0.45)', borderRadius: 8,
        padding: '8px 16px', fontSize: 11, fontWeight: 600,
      }}>
        {Object.entries(TYPE_CONFIG).map(([type, cfg]) => (
          <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{
              width: type === 'target' ? 12 : 9,
              height: type === 'target' ? 12 : 9,
              borderRadius: '50%',
              background: cfg.color,
              boxShadow: `0 0 6px ${cfg.color}`,
              display: 'inline-block',
              border: type === 'target' ? '2px solid white' : undefined,
            }} />
            <span style={{ color: '#94a3b8' }}>{cfg.label}</span>
          </div>
        ))}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 18, height: 2, background: '#ef4444', borderTop: '1px dashed #ef4444' }} />
          <span style={{ color: '#94a3b8' }}>Connection Line</span>
        </div>
      </div>

      {/* ── Attribution ── */}
      <div style={{
        position: 'absolute', bottom: 8, right: 14, zIndex: 500,
        fontSize: 10, color: '#334155', fontFamily: 'sans-serif',
      }}>
        © OpenStreetMap contributors | OpenMapTiles | CARTO
      </div>
    </div>
  );
}
