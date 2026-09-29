import React, { useState, useEffect, useRef, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { 
  Maximize2, Minimize2, ZoomIn, ZoomOut, RefreshCw, 
  Layers, ArrowRight, ArrowLeft, Shield, AlertTriangle, 
  Globe, Zap, Hash, ExternalLink, Play, Pause
} from 'lucide-react';

const NODE_ICONS = {
  tx: "⚡",
  wallet: "💼",
  ip: "🌐",
  ransomware: "💀",
  darknet_market: "🧅",
  mixer: "🔀",
  sanctions: "🚫",
  terror_financing: "☢️",
  exchange: "🏦",
  high_risk_exchange: "⚠️",
  scam: "🎣"
};

export default function LinkAnalysisGraph({ centerNode, onSelectNode }) {
  const fgRef = useRef();
  const containerRef = useRef();

  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [depth, setDepth] = useState(2);
  const [direction, setDirection] = useState('both');
  const [mode, setMode] = useState('all');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [stepperData, setStepperData] = useState(null);
  const [particlesActive, setParticlesActive] = useState(true);

  // Fetch subgraph data from FastAPI
  const fetchGraph = useCallback(async () => {
    setLoading(true);
    try {
      const url = `/api/graph/subgraph?center=${centerNode || ''}&depth=${depth}&direction=${direction}&mode=${mode}`;
      const res = await fetch(url);
      const data = await res.json();
      
      // Format edges for ForceGraph2D (needs source and target as IDs or references)
      const formattedEdges = data.edges.map(e => ({
        ...e,
        source: e.source,
        target: e.target
      }));

      setGraphData({
        nodes: data.nodes,
        links: formattedEdges
      });
    } catch (err) {
      console.error("Failed to load graph data:", err);
    } finally {
      setLoading(false);
    }
  }, [centerNode, depth, direction, mode]);

  useEffect(() => {
    fetchGraph();
  }, [fetchGraph]);

  // Fetch Next-Hop stepper when selected or center node changes
  useEffect(() => {
    const target = selectedNode ? selectedNode.id : centerNode;
    if (!target) return;

    fetch(`/api/graph/stepper?node_id=${encodeURIComponent(target)}`)
      .then(res => res.json())
      .then(data => setStepperData(data))
      .catch(err => console.error("Failed to fetch stepper:", err));
  }, [centerNode, selectedNode]);

  // Toggle true browser fullscreen
  const toggleFullscreen = () => {
    if (!containerRef.current) return;
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen().then(() => setIsFullscreen(true)).catch(e => console.log(e));
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false)).catch(e => console.log(e));
    }
  };

  // Custom Node Canvas Painting (Neon glows, pill badges, clean typography)
  const paintNode = useCallback((node, ctx, globalScale) => {
    const isCenter = node.is_center;
    const isHovered = hoveredNode && hoveredNode.id === node.id;
    const isSelected = selectedNode && selectedNode.id === node.id;
    const r = (isCenter ? 14 : (node.type === 'tx' ? 9 : 7));

    // Outer Glow / Ring for Focus or Hover
    if (isCenter || isSelected || isHovered) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, r + (isCenter ? 6 : 4), 0, 2 * Math.PI, false);
      ctx.fillStyle = isCenter ? 'rgba(56, 189, 248, 0.25)' : 'rgba(251, 191, 36, 0.25)';
      ctx.fill();
      ctx.strokeStyle = isCenter ? '#38bdf8' : '#fbbf24';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }

    // Node Body
    ctx.beginPath();
    ctx.arc(node.x, node.y, r, 0, 2 * Math.PI, false);
    ctx.fillStyle = node.color || '#64748b';
    ctx.fill();
    ctx.strokeStyle = isCenter ? '#ffffff' : 'rgba(0, 0, 0, 0.6)';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Node Label Pill (Only paint if zoomed in enough or if node is center/hovered)
    if (globalScale > 0.8 || isCenter || isHovered || isSelected) {
      const icon = NODE_ICONS[node.category] || NODE_ICONS[node.type] || "●";
      const labelText = `${icon} ${node.label}`;
      const fontSize = Math.max(10 / globalScale, 3);
      ctx.font = `600 ${fontSize}px 'Inter', sans-serif`;

      const textWidth = ctx.measureText(labelText).width;
      const bckgDimensions = [textWidth + 6, fontSize + 3];

      // Pill Background
      ctx.fillStyle = 'rgba(6, 9, 19, 0.85)';
      ctx.fillRect(
        node.x - bckgDimensions[0] / 2,
        node.y + r + 2,
        bckgDimensions[0],
        bckgDimensions[1]
      );

      // Pill Border
      ctx.strokeStyle = isCenter ? '#38bdf8' : 'rgba(51, 65, 85, 0.6)';
      ctx.lineWidth = 0.5;
      ctx.strokeRect(
        node.x - bckgDimensions[0] / 2,
        node.y + r + 2,
        bckgDimensions[0],
        bckgDimensions[1]
      );

      // Label Text
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = isCenter ? '#38bdf8' : '#f8fafc';
      ctx.fillText(labelText, node.x, node.y + r + 2 + bckgDimensions[1] / 2);
    }
  }, [hoveredNode, selectedNode]);

  return (
    <div 
      ref={containerRef}
      className={`glass-panel ${isFullscreen ? 'fullscreen-container' : ''}`}
      style={{
        position: 'relative',
        width: '100%',
        height: isFullscreen ? '100vh' : '720px',
        overflow: 'hidden',
        background: '#070b14',
        border: '1px solid rgba(56, 189, 248, 0.25)',
        display: 'flex',
        flexDirection: 'column'
      }}
    >
      {/* Floating HUD Controls */}
      <div style={{
        position: 'absolute',
        top: 14,
        left: 16,
        right: 16,
        zIndex: 20,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 12,
        pointerEvents: 'none'
      }}>
        {/* Left Status & Filters */}
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: 10, 
          pointerEvents: 'auto',
          background: 'rgba(11, 17, 32, 0.85)',
          backdropFilter: 'blur(16px)',
          padding: '6px 14px',
          borderRadius: 10,
          border: '1px solid rgba(51, 65, 85, 0.5)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="pulse-dot"></span>
            <span style={{ fontSize: 13, fontWeight: 700, color: '#38bdf8', letterSpacing: '0.02em' }}>
              INTERACTIVE LINK ANALYSIS
            </span>
          </div>

          <span style={{ color: '#475569' }}>|</span>

          {/* Depth Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
            <span style={{ color: '#94a3b8', fontWeight: 600 }}>Depth:</span>
            {[1, 2, 3].map(d => (
              <button
                key={d}
                onClick={() => setDepth(d)}
                style={{
                  padding: '2px 8px',
                  borderRadius: 4,
                  fontSize: 11,
                  fontWeight: 700,
                  cursor: 'pointer',
                  border: depth === d ? '1px solid #38bdf8' : '1px solid rgba(51,65,85,0.4)',
                  background: depth === d ? 'rgba(56,189,248,0.2)' : 'transparent',
                  color: depth === d ? '#38bdf8' : '#94a3b8'
                }}
              >
                {d}
              </button>
            ))}
          </div>

          <span style={{ color: '#475569' }}>|</span>

          {/* Direction Filter */}
          <select 
            value={direction} 
            onChange={e => setDirection(e.target.value)}
            style={{
              background: 'rgba(30, 41, 59, 0.7)',
              border: '1px solid rgba(51, 65, 85, 0.6)',
              color: '#f8fafc',
              fontSize: 12,
              padding: '3px 8px',
              borderRadius: 6,
              cursor: 'pointer',
              outline: 'none'
            }}
          >
            <option value="both">⇄ Both Flow Directions</option>
            <option value="downstream">➔ Downstream Hops</option>
            <option value="upstream">⬅ Upstream Origins</option>
          </select>
        </div>

        {/* Right Action Tools */}
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: 8, 
          pointerEvents: 'auto',
          background: 'rgba(11, 17, 32, 0.85)',
          backdropFilter: 'blur(16px)',
          padding: '6px 12px',
          borderRadius: 10,
          border: '1px solid rgba(51, 65, 85, 0.5)'
        }}>
          {/* Animated Particles Toggle */}
          <button
            onClick={() => setParticlesActive(!particlesActive)}
            title={particlesActive ? "Pause Flow Particles" : "Play Flow Particles"}
            style={{
              background: 'transparent',
              border: 'none',
              color: particlesActive ? '#38bdf8' : '#64748b',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              padding: 4
            }}
          >
            {particlesActive ? <Pause size={16} /> : <Play size={16} />}
          </button>

          {/* Reset Zoom / Center */}
          <button
            onClick={() => fgRef.current && fgRef.current.zoomToFit(400, 50)}
            title="Reset View & Center Graph"
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94a3b8',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              padding: 4
            }}
          >
            <RefreshCw size={16} />
          </button>

          {/* Fullscreen Button */}
          <button
            onClick={toggleFullscreen}
            title={isFullscreen ? "Exit Fullscreen" : "Enter Fullscreen"}
            style={{
              background: 'transparent',
              border: 'none',
              color: isFullscreen ? '#38bdf8' : '#94a3b8',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              padding: 4
            }}
          >
            {isFullscreen ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
          </button>
        </div>
      </div>

      {/* Main Force Graph Canvas */}
      <div style={{ flex: 1, width: '100%', height: '100%', position: 'relative' }}>
        {loading && (
          <div style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'rgba(6, 9, 19, 0.75)',
            zIndex: 10,
            color: '#38bdf8',
            fontWeight: 600,
            fontSize: 14,
            gap: 10
          }}>
            <RefreshCw className="animate-spin" size={20} />
            Synthesizing Link Analysis Subgraph...
          </div>
        )}

        <ForceGraph2D
          ref={fgRef}
          graphData={graphData}
          nodeCanvasObject={paintNode}
          nodePointerAreaPaint={(node, color, ctx) => {
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(node.x, node.y, 16, 0, 2 * Math.PI, false);
            ctx.fill();
          }}
          linkDirectionalParticles={particlesActive ? 2 : 0}
          linkDirectionalParticleSpeed={0.005}
          linkDirectionalParticleWidth={1.8}
          linkDirectionalParticleColor={() => "#38bdf8"}
          linkColor={link => link.color || "#334155"}
          linkWidth={link => link.is_active ? 2.2 : 1.0}
          onNodeClick={node => {
            setSelectedNode(node);
            if (onSelectNode) onSelectNode(node.id);
          }}
          onNodeHover={node => setHoveredNode(node)}
          cooldownTicks={120}
          d3AlphaDecay={0.02}
          d3VelocityDecay={0.3}
        />

        {/* Floating Node Inspector Dossier Card */}
        {(hoveredNode || selectedNode) && (
          <div style={{
            position: 'absolute',
            bottom: 80,
            right: 20,
            width: 320,
            background: 'rgba(11, 17, 32, 0.92)',
            backdropFilter: 'blur(20px)',
            border: '1px solid rgba(56, 189, 248, 0.35)',
            borderRadius: 12,
            padding: 16,
            boxShadow: '0 12px 36px rgba(0, 0, 0, 0.6), 0 0 20px rgba(56, 189, 248, 0.1)',
            zIndex: 30,
            pointerEvents: 'auto'
          }}>
            {(() => {
              const item = hoveredNode || selectedNode;
              const isCenter = item.is_center;
              return (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                    <span className="badge" style={{
                      background: item.color ? `${item.color}22` : 'rgba(56, 189, 248, 0.15)',
                      color: item.color || '#38bdf8',
                      borderColor: item.color || '#38bdf8'
                    }}>
                      {NODE_ICONS[item.category] || "●"} {String(item.category || item.type).toUpperCase()}
                    </span>
                    <span className={`badge badge-${String(item.threat_level).toLowerCase()}`}>
                      {item.threat_level || 'MEDIUM'}
                    </span>
                  </div>

                  <div style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc', marginBottom: 4 }}>
                    {item.entity_name || item.label}
                  </div>

                  <div style={{ 
                    fontFamily: 'monospace', 
                    fontSize: 11, 
                    color: '#94a3b8', 
                    wordBreak: 'break-all',
                    background: 'rgba(15, 23, 42, 0.8)',
                    padding: '6px 8px',
                    borderRadius: 6,
                    marginBottom: 12
                  }}>
                    {item.id}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
                    <span style={{ color: '#64748b' }}>Suspicion Score:</span>
                    <span style={{ fontWeight: 700, color: item.suspicion_score > 75 ? '#f87171' : '#38bdf8' }}>
                      {item.suspicion_score ? item.suspicion_score.toFixed(1) : '50.0'} / 100
                    </span>
                  </div>

                  <div style={{ width: '100%', height: 4, background: '#1e293b', borderRadius: 2, overflow: 'hidden', marginBottom: 12 }}>
                    <div style={{
                      width: `${item.suspicion_score || 50}%`,
                      height: '100%',
                      background: item.suspicion_score > 75 ? '#ef4444' : '#38bdf8'
                    }} />
                  </div>

                  <div style={{ display: 'flex', gap: 8 }}>
                    {!isCenter && (
                      <button
                        onClick={() => onSelectNode && onSelectNode(item.id)}
                        className="cyber-btn cyber-btn-primary"
                        style={{ flex: 1, padding: '6px 10px', fontSize: 12 }}
                      >
                        <Zap size={14} /> Center This Node
                      </button>
                    )}
                    <button
                      onClick={() => navigator.clipboard.writeText(item.id)}
                      className="cyber-btn"
                      style={{ padding: '6px 10px', fontSize: 12 }}
                      title="Copy Address / Hash"
                    >
                      Copy
                    </button>
                  </div>
                </div>
              );
            })()}
          </div>
        )}
      </div>

      {/* Next-Hop Connection Navigator (Bottom Bar) */}
      {stepperData && (
        <div style={{
          background: 'rgba(11, 17, 32, 0.95)',
          borderTop: '1px solid rgba(51, 65, 85, 0.5)',
          padding: '10px 18px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 16,
          zIndex: 20
        }}>
          {/* Upstream Sources */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, overflowX: 'auto', flex: 1 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8', whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: 4 }}>
              <ArrowLeft size={13} /> UPSTREAM ({stepperData.total_upstream}):
            </span>
            {stepperData.upstream.slice(0, 3).map((u, i) => (
              <button
                key={i}
                onClick={() => onSelectNode && onSelectNode(u.id)}
                className="cyber-btn"
                style={{ padding: '4px 10px', fontSize: 11, whiteSpace: 'nowrap' }}
              >
                {NODE_ICONS[u.category] || "💼"} {u.label} {u.amount ? `(${u.amount.toFixed(2)} BTC)` : ''}
              </button>
            ))}
          </div>

          <span style={{ color: '#334155' }}>|</span>

          {/* Downstream Targets */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, overflowX: 'auto', flex: 1 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8', whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: 4 }}>
              <ArrowRight size={13} /> DOWNSTREAM ({stepperData.total_downstream}):
            </span>
            {stepperData.downstream.slice(0, 3).map((d, i) => (
              <button
                key={i}
                onClick={() => onSelectNode && onSelectNode(d.id)}
                className="cyber-btn"
                style={{ padding: '4px 10px', fontSize: 11, whiteSpace: 'nowrap' }}
              >
                {NODE_ICONS[d.category] || "⚡"} {d.label} {d.amount ? `(${d.amount.toFixed(2)} BTC)` : ''}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
