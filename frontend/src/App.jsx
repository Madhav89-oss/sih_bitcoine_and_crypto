import React, { useState, useEffect } from 'react';
import { 
  Shield, Network, BarChart3, Globe, Compass, 
  Search, Cpu, CheckCircle2, Zap, ArrowRight, Eye, Map
} from 'lucide-react';
import LinkAnalysisGraph from './components/LinkAnalysisGraph';
import PathFinder from './components/PathFinder';
import OverviewMetrics from './components/OverviewMetrics';
import DarkWebIntel from './components/DarkWebIntel';
import ThreatMap from './components/ThreatMap';

export default function App() {
  const [activeTab, setActiveTab] = useState('graph');
  const [focusNode, setFocusNode] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [searchOpen, setSearchOpen] = useState(false);

  // Search autocomplete
  useEffect(() => {
    if (searchQuery.trim().length < 2) {
      setSearchResults([]);
      setSearchOpen(false);
      return;
    }

    const timer = setTimeout(() => {
      fetch(`/api/graph/search?q=${encodeURIComponent(searchQuery)}`)
        .then(res => res.json())
        .then(d => {
          setSearchResults(d.results || []);
          setSearchOpen(true);
        })
        .catch(err => console.error("Search failed:", err));
    }, 200);

    return () => clearTimeout(timer);
  }, [searchQuery]);

  const handleSelectSearchItem = (id) => {
    setFocusNode(id);
    setActiveTab('graph');
    setSearchQuery('');
    setSearchOpen(false);
  };

  const handleHop = (nodeId) => {
    setFocusNode(nodeId);
    setActiveTab('graph');
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Application Header */}
      <header className="app-header">
        <div style={{ 
          maxWidth: 1600, 
          margin: '0 auto', 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 16
        }}>
          {/* Logo & Platform Title */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{
              width: 44,
              height: 44,
              borderRadius: 10,
              background: 'linear-gradient(135deg, rgba(244,63,94,0.2), rgba(56,189,248,0.2))',
              border: '1px solid rgba(56,189,248,0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 22,
              boxShadow: '0 0 16px rgba(56,189,248,0.25)'
            }}>
              🛡️
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <h1 style={{ fontSize: 18, fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.02em', margin: 0 }}>
                  Syntax Errors AI
                </h1>
                <span style={{ color: '#475569' }}>—</span>
                <span style={{ fontSize: 15, fontWeight: 600, color: '#38bdf8' }}>
                  Dark Web Intelligence & Bitcoin Forensics
                </span>
              </div>
              <p style={{ fontSize: 12, color: '#94a3b8', margin: 0 }}>
                Automated threat actor deanonymization, link analysis & laundering pattern detection | SIH 2026
              </p>
            </div>
          </div>

          {/* Quick Search & Status Indicators */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            {/* Search Bar */}
            <div style={{ position: 'relative' }}>
              <Search size={15} color="#64748b" style={{ position: 'absolute', left: 12, top: 11 }} />
              <input
                type="text"
                placeholder="Search wallet, txid, entity..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                onFocus={() => searchResults.length > 0 && setSearchOpen(true)}
                className="cyber-input"
                style={{ paddingLeft: 34, width: 280 }}
              />

              {/* Search Dropdown Results */}
              {searchOpen && searchResults.length > 0 && (
                <div style={{
                  position: 'absolute',
                  top: '100%',
                  right: 0,
                  width: 360,
                  marginTop: 6,
                  background: 'rgba(11, 17, 32, 0.96)',
                  backdropFilter: 'blur(20px)',
                  border: '1px solid rgba(56, 189, 248, 0.35)',
                  borderRadius: 10,
                  boxShadow: '0 12px 32px rgba(0, 0, 0, 0.8)',
                  zIndex: 100,
                  overflow: 'hidden'
                }}>
                  <div style={{ padding: '8px 12px', fontSize: 11, fontWeight: 700, color: '#64748b', borderBottom: '1px solid rgba(51,65,85,0.4)' }}>
                    SEARCH MATCHES ({searchResults.length})
                  </div>
                  {searchResults.map((res, i) => (
                    <div
                      key={i}
                      onClick={() => handleSelectSearchItem(res.id)}
                      style={{
                        padding: '10px 12px',
                        cursor: 'pointer',
                        borderBottom: '1px solid rgba(51,65,85,0.2)',
                        transition: 'background 0.15s ease'
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(56, 189, 248, 0.12)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <div style={{ fontSize: 13, fontWeight: 600, color: '#f8fafc' }}>
                        {res.title}
                      </div>
                      <div style={{ fontSize: 11, color: '#94a3b8' }}>
                        {res.subtitle}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Live Pipeline Badge */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              background: 'rgba(16, 185, 129, 0.1)',
              border: '1px solid rgba(16, 185, 129, 0.25)',
              padding: '6px 12px',
              borderRadius: 8
            }}>
              <span className="pulse-dot"></span>
              <span style={{ fontSize: 12, fontWeight: 700, color: '#34d399' }}>
                PIPELINE LIVE
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main style={{ maxWidth: 1600, width: '100%', margin: '0 auto', padding: '20px 24px', flex: 1 }}>
        {/* Navigation Tabs Bar */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          marginBottom: 20,
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: 12
        }}>
          <button
            onClick={() => setActiveTab('graph')}
            className={`nav-tab ${activeTab === 'graph' ? 'active' : ''}`}
          >
            <Network size={16} /> Interactive Link Analysis & Hops
          </button>

          <button
            onClick={() => setActiveTab('overview')}
            className={`nav-tab ${activeTab === 'overview' ? 'active' : ''}`}
          >
            <BarChart3 size={16} /> SOC Command Center & Alerts
          </button>

          <button
            onClick={() => setActiveTab('intel')}
            className={`nav-tab ${activeTab === 'intel' ? 'active' : ''}`}
          >
            <Globe size={16} /> Dark Web Onion Intel Feeds
          </button>

          <button
            onClick={() => setActiveTab('map')}
            className={`nav-tab ${activeTab === 'map' ? 'active' : ''}`}
          >
            <Map size={16} /> 🗺️ Live Threat Map
          </button>
        </div>

        {/* Tab Views */}
        {activeTab === 'graph' && (
          <div>
            <LinkAnalysisGraph 
              centerNode={focusNode} 
              onSelectNode={nodeId => setFocusNode(nodeId)} 
            />
            <PathFinder onHopToNode={handleHop} />
          </div>
        )}

        {activeTab === 'overview' && (
          <OverviewMetrics onTraceTx={handleHop} />
        )}

        {activeTab === 'intel' && (
          <DarkWebIntel onSelectWallet={handleHop} />
        )}

        {activeTab === 'map' && (
          <ThreatMap />
        )}
      </main>

      {/* Footer */}
      <footer style={{
        borderTop: '1px solid var(--border-subtle)',
        padding: '16px 24px',
        textAlign: 'center',
        fontSize: 12,
        color: '#64748b',
        background: 'rgba(6, 9, 19, 0.7)'
      }}>
        Syntax Errors AI Forensic Platform • Developed for Smart India Hackathon (SIH 2026) & National Law Enforcement Forensics
      </footer>
    </div>
  );
}
