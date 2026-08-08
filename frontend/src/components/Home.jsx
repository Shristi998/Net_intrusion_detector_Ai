import React, { useState, useRef, useEffect } from "react";
import { ShieldCheck, LayoutDashboard, Bell, List, BarChart3, Settings as SettingsIcon, User, LogOut, ChevronDown, AlertTriangle, Moon, Sun, Network as NetworkIcon, X } from "lucide-react";
import Overview from "../pages/Overview";
import Alerts from "../pages/Alerts";
import Detections from "../pages/Detections"; // Mapped to Model performance
import Logs from "../pages/Logs"; // Mapped to Traffic log
import Settings from "../pages/Settings"; // Mapped to Admin
import Network from "../pages/Network";

import { io } from "socket.io-client";

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';

export default function Home({ user, onLogout, theme, toggleTheme }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [livePackets, setLivePackets] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [toasts, setToasts] = useState([]);
  const [stats, setStats] = useState({
    totalAnalyzed: 0,
    threatsFound: 0,
    blocked: 0,
    monitoredHosts: 0
  });
  const [modelInfo, setModelInfo] = useState({});
  const alertCounterRef = useRef(0);
  const [menuOpen, setMenuOpen] = useState(false);

  const triggerToast = (alertItem) => {
    const toastId = Math.random().toString(36).substring(2, 9);
    const newToast = { id: toastId, ...alertItem };
    setToasts(prev => [newToast, ...prev].slice(0, 3));

    // Auto dismiss after 5 seconds
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== toastId));
    }, 5000);
  };

  const removeToast = (id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };

  const handleClearAlerts = () => {
    setLiveAlerts([]);
  };

  useEffect(() => {
    fetch(`${BACKEND_URL}/api/stats`)
      .then(res => res.json())
      .then(data => {
        if (data.threatsFound) {
          setStats(s => ({ ...s, threatsFound: data.threatsFound }));
          alertCounterRef.current = data.threatsFound;
        }
      })
      .catch(err => console.error(err));

    fetch(`${BACKEND_URL}/api/logs`)
      .then(res => res.json())
      .then(logs => {
        if (Array.isArray(logs) && logs.length > 0) {
          const formattedLogs = logs.map(l => ({
            id: Math.random().toString(36).substr(2, 9),
            time: new Date(l.timestamp),
            src: l.src,
            dst: l.dst,
            proto: l.proto,
            size: l.length || 500,
            flags: "...",
            sev: l.verdict === 'Normal' ? 'Low' : 'High',
            type: l.verdict,
            verdict: l.verdict
          }));
          setLivePackets(formattedLogs);
        }
      })
      .catch(err => console.error(err));

    const socket = io(BACKEND_URL);
    const hostsSet = new Set();
    
    socket.on("packet_update", (data) => {
      hostsSet.add(data.src);
      hostsSet.add(data.dst);

      setStats(prev => {
        let newThreats = prev.threatsFound;
        let newBlocked = prev.blocked;
        if (data.verdict !== "Normal") {
          newThreats++;
          if (data.sev === "High" || data.sev === "Critical") newBlocked++;
        }
        return {
          totalAnalyzed: prev.totalAnalyzed + 1,
          threatsFound: newThreats,
          blocked: newBlocked,
          monitoredHosts: hostsSet.size
        };
      });

      const newPacket = {
        id: data.id || Math.random().toString(36).substr(2, 9),
        time: new Date(data.timestamp),
        src: data.src,
        dst: data.dst,
        proto: data.proto,
        size: data.length,
        flags: "...",
        sev: data.sev,
        type: data.type || data.verdict,
        verdict: data.verdict || data.type
      };

      setLivePackets(prev => [newPacket, ...prev].slice(0, 100));

      if (data.verdict !== "Normal" && data.type !== "Normal") {
        alertCounterRef.current += 1;
        const formattedId = `ALT-${String(alertCounterRef.current).padStart(4, '0')}`;
        
        const attackType = data.type || data.verdict || 'Unknown Threat';
        let severity = data.sev;
        if (!severity) {
            if (['Dos/DDos', 'Infiltration', 'Botnet ARES'].includes(attackType)) {
                severity = 'Critical';
            } else if (['Web Attack', 'Brute Force'].includes(attackType)) {
                severity = 'High';
            } else if (['PortScan'].includes(attackType)) {
                severity = 'Medium';
            } else {
                severity = 'Low';
            }
        }

        const newAlert = {
          id: formattedId,
          time: new Date(data.timestamp).toLocaleString(),
          type: attackType,
          severity: severity,
          srcIp: data.src,
          destIp: data.dst,
        };

        setLiveAlerts(prev => [newAlert, ...prev].slice(0, 100));

        // Popup toast notification for high/critical threats
        if (severity === 'Critical' || severity === 'High') {
          triggerToast(newAlert);
        }
      }
    });

    fetch(`${BACKEND_URL}/api/model_info`)
      .then(res => res.json())
      .then(data => setModelInfo(data))
      .catch(err => console.error(err));

    return () => socket.disconnect();
  }, []);

  const activeAlertsCount = liveAlerts.length;

  const lightThemeCss = `
    :root {
      --surface-1: #ffffff;
      --surface-2: rgba(255, 255, 255, 0.7);
      --surface-3: #ffffff;
      --border: #e2e8f0;
      --bg-base: #f8fafc;
      --bg-accent: rgba(59, 130, 246, 0.1);
      --text-main: #0f172a;
      --text-accent: #2563eb;
      --text-secondary: #475569;
      --text-muted: #94a3b8;
      --text-danger: #ef4444;
      --bg-danger: rgba(239, 68, 68, 0.1);
      --fill-danger: #ef4444;
      --text-warning: #f59e0b;
      --bg-warning: rgba(245, 158, 11, 0.1);
      --fill-warning: #f59e0b;
      --text-success: #10b981;
      --fill-success: #10b981;
      --fill-accent: #3b82f6;
      --radius: 12px;
      --shadow-popover: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.05);
      --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
      --shadow-card: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
    }
  `;

  const darkThemeCss = `
    :root {
      --surface-1: #1e293b;
      --surface-2: rgba(30, 41, 59, 0.7);
      --surface-3: #334155;
      --border: #334155;
      --bg-base: #0f172a;
      --bg-accent: rgba(56, 189, 248, 0.15);
      --text-main: #f8fafc;
      --text-accent: #38bdf8;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --text-danger: #f87171;
      --bg-danger: rgba(248, 113, 113, 0.1);
      --fill-danger: #f87171;
      --text-warning: #fbbf24;
      --bg-warning: rgba(251, 191, 36, 0.1);
      --fill-warning: #fbbf24;
      --text-success: #34d399;
      --fill-success: #34d399;
      --fill-accent: #38bdf8;
      --radius: 12px;
      --shadow-popover: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.3);
      --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.3);
      --shadow-card: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2);
    }
  `;

  return (
    <div style={{
      fontFamily: "'Inter', sans-serif",
      backgroundColor: "var(--bg-base)",
      color: "var(--text-main)",
      minHeight: "100vh",
      display: "flex",
      flexDirection: "column"
    }}>
      {/* Toast Notification Container */}
      <div className="toast-container">
        {toasts.map(toast => (
          <div key={toast.id} className="toast-item">
            <AlertTriangle size={20} color="var(--text-danger)" style={{ flexShrink: 0, marginTop: "2px" }} />
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "2px" }}>
                <span style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-danger)" }}>THREAT DETECTED</span>
                <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "monospace" }}>{toast.id}</span>
              </div>
              <p style={{ fontSize: "13px", fontWeight: "600", margin: "0 0 2px", color: "var(--text-main)" }}>{toast.type}</p>
              <p style={{ fontSize: "11px", margin: 0, color: "var(--text-secondary)", fontFamily: "monospace" }}>{toast.srcIp} &rarr; {toast.destIp}</p>
            </div>
            <button 
              onClick={() => removeToast(toast.id)} 
              style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: "2px" }}
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');
        
        ${theme === 'light' ? lightThemeCss : darkThemeCss}
        
        body {
          font-family: 'Outfit', sans-serif;
          background-color: var(--bg-base);
          background-image: ${theme === 'light' ? 'radial-gradient(at 0% 0%, hsla(210,100%,97%,1) 0, transparent 50%), radial-gradient(at 100% 100%, hsla(210,100%,97%,1) 0, transparent 50%)' : 'radial-gradient(at 0% 0%, rgba(30,41,59,0.5) 0, transparent 50%), radial-gradient(at 100% 100%, rgba(30,41,59,0.5) 0, transparent 50%)'};
        }

        .navitem {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 8px 10px;
          border-radius: var(--radius);
          border: none;
          background: transparent;
          color: var(--text-secondary);
          font-size: 14px;
          font-weight: 500;
          text-align: left;
          cursor: pointer;
          transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .navitem:hover {
          background: rgba(125, 125, 125, 0.1);
          color: var(--text-main);
          transform: translateX(4px);
        }
        .navitem.active {
          background: var(--bg-accent);
          color: var(--text-accent);
          font-weight: 600;
        }
        .navitem.active:hover {
          transform: none;
        }
        .usermenu-item {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 8px 10px;
          font-size: 13px;
          font-weight: 500;
          color: var(--text-secondary);
          border-radius: var(--radius);
          cursor: pointer;
          transition: all 0.2s ease;
        }
        .usermenu-item:hover {
          background: rgba(125, 125, 125, 0.1);
          color: var(--text-main);
        }
        
        /* Card Hover Animations */
        .card-anim {
          transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .card-anim:hover {
          transform: translateY(-2px);
          box-shadow: var(--shadow-card);
        }

        .theme-toggle {
          background: transparent;
          border: none;
          color: var(--text-secondary);
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 6px;
          border-radius: 50%;
          transition: all 0.2s;
        }
        .theme-toggle:hover {
          background: var(--surface-1);
          color: var(--text-main);
        }
      `}</style>
      
      <div style={{ border: "0.5px solid var(--border)", borderRadius: "12px", overflow: "hidden", margin: "1rem", flex: 1, display: "flex", flexDirection: "column", background: "var(--bg-base)", transition: "background 0.3s ease" }}>
        
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 16px", borderBottom: "0.5px solid var(--border)", background: "var(--surface-2)", backdropFilter: "blur(12px)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", fontWeight: "500", fontSize: "14px" }}>
            <ShieldCheck size={18} color="var(--text-accent)" /> NIDS console
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", color: "var(--text-success)" }}>
              <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: "var(--fill-success)", display: "inline-block" }}></span> Sniffer running
            </div>

            <button type="button" className="theme-toggle" onClick={toggleTheme}>
              {theme === 'light' ? <Moon size={18} /> : <Sun size={18} />}
            </button>

            <div style={{ position: "relative" }}>
              <button 
                type="button" 
                onClick={() => setMenuOpen(!menuOpen)}
                style={{ display: "flex", alignItems: "center", gap: "8px", border: "none", background: "transparent", cursor: "pointer", padding: "4px 6px", borderRadius: "var(--radius)" }}
              >
                <div style={{ width: "28px", height: "28px", borderRadius: "50%", background: "var(--bg-accent)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "12px", fontWeight: "500", color: "var(--text-accent)" }}>
                  {user?.firstName?.[0] || 'A'}
                </div>
                <div style={{ textAlign: "left", color: "var(--text-main)" }}>
                  <p style={{ fontSize: "13px", margin: 0, fontWeight: "500" }}>{user ? `${user.firstName} ${user.lastName}` : 'Admin User'}</p>
                  <p style={{ fontSize: "11px", margin: 0, color: "var(--text-secondary)" }}>{user?.role || 'Administrator'}</p>
                </div>
                <ChevronDown size={14} color="var(--text-secondary)" />
              </button>
              
              {menuOpen && (
                <div style={{ position: "absolute", right: 0, top: "38px", width: "180px", background: "var(--surface-3)", border: "0.5px solid var(--border)", borderRadius: "var(--radius)", boxShadow: "var(--shadow-popover)", zIndex: 10, padding: "6px" }}>
                  <div className="usermenu-item"><User size={15} />Profile</div>
                  <div className="usermenu-item"><SettingsIcon size={15} />Preferences</div>
                  <div style={{ height: "0.5px", background: "var(--border)", margin: "4px 6px" }}></div>
                  <button type="button" onClick={onLogout} style={{ display: "flex", alignItems: "center", gap: "8px", padding: "8px 10px", fontSize: "13px", color: "var(--text-danger)", borderRadius: "var(--radius)", width: "100%", border: "none", background: "transparent", textAlign: "left", cursor: "pointer" }}>
                    <LogOut size={15} />Log out
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        <div style={{ display: "flex", gap: 0, flex: 1 }}>
          {/* Sidebar */}
          <div style={{ width: "180px", background: "var(--surface-1)", borderRight: "0.5px solid var(--border)", padding: "1rem 0", flexShrink: 0 }}>
            <p style={{ padding: "0 1rem", fontSize: "11px", color: "var(--text-muted)", margin: "0 0 6px", textTransform: "uppercase", letterSpacing: "0.02em" }}>Monitor</p>
            <div style={{ display: "flex", flexDirection: "column", gap: "2px", padding: "0 8px", marginBottom: "16px" }}>
              <button type="button" className={`navitem ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
                <LayoutDashboard size={16} />Overview
              </button>
              <button type="button" className={`navitem ${activeTab === 'alerts' ? 'active' : ''}`} onClick={() => setActiveTab('alerts')}>
                <Bell size={16} />Live alerts 
                {activeAlertsCount > 0 && (
                  <span style={{ marginLeft: "auto", background: "var(--bg-danger)", color: "var(--text-danger)", fontSize: "11px", padding: "1px 6px", borderRadius: "8px" }}>{activeAlertsCount}</span>
                )}
              </button>
              <button type="button" className={`navitem ${activeTab === 'logs' ? 'active' : ''}`} onClick={() => setActiveTab('logs')}>
                <List size={16} />Traffic log
              </button>
              <button type="button" className={`navitem ${activeTab === 'network' ? 'active' : ''}`} onClick={() => setActiveTab('network')}>
                <NetworkIcon size={16} />Network Map
              </button>
            </div>
            
            <p style={{ padding: "0 1rem", fontSize: "11px", color: "var(--text-muted)", margin: "0 0 6px", textTransform: "uppercase", letterSpacing: "0.02em" }}>System</p>
            <div style={{ display: "flex", flexDirection: "column", gap: "2px", padding: "0 8px" }}>
              <button type="button" className={`navitem ${activeTab === 'model' ? 'active' : ''}`} onClick={() => setActiveTab('model')}>
                <BarChart3 size={16} />Model performance
              </button>
              <button type="button" className={`navitem ${activeTab === 'admin' ? 'active' : ''}`} onClick={() => setActiveTab('admin')}>
                <SettingsIcon size={16} />Admin
              </button>
            </div>
          </div>

          {/* Main Content Area */}
          <div style={{ flex: 1, padding: "1.25rem", minWidth: 0, overflowY: "auto", background: "var(--bg-base)" }}>
            {activeTab === 'overview' && <Overview stats={stats} packets={livePackets} alerts={liveAlerts} modelInfo={modelInfo} />}
            {activeTab === 'alerts' && <Alerts alerts={liveAlerts} onClearAlerts={handleClearAlerts} />}
            {activeTab === 'logs' && <Logs packets={livePackets} />}
            {activeTab === 'network' && <Network packets={livePackets} />}
            {activeTab === 'model' && <Detections modelInfo={modelInfo} />}
            {activeTab === 'admin' && <Settings modelInfo={modelInfo} />}
          </div>
        </div>
      </div>
    </div>
  );
}

