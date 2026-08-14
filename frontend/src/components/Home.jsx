import React, { useState, useRef, useEffect } from "react";
import Overview from "../pages/Overview";
import Alerts from "../pages/Alerts";
import Detections from "../pages/Detections";
import Logs from "../pages/Logs";
import Settings from "../pages/Settings";
import Intel from "../pages/Intel";
import Reports from "../pages/Reports";
import Rules from "../pages/Rules";
import Integrations from "../pages/Integrations";

import { io } from "socket.io-client";

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';

export default function Home({ user, onLogout, theme, toggleTheme }) {
  const [activeTab, setActiveTabState] = useState(() => {
    return window.location.hash.replace('#', '') || 'overview';
  });

  const setActiveTab = (tab) => {
    window.location.hash = tab;
  };

  useEffect(() => {
    const handleHashChange = () => {
      setActiveTabState(window.location.hash.replace('#', '') || 'overview');
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);
  const [livePackets, setLivePackets] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [toasts, setToasts] = useState([]);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  useEffect(() => {
    const handleToast = (e) => {
      const id = Date.now() + Math.random();
      setToasts(prev => [...prev, { id, ...e.detail }]);
      setTimeout(() => {
        setToasts(prev => prev.filter(t => t.id !== id));
      }, 5000);
    };
    window.addEventListener('toast', handleToast);
    return () => window.removeEventListener('toast', handleToast);
  }, []);
  const [stats, setStats] = useState({
    totalAnalyzed: 0,
    threatsFound: 0,
    blocked: 0,
    monitoredHosts: 0
  });
  const [modelInfo, setModelInfo] = useState({});
  const alertCounterRef = useRef(0);

  useEffect(() => {
    if ("Notification" in window) {
      Notification.requestPermission();
    }
    fetch(`${BACKEND_URL}/api/stats`)
      .then(res => res.json())
      .then(data => {
        if (data) {
          setStats(s => ({ 
            ...s, 
            threatsFound: data.threatsFound || 0,
            totalAnalyzed: data.totalAnalyzed || 0,
            monitoredHosts: data.monitoredHosts || 0
          }));
          alertCounterRef.current = data.threatsFound || 0;
        }
      })
      .catch(err => console.error(err));

    fetch(`${BACKEND_URL}/api/logs`)
      .then(res => res.json())
      .then(data => {
        if (data && Array.isArray(data)) {
          setLivePackets(data.map(p => ({
            ...p,
            time: new Date(p.time)
          })));
        }
      })
      .catch(err => console.error(err));

    fetch(`${BACKEND_URL}/api/alerts`)
      .then(res => res.json())
      .then(data => {
        if (data && Array.isArray(data)) {
          setLiveAlerts(data);
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

      setLivePackets(prev => [newPacket, ...prev].slice(0, 50));

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

        if ("Notification" in window && Notification.permission === "granted") {
          new Notification("Threat Detected: " + attackType, {
            body: `Severity: ${severity}\nSource: ${data.src}`,
          });
        }

        const newAlert = {
          id: formattedId,
          time: new Date(data.timestamp).toLocaleString(),
          type: attackType,
          severity: severity,
          srcIp: data.src,
          destIp: data.dst,
          sport: data.sport || 'N/A',
          dport: data.dport || 'N/A',
          proto: data.proto || 'Unknown',
          flags: data.flags || '...',
          packets: data.num_packets || 'Unknown',
        };
        setLiveAlerts(prev => [newAlert, ...prev].slice(0, 100));
      }
    });

    fetch(`${BACKEND_URL}/api/model_info`)
      .then(res => res.json())
      .then(data => setModelInfo(data))
      .catch(err => console.error(err));

    return () => socket.disconnect();
  }, []);

  const markAlertAsRead = (id) => {
    setLiveAlerts(prev => prev.map(a => a.id === id ? { ...a, isRead: true } : a));
  };

  const activeAlertsCount = liveAlerts.filter(a => !a.isRead).length;
  const userName = user ? `${user.firstName} ${user.lastName}` : 'Admin User';
  const userInitials = user?.firstName?.[0] || 'A';
  const userRole = user?.role || 'Security Analyst';

  return (
    <div className="shell">
      {/* Sidebar */}
      <aside className={`sidebar ${!isSidebarOpen ? 'collapsed' : ''}`}>
        <div className="brand">
          <div className="brand-mark"><svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 6v6c0 5.2 3.6 9.9 9 11 5.4-1.1 9-5.8 9-11V6l-9-4z" stroke="#0A0D14" strokeWidth="1.9"/></svg></div>
          <div className="brand-text">NIDS console<span>XGB_ENGINE // V1</span></div>
        </div>

        <div className="health-card">
          <div className="health-top"><span className="health-label">Network health</span><span className="health-val">84%</span></div>
          <div className="health-bar"><div className="health-fill"></div></div>
        </div>

        <div className="nav-label">Monitor</div>
        <div className={`nav-item ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
          <span className="nav-left"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>Overview</span>
        </div>
        <div className={`nav-item ${activeTab === 'alerts' ? 'active' : ''}`} onClick={() => setActiveTab('alerts')}>
          <span className="nav-left"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3a5 5 0 00-5 5v3.5L5 15h14l-2-3.5V8a5 5 0 00-5-5z"/><path d="M10 18a2 2 0 004 0"/></svg>Live alerts</span>
          <span className="nav-badge">{activeAlertsCount}</span>
        </div>
        <div className={`nav-item ${activeTab === 'traffic' ? 'active' : ''}`} onClick={() => setActiveTab('traffic')}>
          <span className="nav-left"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><line x1="4" y1="7" x2="20" y2="7"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="17" x2="14" y2="17"/></svg>Traffic log</span>
        </div>

        <div className="nav-label">Analyze</div>
        <div className={`nav-item ${activeTab === 'intel' ? 'active' : ''}`} onClick={() => setActiveTab('intel')}>
          <span className="nav-left"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="0.7" fill="currentColor"/></svg>Threat intel</span>
          <span className="nav-badge" style={{background: "var(--warn-dim)", color: "var(--warn)"}}>18</span>
        </div>
        <div className={`nav-item ${activeTab === 'reports' ? 'active' : ''}`} onClick={() => setActiveTab('reports')}>
          <span className="nav-left"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z"/><path d="M14 3v5h5"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="13" y2="17"/></svg>Reports</span>
        </div>

        <div className="nav-label">System</div>
        <div className={`nav-item ${activeTab === 'rules' ? 'active' : ''}`} onClick={() => setActiveTab('rules')}>
          <span className="nav-left"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M9 12l2 2 4-4"/><path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z"/></svg>Detection rules</span>
        </div>
        <div className={`nav-item ${activeTab === 'model' ? 'active' : ''}`} onClick={() => setActiveTab('model')}>
          <span className="nav-left"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><line x1="5" y1="20" x2="5" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="19" y1="20" x2="19" y2="14"/></svg>Model performance</span>
        </div>
        <div className={`nav-item ${activeTab === 'integrations' ? 'active' : ''}`} onClick={() => setActiveTab('integrations')}>
          <span className="nav-left"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M9 3H5a2 2 0 00-2 2v4M15 3h4a2 2 0 012 2v4M9 21H5a2 2 0 01-2-2v-4M15 21h4a2 2 0 002-2v-4"/></svg>Integrations</span>
        </div>
        <div className={`nav-item ${activeTab === 'admin' ? 'active' : ''}`} onClick={() => setActiveTab('admin')}>
          <span className="nav-left"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.9l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.9-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1-1.6 1.7 1.7 0 00-1.9.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.9 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1 1.7 1.7 0 00-.3-1.9l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.9.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.9-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.9V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z"/></svg>Admin</span>
        </div>

        <div className="sidebar-foot">nids.db · IDS2025.csv<br/>{stats.totalAnalyzed.toLocaleString()} flows indexed</div>
      </aside>

      {/* Main / topbar */}
      <div className="main">
        <div className="topbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div className="icon-btn" onClick={() => setIsSidebarOpen(!isSidebarOpen)} title="Toggle sidebar">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            </div>
            <div className="status-pill"><span className="dot"></span>Sniffer running</div>
          </div>
          <div className="topbar-right">
            <div className="search-box">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#4E5872" strokeWidth="2"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.6" y2="16.6"/></svg>
              <input placeholder="Search IP, host, alert..." />
            </div>
            <div className="icon-btn" onClick={toggleTheme} title="Toggle theme">
              {theme === 'light' ? (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>
              ) : (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
              )}
            </div>
            <div className="icon-btn" style={{ position: 'relative' }} onClick={() => setShowNotifications(!showNotifications)}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 01-3.4 0"/></svg>
              {activeAlertsCount > 0 && <span className="ping"></span>}              {showNotifications && (
                <div className="notifications-dropdown" style={{
                  position: 'absolute', top: '48px', right: '-8px', width: '380px',
                  background: 'var(--bg-panel)', border: '1px solid var(--border-soft)',
                  borderRadius: '12px', boxShadow: '0 12px 40px rgba(0,0,0,0.4)',
                  overflow: 'hidden', zIndex: 100, display: 'flex', flexDirection: 'column'
                }}>
                  <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-soft)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ fontSize: '14px', fontWeight: '600' }}>Recent Alerts</div>
                    {activeAlertsCount > 0 && <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--admin-red)', background: 'rgba(242,85,90,0.1)', padding: '3px 8px', borderRadius: '5px' }}>{activeAlertsCount} New</div>}
                  </div>
                  <div className="notifications-list" style={{ maxHeight: '380px', overflowY: 'auto' }}>
                    {liveAlerts.length === 0 ? (
                      <div style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-faint)', fontSize: '13px' }}>No new alerts</div>
                    ) : (
                      liveAlerts.slice(0, 5).map((alert, i) => {
                        const type = alert.type || alert.threat_class || 'Anomaly Detected';
                        const srcIp = alert.srcIp || alert.src_ip || 'Unknown';
                        const dstIp = alert.destIp || alert.dst_ip || 'Unknown';
                        const sport = alert.sport || 'N/A';
                        const dport = alert.dport || 'N/A';
                        const flags = alert.flags || '...';
                        const sev = alert.severity || alert.sev || 'Low';
                        
                        let timeStr = alert.time || alert.timestamp || new Date().toISOString();
                        try {
                          const dt = new Date(timeStr);
                          timeStr = dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                        } catch(e) {}
                        
                        let colorVar = '--admin-amber';
                        if (sev.toLowerCase() === 'critical' || sev.toLowerCase() === 'high') colorVar = '--admin-red';
                        else if (sev.toLowerCase() === 'low') colorVar = '--admin-blue';
                        
                        return (
                          <div key={i} style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-soft)', display: 'flex', gap: '14px', alignItems: 'flex-start', cursor: 'pointer', transition: 'background 0.2s' }} onMouseEnter={(e)=>e.currentTarget.style.background='var(--bg-hover)'} onMouseLeave={(e)=>e.currentTarget.style.background='transparent'} onClick={() => { setActiveTab('alerts'); setShowNotifications(false); }}>
                            <div style={{ width: '32px', height: '32px', borderRadius: '8px', flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: `rgba(var(${colorVar}-rgb, 242,85,90), 0.1)`, color: `var(${colorVar})` }}>
                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                            </div>
                            <div style={{ flex: 1 }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                                <div style={{ fontSize: '13.5px', fontWeight: '600', color: `var(${colorVar})` }}>{type}</div>
                                <div style={{ fontSize: '11px', color: 'var(--text-faint)', fontFamily: 'var(--font-mono)' }}>{timeStr}</div>
                              </div>
                              <div style={{ fontSize: '12px', color: 'var(--text-primary)', marginBottom: '4px', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span>{srcIp}<span style={{color: 'var(--text-dim)'}}>:{sport}</span></span>
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--text-faint)" strokeWidth="2"><path d="M5 12h14"/><path d="M12 5l7 7-7 7"/></svg>
                                <span>{dstIp}<span style={{color: 'var(--text-dim)'}}>:{dport}</span></span>
                              </div>
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                  <div style={{ padding: '14px', textAlign: 'center', borderTop: '1px solid var(--border-soft)', fontSize: '12.5px', fontWeight: '600', color: 'var(--admin-green)', cursor: 'pointer', transition: 'color 0.2s' }} onMouseEnter={(e)=>e.target.style.color='#4ade80'} onMouseLeave={(e)=>e.target.style.color='var(--admin-green)'} onClick={() => { setActiveTab('alerts'); setShowNotifications(false); }}>
                    View all alerts
                  </div>
                </div>
              )}
            </div>
            <div className="user-chip-wrapper" style={{ position: 'relative' }}>
              <div className="user-chip" onClick={() => setShowProfileMenu(!showProfileMenu)}>
                <div className="avatar">{userInitials}</div>
                <div><div className="user-name">{userName}</div><div className="user-role">{userRole}</div></div>
              </div>
              {showProfileMenu && (
                <div className="notifications-dropdown" style={{ width: '200px', top: '48px', right: '0' }}>
                  <div className="notification-item" onClick={onLogout} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/></svg>
                    <span>Logout</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="content">
          {activeTab === 'overview' && <Overview stats={stats} packets={livePackets} alerts={liveAlerts} modelInfo={modelInfo} />}
          {activeTab === 'alerts' && <Alerts alerts={liveAlerts} markAlertAsRead={markAlertAsRead} />}
          {activeTab === 'traffic' && <Logs packets={livePackets} />}
          {activeTab === 'intel' && <Intel />}
          {activeTab === 'reports' && <Reports />}
          {activeTab === 'rules' && <Rules />}
          {activeTab === 'model' && <Detections modelInfo={modelInfo} alerts={liveAlerts} />}
          {activeTab === 'integrations' && <Integrations />}
          {activeTab === 'admin' && <Settings modelInfo={modelInfo} />}
        </div>
      </div>
      
      {/* Global Toast Container */}
      <div style={{ position: 'fixed', bottom: '24px', right: '24px', display: 'flex', flexDirection: 'column', gap: '10px', zIndex: 9999 }}>
        {toasts.map(t => (
          <div key={t.id} style={{ 
            background: 'var(--bg-panel)', 
            border: `1px solid ${t.type === 'error' ? 'var(--critical)' : t.type === 'warning' ? 'var(--warn)' : 'var(--signal)'}`, 
            borderLeft: `4px solid ${t.type === 'error' ? 'var(--critical)' : t.type === 'warning' ? 'var(--warn)' : 'var(--signal)'}`,
            padding: '16px 20px', 
            borderRadius: '8px', 
            boxShadow: '0 10px 30px rgba(0,0,0,0.5)', 
            display: 'flex', 
            alignItems: 'center', 
            gap: '12px',
            animation: 'slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
            minWidth: '300px',
            color: 'var(--text-primary)'
          }}>
            {t.type === 'error' ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--critical)" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            ) : t.type === 'warning' ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--signal)" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            )}
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '14px', fontWeight: '600' }}>{t.type === 'error' ? 'Error' : t.type === 'warning' ? 'Warning' : 'Success'}</div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>{t.message}</div>
            </div>
            <button onClick={() => setToasts(prev => prev.filter(toast => toast.id !== t.id))} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '4px' }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
        ))}
      </div>
      
    </div>
  );
}
