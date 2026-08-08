import React, { useState } from 'react';
import { Search, Trash2, AlertTriangle, ShieldAlert, Filter } from 'lucide-react';

export default function Alerts({ alerts = [], onClearAlerts }) {
  const [selectedSev, setSelectedSev] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const getBadgeStyle = (sev) => {
    const s = (sev || 'High').toLowerCase();
    if (s === 'critical') {
      return { bg: 'var(--bg-danger)', text: 'var(--text-danger)', border: 'rgba(239, 68, 68, 0.4)' };
    } else if (s === 'high') {
      return { bg: 'rgba(239, 68, 68, 0.1)', text: 'var(--text-danger)', border: 'rgba(239, 68, 68, 0.25)' };
    } else if (s === 'medium') {
      return { bg: 'var(--bg-warning)', text: 'var(--text-warning)', border: 'rgba(245, 158, 11, 0.3)' };
    } else {
      return { bg: 'var(--surface-3)', text: 'var(--text-secondary)', border: 'var(--border)' };
    }
  };

  const criticalCount = alerts.filter(a => (a.severity || '').toLowerCase() === 'critical').length;
  const highCount = alerts.filter(a => (a.severity || '').toLowerCase() === 'high').length;
  const mediumCount = alerts.filter(a => (a.severity || '').toLowerCase() === 'medium').length;
  const lowCount = alerts.filter(a => (a.severity || '').toLowerCase() === 'low').length;

  const filteredAlerts = alerts.filter(alert => {
    const matchSev = selectedSev === 'ALL' || (alert.severity || '').toUpperCase() === selectedSev;
    const q = searchQuery.toLowerCase();
    const matchQuery = !q || 
      (alert.type || '').toLowerCase().includes(q) || 
      (alert.srcIp || '').toLowerCase().includes(q) || 
      (alert.destIp || '').toLowerCase().includes(q) ||
      (alert.id || '').toLowerCase().includes(q);
    return matchSev && matchQuery;
  });

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <div>
          <p style={{ fontSize: "16px", fontWeight: "600", margin: "0 0 2px", color: "var(--text-main)" }}>Live Security Threat Alerts</p>
          <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: 0 }}>Streaming real-time incident reports from AI anomaly detector</p>
        </div>
        {alerts.length > 0 && (
          <button 
            onClick={onClearAlerts}
            className="action-btn action-btn-danger"
          >
            <Trash2 size={14} /> Clear Active Alerts
          </button>
        )}
      </div>

      {/* Severity Counters Bar */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "10px", marginBottom: "16px" }}>
        <div onClick={() => setSelectedSev('ALL')} style={{ cursor: "pointer", background: "var(--surface-1)", padding: "10px 14px", borderRadius: "10px", border: selectedSev === 'ALL' ? "1px solid var(--text-accent)" : "1px solid var(--border)" }}>
          <span style={{ fontSize: "11px", color: "var(--text-secondary)", fontWeight: "500" }}>TOTAL ALERTS</span>
          <p style={{ fontSize: "20px", fontWeight: "700", margin: "2px 0 0", color: "var(--text-main)" }}>{alerts.length}</p>
        </div>
        <div onClick={() => setSelectedSev('CRITICAL')} style={{ cursor: "pointer", background: "var(--surface-1)", padding: "10px 14px", borderRadius: "10px", border: selectedSev === 'CRITICAL' ? "1px solid var(--text-danger)" : "1px solid var(--border)" }}>
          <span style={{ fontSize: "11px", color: "var(--text-danger)", fontWeight: "500" }}>CRITICAL</span>
          <p style={{ fontSize: "20px", fontWeight: "700", margin: "2px 0 0", color: "var(--text-danger)" }}>{criticalCount}</p>
        </div>
        <div onClick={() => setSelectedSev('HIGH')} style={{ cursor: "pointer", background: "var(--surface-1)", padding: "10px 14px", borderRadius: "10px", border: selectedSev === 'HIGH' ? "1px solid var(--text-danger)" : "1px solid var(--border)" }}>
          <span style={{ fontSize: "11px", color: "var(--text-danger)", fontWeight: "500" }}>HIGH</span>
          <p style={{ fontSize: "20px", fontWeight: "700", margin: "2px 0 0", color: "var(--text-danger)" }}>{highCount}</p>
        </div>
        <div onClick={() => setSelectedSev('MEDIUM')} style={{ cursor: "pointer", background: "var(--surface-1)", padding: "10px 14px", borderRadius: "10px", border: selectedSev === 'MEDIUM' ? "1px solid var(--text-warning)" : "1px solid var(--border)" }}>
          <span style={{ fontSize: "11px", color: "var(--text-warning)", fontWeight: "500" }}>MEDIUM</span>
          <p style={{ fontSize: "20px", fontWeight: "700", margin: "2px 0 0", color: "var(--text-warning)" }}>{mediumCount}</p>
        </div>
        <div onClick={() => setSelectedSev('LOW')} style={{ cursor: "pointer", background: "var(--surface-1)", padding: "10px 14px", borderRadius: "10px", border: selectedSev === 'LOW' ? "1px solid var(--text-secondary)" : "1px solid var(--border)" }}>
          <span style={{ fontSize: "11px", color: "var(--text-secondary)", fontWeight: "500" }}>LOW</span>
          <p style={{ fontSize: "20px", fontWeight: "700", margin: "2px 0 0", color: "var(--text-secondary)" }}>{lowCount}</p>
        </div>
      </div>

      {/* Control Bar: Filter Tabs + Search Bar */}
      <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", gap: "12px", marginBottom: "16px", background: "var(--surface-1)", padding: "10px 14px", borderRadius: "12px", border: "1px solid var(--border)" }}>
        <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
          <Filter size={14} color="var(--text-secondary)" style={{ marginRight: "4px" }} />
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <button
              key={sev}
              onClick={() => setSelectedSev(sev)}
              className={`filter-btn ${selectedSev === sev ? 'active' : ''}`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div style={{ position: "relative", minWidth: "240px" }}>
          <Search size={14} color="var(--text-secondary)" style={{ position: "absolute", left: "10px", top: "50%", transform: "translateY(-50%)" }} />
          <input
            type="text"
            placeholder="Search IP, attack type..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: "100%",
              padding: "7px 10px 7px 32px",
              borderRadius: "8px",
              border: "1px solid var(--border)",
              background: "var(--bg-base)",
              color: "var(--text-main)",
              fontSize: "12px",
              outline: "none"
            }}
          />
        </div>
      </div>

      {/* Alerts Feed */}
      <div className="card-anim" style={{ display: "flex", flexDirection: "column", gap: "10px", background: "var(--surface-1)", padding: "1.25rem", borderRadius: "12px", border: "1px solid var(--border)" }}>
        {filteredAlerts.map((alert, i) => {
          const style = getBadgeStyle(alert.severity);
          return (
            <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 18px", background: style.bg, borderRadius: "10px", border: `1px solid ${style.border}`, transition: "transform 0.15s ease" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <ShieldAlert size={20} color={style.text} />
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{ fontSize: "14px", fontWeight: "600", color: "var(--text-main)" }}>{alert.type}</span>
                    <span style={{ fontSize: "11px", fontFamily: "monospace", background: "rgba(0,0,0,0.15)", padding: "2px 6px", borderRadius: "4px", color: "var(--text-muted)" }}>{alert.id}</span>
                  </div>
                  <span style={{ fontSize: "12px", color: "var(--text-secondary)", fontFamily: "monospace" }}>
                    {alert.srcIp} &rarr; {alert.destIp}
                  </span>
                </div>
              </div>
              <div style={{ textAlign: "right" }}>
                <span style={{ fontSize: "11px", fontWeight: "700", color: style.text, textTransform: "uppercase", padding: "3px 8px", borderRadius: "6px", background: "rgba(0,0,0,0.15)", display: "inline-block", marginBottom: "4px" }}>
                  {alert.severity || 'HIGH'}
                </span>
                <p style={{ fontSize: "11px", color: "var(--text-muted)", margin: 0 }}>{alert.time}</p>
              </div>
            </div>
          );
        })}
        {filteredAlerts.length === 0 && (
          <div style={{ padding: "32px 16px", background: "var(--surface-1)", borderRadius: "var(--radius)", textAlign: "center" }}>
            <AlertTriangle size={24} color="var(--text-secondary)" style={{ marginBottom: "8px" }} />
            <p style={{ fontSize: "14px", color: "var(--text-main)", fontWeight: "500", margin: "0 0 4px" }}>No alerts matching criteria</p>
            <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: 0 }}>All network traffic flows are currently within normal baseline parameters.</p>
          </div>
        )}
      </div>
    </div>
  );
}

