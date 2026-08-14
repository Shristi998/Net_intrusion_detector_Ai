import React, { useState, useEffect } from "react";

const formatTimestamp = (ts) => {
  if (!ts) return "Just now";
  try {
    const isoStr = ts.includes(' ') ? ts.replace(' ', 'T') : ts;
    const d = new Date(isoStr);
    return isNaN(d.getTime()) ? ts : d.toLocaleString();
  } catch (e) {
    return ts;
  }
};

export default function Settings({ modelInfo }) {
  const [blockedIps, setBlockedIps] = useState([]);
  const [showBlockModal, setShowBlockModal] = useState(false);
  const [ipToBlock, setIpToBlock] = useState("");
  const [reasonToBlock, setReasonToBlock] = useState("");
  const [blockError, setBlockError] = useState("");
  const [isBlocking, setIsBlocking] = useState(false);

  useEffect(() => {
    fetchBlockedIps();
  }, []);

  const fetchBlockedIps = async () => {
    try {
      const BACKEND_URL = window.location.hostname === 'localhost' ? 'http://localhost:5000' : '';
      const res = await fetch(`${BACKEND_URL}/api/blocked_ips`);
      const data = await res.json();
      if (Array.isArray(data)) {
        setBlockedIps(data);
      }
    } catch (e) {
      console.error("Error fetching blocked IPs", e);
    }
  };

  const handleUnblock = async (ip) => {
    try {
      const BACKEND_URL = window.location.hostname === 'localhost' ? 'http://localhost:5000' : '';
      const res = await fetch(`${BACKEND_URL}/api/unblock_ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      if (data.success) {
        window.dispatchEvent(new CustomEvent('toast', { detail: { message: `Successfully unblocked ${ip}${data.os_unblocked ? ' at OS Firewall level' : ''}.`, type: 'success' } }));
        fetchBlockedIps();
      } else {
        window.dispatchEvent(new CustomEvent('toast', { detail: { message: `Failed to unblock: ${data.error}`, type: 'error' } }));
      }
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { message: "Error unblocking IP. Please check connection.", type: 'error' } }));
    }
  };

  const submitBlockIp = async () => {
    if (!ipToBlock.trim()) {
      setBlockError("Please enter an IP address.");
      return;
    }
    setIsBlocking(true);
    setBlockError("");
    try {
      const BACKEND_URL = window.location.hostname === 'localhost' ? 'http://localhost:5000' : '';
      const res = await fetch(`${BACKEND_URL}/api/block_ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: ipToBlock.trim(),
          reason: reasonToBlock.trim()
        })
      });
      const data = await res.json();
      if (data.success) {
        setShowBlockModal(false);
        setIpToBlock("");
        setReasonToBlock("");
        window.dispatchEvent(new CustomEvent('toast', { detail: { message: `Successfully blocked ${ipToBlock.trim()}${data.os_blocked ? ' at OS Firewall level' : ' at Application level'}.`, type: 'success' } }));
        fetchBlockedIps();
      } else {
        setBlockError(`Failed to block: ${data.error}`);
      }
    } catch (e) {
      setBlockError("Error blocking IP. Please check connection.");
    } finally {
      setIsBlocking(false);
    }
  };

  const handleAction = async (endpoint, successMsg) => {
    try {
      const BACKEND_URL = window.location.hostname === 'localhost' ? 'http://localhost:5000' : '';
      const res = await fetch(`${BACKEND_URL}${endpoint}`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        window.dispatchEvent(new CustomEvent('toast', { detail: { message: successMsg, type: 'success' } }));
      } else {
        window.dispatchEvent(new CustomEvent('toast', { detail: { message: `Action failed: ${data.error}`, type: 'error' } }));
      }
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { message: "Network error. Please check connection.", type: 'error' } }));
    }
  };

  const handleRestartSniffer = () => handleAction('/api/sniffer/restart', 'Restart signal sent to sniffer.');
  const handleStopSniffer = () => handleAction('/api/sniffer/stop', 'Stop signal sent to sniffer.');
  const handleRetrainModel = () => handleAction('/api/model/retrain', 'Model retraining started in the background.');

  return (
    <div className="tab-page active admin-page" id="admin">
      {/* Modal for Blocking IP */}
      {showBlockModal && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 999, backdropFilter: 'blur(3px)' }}>
          <div className="admin-card" style={{ width: '420px', margin: 0, boxShadow: '0 10px 40px rgba(0,0,0,0.5)' }}>
            <div className="panel-head">
              <div>
                <div className="panel-title">Block IP Address</div>
                <div className="panel-sub">Add a new firewall rule to drop traffic</div>
              </div>
              <button onClick={() => setShowBlockModal(false)} style={{ background: 'transparent', border: 'none', color: 'var(--text-faint)', cursor: 'pointer' }}>
                <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" strokeWidth="2" fill="none"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            <form onSubmit={(e) => { e.preventDefault(); submitBlockIp(); }}>
              <div style={{ padding: '22px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div className="config-field">
                  <label>IP Address *</label>
                  <input 
                    id="block-ip-input"
                    type="text" 
                    placeholder="e.g. 192.168.1.50" 
                    value={ipToBlock} 
                    onChange={(e) => setIpToBlock(e.target.value)} 
                    autoFocus
                    required
                  />
                </div>
                <div className="config-field">
                  <label>Reason / Description (Optional)</label>
                  <input 
                    id="block-reason-input"
                    type="text" 
                    placeholder="e.g. Malicious Port Scan detected" 
                    value={reasonToBlock} 
                    onChange={(e) => setReasonToBlock(e.target.value)} 
                  />
                </div>
                {blockError && <div style={{ color: 'var(--admin-red)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>{blockError}</div>}
              </div>
              <div className="config-footer" style={{ justifyContent: 'flex-end', gap: '10px' }}>
                <button type="button" className="btn" onClick={() => setShowBlockModal(false)} disabled={isBlocking}>Cancel</button>
                <button type="submit" className="btn primary" disabled={isBlocking} style={{ background: 'linear-gradient(180deg, #f2555a, #d43b3f)', borderColor: '#f2555a' }}>
                  {isBlocking ? 'Blocking...' : 'Confirm Block'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <div className="breadcrumb">SYSTEM <span className="sep">/</span> <span className="current">ADMIN</span></div>
      <h1 className="admin-page-title">Admin</h1>

      {/* Engine Status Card */}
      <div className="section-label">Engine status</div>
      <div className="admin-card admin-stat-grid">
        <div className="admin-stat">
          <div className="stat-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3"/></svg>
            Active dataset
          </div>
          <div className="stat-value">IDS2025.csv</div>
          <div className="stat-sub">91,703 flows</div>
        </div>
        <div className="admin-stat">
          <div className="stat-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2a4 4 0 014 4v1h1a2 2 0 012 2v9a2 2 0 01-2 2H7a2 2 0 01-2-2v-9a2 2 0 012-2h1V6a4 4 0 014-4z"/></svg>
            Model version
          </div>
          <div className="stat-value">xgb_nids_engine</div>
          <div className="stat-sub">v1</div>
        </div>
        <div className="admin-stat">
          <div className="stat-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15.5 14"/></svg>
            Sniffer status
          </div>
          <span className="status-tag"><span className="dot"></span>running</span>
        </div>
        <div className="admin-stat">
          <div className="stat-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z"/></svg>
            Alert database
          </div>
          <div className="stat-value mint">nids.db</div>
          <div className="stat-sub">connected</div>
        </div>
      </div>

      {/* Firewall & IP Blocking Section */}
      <div className="section-label">Firewall &amp; blocking</div>
      <div className="admin-card">
        <div className="panel-head">
          <div>
            <div className="panel-title">Blocked IPs</div>
            <div className="panel-sub">Manage blocked IPs</div>
          </div>
          <button className="btn primary" onClick={() => { setIpToBlock(""); setReasonToBlock(""); setBlockError(""); setShowBlockModal(true); }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Block an IP
          </button>
        </div>

        {/* Blocked IPs Table */}
        <table className="admin-table">
          <thead>
            <tr>
              <th>IP address</th>
              <th>Reason / Threat</th>
              <th>Status</th>
              <th>Blocked at</th>
              <th style={{ textAlign: 'right' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {blockedIps.map(b => (
              <tr key={b.ip}>
                <td className="ip-mono" style={{ color: 'var(--admin-red)', fontWeight: '600' }}>{b.ip}</td>
                <td>{b.reason || "-"}</td>
                <td>
                  {b.auto_blocked ? (
                    <span className="sev-badge critical" style={{ fontSize: '10px', padding: '2px 7px' }}>AUTO-BLOCKED</span>
                  ) : (
                    <span className="sev-badge medium" style={{ fontSize: '10px', padding: '2px 7px' }}>MANUAL</span>
                  )}
                </td>
                <td className="ip-mono" style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                  {formatTimestamp(b.blocked_at)}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <span className="action-block" onClick={() => handleUnblock(b.ip)}>Unblock</span>
                </td>
              </tr>
            ))}
            {blockedIps.length === 0 && (
              <tr className="empty-row">
                <td colSpan="5">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                  No IPs currently blocked
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Sniffer Configuration Section */}
      <div className="section-label">Sniffer configuration</div>
      <div className="admin-card">
        <div className="panel-head">
          <div>
            <div className="panel-title">Capture settings</div>
            <div className="panel-sub">Interface, filters &amp; runtime controls</div>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button className="btn" onClick={handleRestartSniffer}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>Restart sniffer</button>
            <button className="btn" style={{ color: '#ff9599', borderColor: '#3a2226' }} onClick={handleStopSniffer}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="6" y="6" width="12" height="12" rx="1.5"/></svg>Stop</button>
          </div>
        </div>
        <div className="config-grid">
          <div className="config-field">
            <label>Capture interface</label>
            <select><option>eth0 — primary uplink</option><option>eth1 — DMZ segment</option><option>wlan0</option></select>
          </div>
          <div className="config-field">
            <label>Capture filter (BPF)</label>
            <input type="text" defaultValue="tcp or udp" spellCheck={false} />
          </div>
          <div className="config-field">
            <label>Sample rate</label>
            <select><option>Full capture (100%)</option><option>1 in 10 packets</option><option>1 in 100 packets</option></select>
          </div>
          <div className="config-field">
            <label>Buffer size</label>
            <input type="text" defaultValue="256 MB" spellCheck={false} />
          </div>
        </div>
        <div className="config-footer">
          <span className="hint">Changes apply on next sniffer restart</span>
          <button className="btn primary" style={{ padding: '8px 18px' }}>Save changes</button>
        </div>
      </div>

      {/* Detection Model Section */}
      <div className="section-label">Detection model</div>
      <div className="admin-card">
        <div className="panel-head">
          <div>
            <div className="panel-title">Retraining</div>
          </div>
          <button className="btn primary" onClick={handleRetrainModel}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>Retrain now</button>
        </div>
        <div className="admin-stat-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
          <div className="admin-stat">
            <div className="stat-label">Last trained</div>
            <div className="stat-value">Aug 6, 2026</div>
            <div className="stat-sub">03:12 UTC · 41m runtime</div>
          </div>
          <div className="admin-stat">
            <div className="stat-label">Validation accuracy</div>
            <div className="stat-value mint">97.8%</div>
            <div className="stat-sub">+0.4% vs previous</div>
          </div>
          <div className="admin-stat">
            <div className="stat-label">Next scheduled run</div>
            <div className="stat-value">Aug 13, 2026</div>
            <div className="stat-sub">Weekly · Wed 03:00 UTC</div>
          </div>
        </div>
        <table className="admin-table">
          <thead><tr><th>Version</th><th>Trained</th><th>Accuracy</th><th style={{ textAlign: 'right' }}>Status</th></tr></thead>
          <tbody>
            <tr>
              <td className="ip-mono">v1</td>
              <td>Aug 6, 2026 · 03:12 UTC</td>
              <td className="ip-mono mint-text">97.8%</td>
              <td style={{ textAlign: 'right' }}><span className="status-tag"><span className="dot"></span>active</span></td>
            </tr>
            <tr>
              <td className="ip-mono">v0.9</td>
              <td>Jul 30, 2026 · 03:04 UTC</td>
              <td className="ip-mono">97.4%</td>
              <td style={{ textAlign: 'right' }}><span className="tag-neutral">archived</span></td>
            </tr>
            <tr>
              <td className="ip-mono">v0.8</td>
              <td>Jul 23, 2026 · 03:11 UTC</td>
              <td className="ip-mono">96.1%</td>
              <td style={{ textAlign: 'right' }}><span className="tag-neutral">archived</span></td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* User Access Section */}
      <div className="section-label">User access</div>
      <div className="admin-card">
        <div className="panel-head">
          <div>
            <div className="panel-title">Team &amp; permissions</div>
            <div className="panel-sub">4 members</div>
          </div>
          <button className="btn primary"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>Invite member</button>
        </div>
      </div>
    </div>
  );
}
