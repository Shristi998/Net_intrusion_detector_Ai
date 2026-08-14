import React, { useState, useEffect } from "react";

export default function Settings({ modelInfo }) {
  const [blockedIps, setBlockedIps] = useState([]);
  const [showBlockModal, setShowBlockModal] = useState(false);
  const [ipToBlock, setIpToBlock] = useState("");
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
      setBlockedIps(data);
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
        body: JSON.stringify({ ip: ipToBlock.trim() })
      });
      const data = await res.json();
      if (data.success) {
        setShowBlockModal(false);
        setIpToBlock("");
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
      {showBlockModal && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 999, backdropFilter: 'blur(3px)' }}>
          <div className="admin-card" style={{ width: '400px', margin: 0, boxShadow: '0 10px 40px rgba(0,0,0,0.5)' }}>
            <div className="panel-head">
              <div>
                <div className="panel-title">Block IP Address</div>
                <div className="panel-sub">Add a new firewall rule</div>
              </div>
              <button onClick={() => setShowBlockModal(false)} style={{ background: 'transparent', border: 'none', color: 'var(--text-faint)', cursor: 'pointer' }}>
                <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" strokeWidth="2" fill="none"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            <div style={{ padding: '22px' }}>
              <div className="config-field">
                <label>IP Address</label>
                <input 
                  type="text" 
                  placeholder="e.g. 192.168.1.50" 
                  value={ipToBlock} 
                  onChange={(e) => setIpToBlock(e.target.value)} 
                  autoFocus
                />
              </div>
              {blockError && <div style={{ color: 'var(--admin-red)', fontSize: '12px', marginTop: '10px', fontFamily: 'var(--font-mono)' }}>{blockError}</div>}
            </div>
            <div className="config-footer" style={{ justifyContent: 'flex-end', gap: '10px' }}>
              <button className="btn" onClick={() => setShowBlockModal(false)} disabled={isBlocking}>Cancel</button>
              <button className="btn primary" onClick={submitBlockIp} disabled={isBlocking} style={{ background: 'linear-gradient(180deg, #f2555a, #d43b3f)', borderColor: '#f2555a' }}>
                {isBlocking ? 'Blocking...' : 'Confirm Block'}
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="breadcrumb">SYSTEM <span className="sep">/</span> <span className="current">ADMIN</span></div>
      <h1 className="admin-page-title">Admin</h1>

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

      <div className="section-label">Firewall &amp; blocking</div>
      <div className="admin-card">
        <div className="panel-head">
          <div>
            <div className="panel-title">Blocked IPs</div>
            <div className="panel-sub">Manage blocked IPs</div>
          </div>
          <button className="btn primary" onClick={() => { setIpToBlock(""); setBlockError(""); setShowBlockModal(true); }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Block an IP
          </button>
        </div>
        <table className="admin-table">
          <thead>
            <tr><th>IP address</th><th>Blocked at</th><th style={{textAlign: 'right'}}>Action</th></tr>
          </thead>
          <tbody>
            {blockedIps.map(b => (
              <tr key={b.ip}>
                <td className="ip-mono" style={{color: 'var(--admin-red)'}}>{b.ip}</td>
                <td>{new Date(b.blocked_at).toLocaleString()}</td>
                <td style={{textAlign: 'right'}}>
                  <span className="action-block" onClick={() => handleUnblock(b.ip)}>Unblock</span>
                </td>
              </tr>
            ))}
            {blockedIps.length === 0 && (
              <tr className="empty-row">
                <td colSpan="3">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                  No IPs currently blocked
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="section-label">Sniffer configuration</div>
      <div className="admin-card">
        <div className="panel-head">
          <div>
            <div className="panel-title">Capture settings</div>
            <div className="panel-sub">Interface, filters &amp; runtime controls</div>
          </div>
          <div style={{display: 'flex', gap: '10px'}}>
            <button className="btn" onClick={handleRestartSniffer}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>Restart sniffer</button>
            <button className="btn" style={{color: '#ff9599', borderColor: '#3a2226'}} onClick={handleStopSniffer}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="6" y="6" width="12" height="12" rx="1.5"/></svg>Stop</button>
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
          <button className="btn primary" style={{padding: '8px 18px'}}>Save changes</button>
        </div>
      </div>

      <div className="section-label">Detection model</div>
      <div className="admin-card">
        <div className="panel-head">
          <div>
            <div className="panel-title">Retraining</div>
          </div>
          <button className="btn primary" onClick={handleRetrainModel}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>Retrain now</button>
        </div>
        <div className="admin-stat-grid" style={{gridTemplateColumns: 'repeat(3, 1fr)'}}>
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
          <thead><tr><th>Version</th><th>Trained</th><th>Accuracy</th><th style={{textAlign: 'right'}}>Status</th></tr></thead>
          <tbody>
            <tr>
              <td className="ip-mono">v1</td>
              <td>Aug 6, 2026 · 03:12 UTC</td>
              <td className="ip-mono mint-text">97.8%</td>
              <td style={{textAlign: 'right'}}><span className="status-tag"><span className="dot"></span>active</span></td>
            </tr>
            <tr>
              <td className="ip-mono">v0.9</td>
              <td>Jul 30, 2026 · 03:04 UTC</td>
              <td className="ip-mono">97.4%</td>
              <td style={{textAlign: 'right'}}><span className="tag-neutral">archived</span></td>
            </tr>
            <tr>
              <td className="ip-mono">v0.8</td>
              <td>Jul 23, 2026 · 03:11 UTC</td>
              <td className="ip-mono">96.1%</td>
              <td style={{textAlign: 'right'}}><span className="tag-neutral">archived</span></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="section-label">User access</div>
      <div className="admin-card">
        <div className="panel-head">
          <div>
            <div className="panel-title">Team &amp; permissions</div>
            <div className="panel-sub">4 members</div>
          </div>
          <button className="btn primary"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>Invite member</button>
        </div>
        <table className="admin-table">
          <thead><tr><th>Member</th><th>Role</th><th>2FA</th><th style={{textAlign: 'right'}}>Last active</th></tr></thead>
          <tbody>
            <tr>
              <td>
                <div className="member">
                  <div className="avatar small">RP</div>
                  <div><div className="member-name">Rajish Pandey</div><div className="member-email">rajish@secops.io</div></div>
                </div>
              </td>
              <td><span className="role-tag role-admin">Admin</span></td>
              <td><span className="status-tag"><span className="dot"></span>enabled</span></td>
              <td style={{textAlign: 'right'}} className="ip-mono muted">now</td>
            </tr>
            <tr>
              <td>
                <div className="member">
                  <div className="avatar small">SK</div>
                  <div><div className="member-name">Sanya Karki</div><div className="member-email">sanya@secops.io</div></div>
                </div>
              </td>
              <td><span className="role-tag role-analyst">Analyst</span></td>
              <td><span className="status-tag"><span className="dot"></span>enabled</span></td>
              <td style={{textAlign: 'right'}} className="ip-mono muted">2h ago</td>
            </tr>
            <tr>
              <td>
                <div className="member">
                  <div className="avatar small">MT</div>
                  <div><div className="member-name">Manish Thapa</div><div className="member-email">manish@secops.io</div></div>
                </div>
              </td>
              <td><span className="role-tag role-analyst">Analyst</span></td>
              <td><span className="status-tag warn"><span className="dot"></span>disabled</span></td>
              <td style={{textAlign: 'right'}} className="ip-mono muted">3d ago</td>
            </tr>
            <tr>
              <td>
                <div className="member">
                  <div className="avatar small">GB</div>
                  <div><div className="member-name">Gita Bhandari</div><div className="member-email">gita@secops.io</div></div>
                </div>
              </td>
              <td><span className="role-tag role-viewer">Viewer</span></td>
              <td><span className="status-tag"><span className="dot"></span>enabled</span></td>
              <td style={{textAlign: 'right'}} className="ip-mono muted">1w ago</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="section-label">Audit log</div>
      <div className="admin-card" style={{marginBottom: '40px'}}>
        <div className="panel-head">
          <div>
            <div className="panel-title">Recent admin activity</div>
            <div className="panel-sub">Last 24 hours</div>
          </div>
          <button className="btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Export</button>
        </div>
        <div className="log-list">
          <div className="log-row">
            <div className="log-icon mint"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z"/></svg></div>
            <div className="log-body">
              <div><b>Rajish Pandey</b> triggered a manual model retrain</div>
              <div className="log-meta">xgb_nids_engine · v1 → training</div>
            </div>
            <div className="log-time">08:12</div>
          </div>
          <div className="log-row">
            <div className="log-icon red"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg></div>
            <div className="log-body">
              <div><b>Sanya Karki</b> blocked IP <span className="ip-mono">185.212.44.9</span></div>
              <div className="log-meta">Firewall &amp; blocking</div>
            </div>
            <div className="log-time">06:47</div>
          </div>
          <div className="log-row">
            <div className="log-icon amber"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="13"/><circle cx="12" cy="16" r="0.5" fill="currentColor"/></svg></div>
            <div className="log-body">
              <div><b>System</b> disabled 2FA enforcement for <b>Manish Thapa</b> (inactivity)</div>
              <div className="log-meta">User access</div>
            </div>
            <div className="log-time">Yesterday · 22:03</div>
          </div>
          <div className="log-row">
            <div className="log-icon blue"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg></div>
            <div className="log-body">
              <div><b>Rajish Pandey</b> restarted the sniffer on <span className="ip-mono">eth0</span></div>
              <div className="log-meta">Sniffer configuration</div>
            </div>
            <div className="log-time">Yesterday · 19:41</div>
          </div>
        </div>
      </div>
    </div>
  );
}
