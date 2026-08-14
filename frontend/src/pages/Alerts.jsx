import React, { useState } from "react";

export default function Alerts({ alerts, markAlertAsRead }) {
  const [filter, setFilter] = useState('All');
  const [expandedId, setExpandedId] = useState(null);

  const dosCount = alerts.filter(a => a.type === 'Dos/DDos' || a.type === 'Dos/DDoS').length;
  const portScanCount = alerts.filter(a => a.type === 'PortScan').length;
  const bruteCount = alerts.filter(a => a.type === 'Brute Force').length;
  const webCount = alerts.filter(a => a.type === 'Web Attack').length;
  const otherCount = alerts.length - (dosCount + portScanCount + bruteCount + webCount);

  const filteredAlerts = alerts.filter(a => {
    if (filter === 'All') return true;
    if (filter === 'Dos/DDoS') return a.type === 'Dos/DDos' || a.type === 'Dos/DDoS';
    if (filter === 'PortScan') return a.type === 'PortScan';
    if (filter === 'Brute Force') return a.type === 'Brute Force';
    if (filter === 'Web Attack') return a.type === 'Web Attack';
    if (filter === 'Other') return !['Dos/DDos', 'Dos/DDoS', 'PortScan', 'Brute Force', 'Web Attack'].includes(a.type);
    return true;
  });

  const handleAlertClick = (id) => {
    if (markAlertAsRead) markAlertAsRead(id);
    setExpandedId(prev => prev === id ? null : id);
  };

  const handleBlockIp = async (ip) => {
    try {
      const BACKEND_URL = window.location.hostname === 'localhost' ? 'http://localhost:5000' : '';
      const res = await fetch(`${BACKEND_URL}/api/block_ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      if (data.success) {
        window.dispatchEvent(new CustomEvent('toast', { detail: { message: `Successfully blocked ${ip}${data.os_blocked ? ' at OS Firewall level' : ' at Application level'}.`, type: 'success' } }));
      } else {
        window.dispatchEvent(new CustomEvent('toast', { detail: { message: `Failed to block: ${data.error}`, type: 'error' } }));
      }
    } catch (e) {
      window.dispatchEvent(new CustomEvent('toast', { detail: { message: "Error blocking IP. Please check connection.", type: 'error' } }));
    }
  };

  return (
    <div className="tab-page active" id="alerts">
      <div className="page-head"><div><div className="eyebrow">MONITOR / LIVE ALERTS</div><div className="page-title">Live alerts</div></div></div>
      <div className="filter-row">
        <div className={`chip ${filter === 'All' ? 'active' : ''}`} onClick={() => setFilter('All')} style={{cursor: 'pointer'}}>All · {alerts.length}</div>
        <div className={`chip ${filter === 'Dos/DDoS' ? 'active' : ''}`} onClick={() => setFilter('Dos/DDoS')} style={{cursor: 'pointer'}}>Dos/DDoS · {dosCount}</div>
        <div className={`chip ${filter === 'PortScan' ? 'active' : ''}`} onClick={() => setFilter('PortScan')} style={{cursor: 'pointer'}}>PortScan · {portScanCount}</div>
        <div className={`chip ${filter === 'Brute Force' ? 'active' : ''}`} onClick={() => setFilter('Brute Force')} style={{cursor: 'pointer'}}>Brute Force · {bruteCount}</div>
        <div className={`chip ${filter === 'Web Attack' ? 'active' : ''}`} onClick={() => setFilter('Web Attack')} style={{cursor: 'pointer'}}>Web Attack · {webCount}</div>
        <div className={`chip ${filter === 'Other' ? 'active' : ''}`} onClick={() => setFilter('Other')} style={{cursor: 'pointer'}}>Other · {otherCount}</div>
      </div>
      <div className="alerts-table-container">
        <table className="alerts-table">
          <thead>
            <tr>
              <th>Alert ID</th>
              <th>Timestamp</th>
              <th>Severity</th>
              <th>Threat type</th>
              <th>Source IP</th>
              <th>Destination IP</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.map((a, i) => {
              const sev = a.severity ? a.severity.toLowerCase() : 'high';
              const timeStr = (a.time || '').split(' ')[1] || a.time;
              
              return (
                <React.Fragment key={a.id || i}>
                  <tr 
                    className={a.isRead ? 'read' : ''} 
                    style={{ cursor: 'pointer', borderBottom: expandedId === a.id ? 'none' : '' }}
                    onClick={() => handleAlertClick(a.id)}
                  >
                    <td className="ip-mono" style={{ color: 'var(--text-secondary)' }}>{a.id || `ALT-${Math.floor(4600 - i)}`}</td>
                    <td className="ip-mono">{timeStr}</td>
                    <td>
                      <span className={`sev-badge ${sev}`}>
                        {sev.charAt(0).toUpperCase() + sev.slice(1)}
                      </span>
                    </td>
                    <td style={{ fontWeight: '500' }}>{a.type}</td>
                    <td className="ip-mono">{a.srcIp}</td>
                    <td className="ip-mono">{a.destIp}</td>
                  </tr>
                  
                  {expandedId === a.id && (
                    <tr style={{ backgroundColor: 'rgba(0,0,0,0.2)' }}>
                      <td colSpan="6" style={{ padding: 0 }}>
                        <div style={{ padding: '20px 24px', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: '20px', fontSize: '13px', borderBottom: '1px solid var(--border)' }}>
                          <div>
                            <div style={{ color: 'var(--text-tertiary)', marginBottom: '6px' }}>Source Port</div>
                            <div className="ip-mono">{a.sport}</div>
                          </div>
                          <div>
                            <div style={{ color: 'var(--text-tertiary)', marginBottom: '6px' }}>Destination Port</div>
                            <div className="ip-mono">{a.dport}</div>
                          </div>
                          <div>
                            <div style={{ color: 'var(--text-tertiary)', marginBottom: '6px' }}>Protocol</div>
                            <div>{a.proto}</div>
                          </div>
                          <div>
                            <div style={{ color: 'var(--text-tertiary)', marginBottom: '6px' }}>Flags</div>
                            <div className="ip-mono">{a.flags}</div>
                          </div>
                          <div>
                            <div style={{ color: 'var(--text-tertiary)', marginBottom: '6px' }}>Total Packets</div>
                            <div className="ip-mono">{a.packets}</div>
                          </div>
                          
                          <div style={{ gridColumn: '1 / -1', marginTop: '12px', display: 'flex', justifyContent: 'flex-end' }}>
                            <button onClick={(e) => { e.stopPropagation(); handleBlockIp(a.srcIp); }} style={{ background: 'var(--critical-dim)', color: 'var(--critical)', border: '1px solid var(--critical)', padding: '8px 16px', borderRadius: '6px', fontSize: '12px', fontWeight: '600', cursor: 'pointer' }}>
                              Block Source IP ({a.srcIp})
                            </button>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
            {filteredAlerts.length === 0 && (
              <tr>
                <td colSpan="6" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                  No {filter !== 'All' ? filter.toLowerCase() : 'active'} alerts detected.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
