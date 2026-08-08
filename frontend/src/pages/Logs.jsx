import React, { useState } from 'react';
import { Search, Download, Filter, RefreshCw } from 'lucide-react';

export default function Logs({ packets = [] }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedProto, setSelectedProto] = useState('ALL');
  const [verdictFilter, setVerdictFilter] = useState('ALL');

  const getClassColor = (cls) => {
    const s = (cls || '').toLowerCase();
    if (s.includes('normal')) return 'var(--text-success)';
    if (s.includes('dos') || s.includes('brute') || s.includes('botnet') || s.includes('infiltration')) return 'var(--text-danger)';
    if (s.includes('scan') || s.includes('web')) return 'var(--text-warning)';
    return 'var(--text-secondary)';
  };

  const filteredPackets = packets.filter(pkt => {
    const verdict = pkt.verdict || pkt.type || 'Normal';
    const proto = (pkt.proto || '').toUpperCase();
    const q = searchQuery.toLowerCase();

    const matchSearch = !q || 
      (pkt.src || '').toLowerCase().includes(q) || 
      (pkt.dst || '').toLowerCase().includes(q) || 
      verdict.toLowerCase().includes(q) || 
      proto.toLowerCase().includes(q);

    const matchProto = selectedProto === 'ALL' || proto.includes(selectedProto);

    let matchVerdict = true;
    if (verdictFilter === 'NORMAL') matchVerdict = verdict.toLowerCase() === 'normal';
    if (verdictFilter === 'ATTACK') matchVerdict = verdict.toLowerCase() !== 'normal';

    return matchSearch && matchProto && matchVerdict;
  });

  const exportToCSV = () => {
    if (filteredPackets.length === 0) return;

    const headers = ['Timestamp', 'Source IP', 'Destination IP', 'Size (Bytes)', 'Protocol', 'AI Verdict'];
    const rows = filteredPackets.map(p => [
      p.time instanceof Date ? p.time.toISOString() : new Date().toISOString(),
      p.src,
      p.dst,
      p.size,
      p.proto,
      p.verdict || p.type || 'Normal'
    ]);

    const csvContent = "data:text/csv;charset=utf-8," 
      + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `nids_traffic_log_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <div>
          <p style={{ fontSize: "16px", fontWeight: "600", margin: "0 0 2px", color: "var(--text-main)" }}>Live Network Traffic Forensics</p>
          <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: 0 }}>Showing {filteredPackets.length} of {packets.length} captured bidirectional flow records</p>
        </div>
        
        <button 
          onClick={exportToCSV}
          className="action-btn"
          disabled={filteredPackets.length === 0}
          style={{ opacity: filteredPackets.length === 0 ? 0.5 : 1 }}
        >
          <Download size={14} /> Export CSV Report
        </button>
      </div>

      {/* Control Bar: Search + Protocol Filter + Verdict Filter */}
      <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", gap: "12px", marginBottom: "16px", background: "var(--surface-1)", padding: "10px 14px", borderRadius: "12px", border: "1px solid var(--border)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
          {/* Protocol filter */}
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <Filter size={13} color="var(--text-secondary)" />
            <span style={{ fontSize: "12px", color: "var(--text-secondary)" }}>Protocol:</span>
            {['ALL', 'TCP', 'UDP', 'ICMP'].map(p => (
              <button
                key={p}
                onClick={() => setSelectedProto(p)}
                className={`filter-btn ${selectedProto === p ? 'active' : ''}`}
              >
                {p}
              </button>
            ))}
          </div>

          {/* Verdict filter */}
          <div style={{ display: "flex", alignItems: "center", gap: "6px", marginLeft: "12px" }}>
            <span style={{ fontSize: "12px", color: "var(--text-secondary)" }}>Verdict:</span>
            {['ALL', 'NORMAL', 'ATTACK'].map(v => (
              <button
                key={v}
                onClick={() => setVerdictFilter(v)}
                className={`filter-btn ${verdictFilter === v ? 'active' : ''}`}
              >
                {v}
              </button>
            ))}
          </div>
        </div>

        {/* Search bar */}
        <div style={{ position: "relative", minWidth: "220px" }}>
          <Search size={14} color="var(--text-secondary)" style={{ position: "absolute", left: "10px", top: "50%", transform: "translateY(-50%)" }} />
          <input
            type="text"
            placeholder="Search IP, verdict..."
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
      
      <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "12px", border: "1px solid var(--border)", overflow: "hidden" }}>
        <table style={{ width: "100%", fontSize: "13px", borderCollapse: "collapse", tableLayout: "fixed" }}>
          <thead>
            <tr style={{ background: "var(--surface-2)", color: "var(--text-secondary)", textAlign: "left", borderBottom: "1px solid var(--border)" }}>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Source IP</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Dest IP</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Size (Bytes)</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Protocol</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>AI Verdict</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {filteredPackets.map((pkt, i) => (
              <tr key={i} style={{ borderBottom: "1px solid var(--border)", transition: "background 0.2s" }} onMouseEnter={(e) => e.currentTarget.style.backgroundColor = "var(--bg-accent)"} onMouseLeave={(e) => e.currentTarget.style.backgroundColor = "transparent"}>
                <td style={{ padding: "12px 16px", fontWeight: "500", fontFamily: "monospace" }}>{pkt.src}</td>
                <td style={{ padding: "12px 16px", fontWeight: "500", fontFamily: "monospace" }}>{pkt.dst}</td>
                <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{pkt.size} B</td>
                <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{pkt.proto}</td>
                <td style={{ padding: "12px 16px", fontWeight: "600", color: getClassColor(pkt.verdict || pkt.type) }}>{pkt.verdict || pkt.type}</td>
                <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{pkt.time instanceof Date ? pkt.time.toLocaleTimeString() : 'Just now'}</td>
              </tr>
            ))}
            {filteredPackets.length === 0 && (
              <tr>
                <td colSpan="6" style={{ padding: "32px 16px", color: "var(--text-secondary)", textAlign: "center" }}>
                  <p style={{ margin: "0 0 4px", fontSize: "14px" }}>No traffic logs match filter criteria</p>
                  <p style={{ margin: 0, fontSize: "12px" }}>Try adjusting search parameters or selecting "ALL" protocols.</p>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

