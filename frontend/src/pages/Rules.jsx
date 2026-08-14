import React from "react";

export default function Rules() {
  return (
    <div className="tab-page active" id="rules">
      <div className="page-head">
        <div><div className="eyebrow">SYSTEM / DETECTION RULES</div><div className="page-title">Detection rules</div></div>
      </div>
      <div className="panel">
        <div className="kv-row"><span className="kv-row-label">SYN flood threshold — &gt;500 pkts/sec from single source</span><span className="kv-row-value ok">enabled</span></div>
        <div className="kv-row"><span className="kv-row-label">Port scan detection — &gt;15 ports in 10s</span><span className="kv-row-value ok">enabled</span></div>
        <div className="kv-row"><span className="kv-row-label">Brute force lockout — &gt;5 failed auths in 60s</span><span className="kv-row-value ok">enabled</span></div>
        <div className="kv-row"><span className="kv-row-label">Known botnet C2 signature match</span><span className="kv-row-value ok">enabled</span></div>
        <div className="kv-row"><span className="kv-row-label">Data exfiltration — outbound &gt;500MB to new host</span><span className="kv-row-value" style={{color: "var(--text-tertiary)"}}>disabled</span></div>
      </div>
    </div>
  );
}
