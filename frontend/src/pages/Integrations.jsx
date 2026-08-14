import React from "react";

export default function Integrations() {
  return (
    <div className="tab-page active" id="integrations">
      <div className="page-head">
        <div><div className="eyebrow">SYSTEM / INTEGRATIONS</div><div className="page-title">Integrations</div></div>
      </div>
      <div className="panel">
        <div className="kv-row"><span className="kv-row-label">Slack — #soc-alerts</span><span className="kv-row-value ok">connected</span></div>
        <div className="kv-row"><span className="kv-row-label">PagerDuty — on-call escalation</span><span className="kv-row-value ok">connected</span></div>
        <div className="kv-row"><span className="kv-row-label">Splunk — SIEM forwarding</span><span className="kv-row-value" style={{color: "var(--text-tertiary)"}}>not connected</span></div>
        <div className="kv-row"><span className="kv-row-label">Email digest — daily 8:00 AM</span><span className="kv-row-value ok">connected</span></div>
      </div>
    </div>
  );
}
