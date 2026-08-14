import React from "react";

export default function Reports() {
  return (
    <div className="tab-page active" id="reports">
      <div className="page-head">
        <div><div className="eyebrow">ANALYZE / REPORTS</div><div className="page-title">Reports</div></div>
      </div>
      <div className="panel">
        <div className="kv-row"><span className="kv-row-label">Daily threat summary — Aug 7, 2026</span><span className="kv-row-value" style={{color: "var(--info)", cursor: "pointer"}}>Download PDF</span></div>
        <div className="kv-row"><span className="kv-row-label">Weekly traffic analysis — Week 32</span><span className="kv-row-value" style={{color: "var(--info)", cursor: "pointer"}}>Download PDF</span></div>
        <div className="kv-row"><span className="kv-row-label">Model retraining audit — v1</span><span className="kv-row-value" style={{color: "var(--info)", cursor: "pointer"}}>Download CSV</span></div>
        <div className="kv-row"><span className="kv-row-label">Monthly compliance export — Jul 2026</span><span className="kv-row-value" style={{color: "var(--info)", cursor: "pointer"}}>Download PDF</span></div>
      </div>
    </div>
  );
}
