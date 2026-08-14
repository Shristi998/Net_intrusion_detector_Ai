import React from "react";

export default function Detections({ modelInfo, alerts }) {
  const accuracy = modelInfo?.accuracy || '98.44%';
  const samples = modelInfo?.total_samples || '73,362';

  const detectedClasses = new Set();
  (alerts || []).forEach(a => {
    if (a.type && a.type !== 'Normal') {
      detectedClasses.add(a.type);
    }
  });
  const classesArray = Array.from(detectedClasses);

  return (
    <div className="tab-page active" id="model">
      <div className="page-head"><div><div className="eyebrow">SYSTEM / MODEL</div><div className="page-title">Model performance</div></div></div>
      <div className="kv-grid">
        <div className="kv-card"><div className="kv-label">Algorithm</div><div className="kv-value">XGBoost</div></div>
        <div className="kv-card"><div className="kv-label">Reported accuracy</div><div className="kv-value accent">{accuracy}</div></div>
        <div className="kv-card"><div className="kv-label">Training samples</div><div className="kv-value">{samples}</div></div>
        <div className="kv-card"><div className="kv-label">GAN augmented</div><div className="kv-value accent">Yes</div></div>
      </div>
      <div className="panel" style={{ padding: "18px" }}>
        <div className="panel-title" style={{ marginBottom: "12px" }}>Detected threat classes</div>
        <div className="tag-row">
          <span className="tag">Normal</span>
          {classesArray.map((cls, i) => (
            <span key={i} className="tag hot">{cls}</span>
          ))}
          {classesArray.length === 0 && (
            <span className="tag" style={{ color: "var(--text-tertiary)" }}>No active threats</span>
          )}
        </div>
      </div>
    </div>
  );
}
