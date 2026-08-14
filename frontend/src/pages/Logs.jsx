import React from "react";

export default function Logs({ packets }) {
  return (
    <div className="tab-page active" id="traffic">
      <div className="page-head"><div><div className="eyebrow">MONITOR / TRAFFIC LOG</div><div className="page-title">Traffic log</div></div></div>
      <div className="panel">
        <table>
          <thead><tr><th>Source IP</th><th>Dest IP</th><th>Port/Size</th><th>Protocol</th><th>Class</th><th>Time</th></tr></thead>
          <tbody>
            {packets.map((p, i) => (
              <tr key={i}>
                <td className="ip">{p.src}</td>
                <td className="ip">{p.dst}</td>
                <td>{p.size || 0}</td>
                <td>{p.proto === 6 ? 'TCP' : p.proto === 17 ? 'UDP' : p.proto}</td>
                <td>
                    {p.verdict === 'Normal' ? (
                      <span className="badge sev-low">NORMAL</span>
                    ) : (
                      <span className={`badge sev-${p.sev ? p.sev.toLowerCase() : 'high'}`}>{p.verdict.toUpperCase()}</span>
                    )}
                </td>
                <td>{p.time.toLocaleTimeString()}</td>
              </tr>
            ))}
            {packets.length === 0 && (
              <tr>
                <td colSpan="6" style={{textAlign: "center", padding: "20px"}}>No traffic recorded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
