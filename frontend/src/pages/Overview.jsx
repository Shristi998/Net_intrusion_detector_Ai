import React from "react";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';
import { ShieldCheck, Activity, AlertTriangle, Cpu } from 'lucide-react';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

export default function Overview({ stats, packets = [], alerts = [], modelInfo }) {
  const time = new Date().toLocaleTimeString();

  const activeAlertsCount = alerts.length;
  const totalAnalyzed = stats.totalAnalyzed || 0;
  const accuracy = modelInfo?.accuracy || '99.4%';
  const monitoredHosts = stats.monitoredHosts || 0;
  const threatsFound = stats.threatsFound || 0;

  // Aggregate verdict breakdown from current packet memory buffer
  const counts = {
    Normal: 0,
    'Dos/DDos': 0,
    PortScan: 0,
    'Brute Force': 0,
    'Web Attack': 0,
    'Botnet ARES': 0,
    Infiltration: 0
  };

  packets.forEach(p => {
    const verdict = p.verdict || p.type || 'Normal';
    if (counts[verdict] !== undefined) {
      counts[verdict] += 1;
    } else if (verdict !== 'Normal') {
      counts['PortScan'] += 1;
    } else {
      counts.Normal += 1;
    }
  });

  const doughnutData = {
    labels: Object.keys(counts),
    datasets: [
      {
        data: Object.values(counts),
        backgroundColor: [
          '#10b981', // Normal - Green
          '#ef4444', // DoS - Red
          '#f59e0b', // PortScan - Amber
          '#ec4899', // Brute Force - Pink
          '#8b5cf6', // Web Attack - Purple
          '#3b82f6', // Botnet - Blue
          '#6366f1'  // Infiltration - Indigo
        ],
        borderWidth: 2,
        borderColor: 'var(--surface-1)'
      }
    ]
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: 'var(--text-secondary)',
          font: { size: 11, family: "'Inter', sans-serif" },
          boxWidth: 12,
          padding: 12
        }
      },
      tooltip: {
        backgroundColor: 'rgba(15, 23, 42, 0.9)',
        titleColor: '#fff',
        bodyColor: '#cbd5e1',
        borderColor: 'rgba(255, 255, 255, 0.1)',
        borderWidth: 1
      }
    },
    cutout: '70%'
  };

  // Live packet rate over time (last 10 data points)
  const lineLabels = packets.slice(0, 10).reverse().map((p, idx) => {
    return p.time instanceof Date ? p.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : `T-${10 - idx}s`;
  });
  const lineValues = packets.slice(0, 10).reverse().map(p => p.size || 64);

  const lineData = {
    labels: lineLabels.length > 0 ? lineLabels : ['12:00', '12:01', '12:02', '12:03', '12:04'],
    datasets: [
      {
        label: 'Flow Size (Bytes)',
        data: lineValues.length > 0 ? lineValues : [120, 450, 320, 890, 210],
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56, 189, 248, 0.12)',
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      }
    ]
  };

  const lineOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: 'rgba(15, 23, 42, 0.9)',
        titleColor: '#fff',
        bodyColor: '#cbd5e1',
        borderColor: 'rgba(255, 255, 255, 0.1)',
        borderWidth: 1
      }
    },
    scales: {
      x: {
        grid: { color: 'rgba(148, 163, 184, 0.1)' },
        ticks: { color: 'var(--text-secondary)', font: { size: 10 } }
      },
      y: {
        grid: { color: 'rgba(148, 163, 184, 0.1)' },
        ticks: { color: 'var(--text-secondary)', font: { size: 10 } }
      }
    }
  };

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <div>
          <p style={{ fontSize: "16px", fontWeight: "600", margin: "0 0 2px", color: "var(--text-main)" }}>System Overview</p>
          <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: 0 }}>Real-time telemetry updated at {time}</p>
        </div>
        <span style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", color: "var(--text-success)", background: "rgba(16,185,129,0.1)", padding: "4px 10px", borderRadius: "12px", border: "1px solid rgba(16,185,129,0.2)" }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--text-success)" }} /> Engine Live
        </span>
      </div>
      
      {/* Metrics Row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px", marginBottom: "16px" }}>
        <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "1.25rem", border: "1px solid var(--border)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
            <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: 0, fontWeight: "500" }}>Model Accuracy</p>
            <ShieldCheck size={18} color="var(--text-success)" />
          </div>
          <p style={{ fontSize: "28px", fontWeight: "700", margin: 0, letterSpacing: "-0.5px" }}>{accuracy}</p>
          <p style={{ fontSize: "11px", color: "var(--text-secondary)", margin: "4px 0 0" }}>XGBoost Classifier Engine</p>
        </div>

        <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "1.25rem", border: "1px solid var(--border)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
            <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: 0, fontWeight: "500" }}>Active Threats</p>
            <AlertTriangle size={18} color={activeAlertsCount > 0 ? "var(--text-danger)" : "var(--text-success)"} />
          </div>
          <p style={{ fontSize: "28px", fontWeight: "700", margin: 0, letterSpacing: "-0.5px", color: activeAlertsCount > 0 ? "var(--text-danger)" : "var(--text-success)" }}>{threatsFound}</p>
          <p style={{ fontSize: "11px", color: "var(--text-secondary)", margin: "4px 0 0" }}>Flagged network intrusions</p>
        </div>

        <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "1.25rem", border: "1px solid var(--border)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
            <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: 0, fontWeight: "500" }}>Total Analyzed</p>
            <Activity size={18} color="var(--text-accent)" />
          </div>
          <p style={{ fontSize: "28px", fontWeight: "700", margin: 0, letterSpacing: "-0.5px" }}>{totalAnalyzed.toLocaleString()}</p>
          <p style={{ fontSize: "11px", color: "var(--text-secondary)", margin: "4px 0 0" }}>Flow packets classified</p>
        </div>

        <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "1.25rem", border: "1px solid var(--border)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
            <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: 0, fontWeight: "500" }}>Monitored Hosts</p>
            <Cpu size={18} color="var(--text-accent)" />
          </div>
          <p style={{ fontSize: "28px", fontWeight: "700", margin: 0, letterSpacing: "-0.5px", color: "var(--text-accent)" }}>{monitoredHosts}</p>
          <p style={{ fontSize: "11px", color: "var(--text-secondary)", margin: "4px 0 0" }}>Unique IPs in active subnet</p>
        </div>
      </div>

      {/* Visual Analytics Charts */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
        <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "12px", border: "1px solid var(--border)", padding: "1.25rem" }}>
          <p style={{ fontSize: "14px", fontWeight: "600", margin: "0 0 12px", color: "var(--text-main)" }}>Traffic Classification Breakdown</p>
          <div style={{ height: "220px", position: "relative" }}>
            <Doughnut data={doughnutData} options={doughnutOptions} />
          </div>
        </div>

        <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "12px", border: "1px solid var(--border)", padding: "1.25rem" }}>
          <p style={{ fontSize: "14px", fontWeight: "600", margin: "0 0 12px", color: "var(--text-main)" }}>Real-Time Flow Throughput</p>
          <div style={{ height: "220px", position: "relative" }}>
            <Line data={lineData} options={lineOptions} />
          </div>
        </div>
      </div>

      {/* Recent Traffic Table */}
      <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "12px", border: "1px solid var(--border)", overflow: "hidden" }}>
        <div style={{ padding: "1.25rem 1.25rem 0.5rem", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <p style={{ fontSize: "14px", fontWeight: "600", margin: "0 0 2px" }}>Recent Traffic Log</p>
            <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: 0 }}>Latest captured bidirectional network flows</p>
          </div>
          <span style={{ fontSize: "12px", color: "var(--text-secondary)" }}>Showing 5 of {packets.length}</span>
        </div>
        <table style={{ width: "100%", fontSize: "13px", borderCollapse: "collapse", tableLayout: "fixed" }}>
          <thead>
            <tr style={{ color: "var(--text-secondary)", textAlign: "left", borderBottom: "1px solid var(--border)", background: "var(--surface-2)" }}>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Source IP</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Dest IP</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Size (Bytes)</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Protocol</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>AI Verdict</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {packets.slice(0, 5).map((pkt, i) => {
              let color = 'var(--text-success)';
              const v = (pkt.verdict || pkt.type || '').toLowerCase();
              if (v.includes('dos') || v.includes('brute') || v.includes('botnet') || v.includes('infiltration')) color = 'var(--text-danger)';
              else if (v.includes('scan') || v.includes('web')) color = 'var(--text-warning)';

              return (
                <tr key={i} style={{ borderBottom: "1px solid var(--border)", transition: "background 0.2s" }} onMouseEnter={(e) => e.currentTarget.style.backgroundColor = "var(--bg-accent)"} onMouseLeave={(e) => e.currentTarget.style.backgroundColor = "transparent"}>
                  <td style={{ padding: "12px 16px", fontWeight: "500", fontFamily: "monospace" }}>{pkt.src}</td>
                  <td style={{ padding: "12px 16px", fontWeight: "500", fontFamily: "monospace" }}>{pkt.dst}</td>
                  <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{pkt.size} B</td>
                  <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{pkt.proto}</td>
                  <td style={{ padding: "12px 16px", fontWeight: "600", color: color }}>{pkt.verdict || pkt.type}</td>
                  <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{pkt.time instanceof Date ? pkt.time.toLocaleTimeString() : 'Just now'}</td>
                </tr>
              )
            })}
            {packets.length === 0 && (
              <tr>
                <td colSpan="6" style={{ padding: "24px 16px", color: "var(--text-secondary)", textAlign: "center" }}>Listening for network flows...</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

