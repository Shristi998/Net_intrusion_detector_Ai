import React, { useState, useEffect } from "react";

export default function Overview({ stats, packets, alerts, modelInfo }) {
  const [timeRange, setTimeRange] = useState('6H');
  const [chartData, setChartData] = useState({ normalCounts: Array(30).fill(0), flaggedCounts: Array(30).fill(0) });

  useEffect(() => {
    fetch(`http://localhost:5000/api/chart?range=${timeRange}`)
      .then(res => res.json())
      .then(data => {
        if (data.normalCounts && data.flaggedCounts) {
          setChartData(data);
        }
      })
      .catch(err => console.error("Chart fetch error:", err));
  }, [timeRange]);

  const now = Date.now();
  const getFilterTime = () => {
    if (timeRange === '1H') return now - 1 * 60 * 60 * 1000;
    if (timeRange === '6H') return now - 6 * 60 * 60 * 1000;
    if (timeRange === '24H') return now - 24 * 60 * 60 * 1000;
    return now - 6 * 60 * 60 * 1000;
  };

  const filteredAlerts = alerts.filter(a => {
    const t = new Date(a.time || a.timestamp || Date.now()).getTime();
    return t >= getFilterTime();
  });

  const filteredPackets = packets.filter(p => {
    const t = new Date(p.time || p.timestamp || Date.now()).getTime();
    return t >= getFilterTime();
  });

  const totalAnalyzed = stats.totalAnalyzed || 0;
  const accuracy = modelInfo?.accuracy || '...';
  const monitoredHosts = stats.monitoredHosts || 0;
  const activeAlertsCount = filteredAlerts.length;

  // Derive donut values from filteredAlerts
  const threatCounts = {
    'Dos/DDoS': 0,
    'PortScan': 0,
    'Brute Force': 0,
    'Web Attack': 0,
    'Other': 0
  };
  
  filteredAlerts.forEach(a => {
    let t = a.type || a.threat_class || 'Other';
    if (t === 'Dos/DDos' || t === 'Dos/DDoS') t = 'Dos/DDoS';
    if (t === 'Botnet ARES' || t === 'Infiltration') t = 'Other';
    if (threatCounts[t] !== undefined) {
      threatCounts[t]++;
    } else {
      threatCounts['Other']++;
    }
  });

  const total = filteredAlerts.length || 1;
  const pDos = Math.round((threatCounts['Dos/DDoS'] / total) * 100);
  const pPort = Math.round((threatCounts['PortScan'] / total) * 100);
  const pBrute = Math.round((threatCounts['Brute Force'] / total) * 100);
  const pWeb = Math.round((threatCounts['Web Attack'] / total) * 100);
  const pOther = Math.round((threatCounts['Other'] / total) * 100);

  const ipCounts = {};
  filteredPackets.forEach(p => {
    const src = p.src || p.src_ip;
    const dst = p.dst || p.dst_ip;
    if (src) ipCounts[src] = (ipCounts[src] || 0) + 1;
    if (dst) ipCounts[dst] = (ipCounts[dst] || 0) + 1;
  });
  const totalIps = Object.values(ipCounts).reduce((a, b) => a + b, 0) || 1;
  const topTalkers = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([ip, count]) => ({ ip, pct: Math.round((count / totalIps) * 100) }));

  const p1 = pDos;
  const p2 = p1 + pPort;
  const p3 = p2 + pBrute;
  const p4 = p3 + pWeb;
  const donutStyle = activeAlertsCount === 0 
    ? { background: 'var(--bg-panel-alt)' }
    : { background: `conic-gradient(var(--critical) 0% ${p1}%, var(--warn) ${p1}% ${p2}%, var(--info) ${p2}% ${p3}%, var(--violet) ${p3}% ${p4}%, var(--signal) ${p4}% 100%)` };

  // Use fetched chart data from backend
  const numBuckets = 30;
  const normalCounts = chartData.normalCounts;
  const flaggedCounts = chartData.flaggedCounts;

  const maxCount = Math.max(...normalCounts, ...flaggedCounts, 10);
  const scaleY = (val) => 180 - (val / maxCount) * 140; // Max Y is 40, Min Y is 180
  const scaleX = (idx) => (idx / (numBuckets - 1)) * 760;

  let normalPts = '';
  let flaggedPts = '';
  let pathD = '';
  const circs = [];

  for (let i = 0; i < numBuckets; i++) {
    const x = scaleX(i);
    const yN = scaleY(normalCounts[i]);
    const yF = scaleY(flaggedCounts[i]);
    
    normalPts += `${x},${yN} `;
    flaggedPts += `${x},${yF} `;
    
    if (i === 0) pathD += `M${x},${yN} `;
    else pathD += `L${x},${yN} `;

    if (flaggedCounts[i] > 0) {
      circs.push({ x, y: yF });
    }
  }
  pathD += `L760,200 L0,200 Z`;

  return (
    <div className="tab-page active" id="overview">
      <div className="page-head">
        <div><div className="eyebrow">MONITOR / OVERVIEW</div><div className="page-title">Network overview</div></div>
        <div className="range-tabs">
          <div className={`range-tab ${timeRange === '1H' ? 'active' : ''}`} onClick={() => setTimeRange('1H')}>1H</div>
          <div className={`range-tab ${timeRange === '6H' ? 'active' : ''}`} onClick={() => setTimeRange('6H')}>6H</div>
          <div className={`range-tab ${timeRange === '24H' ? 'active' : ''}`} onClick={() => setTimeRange('24H')}>24H</div>
        </div>
      </div>

      <div className="stat-grid">
        <div className="stat-card c-signal">
          <div className="stat-top"><div className="stat-icon signal"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="9"/></svg></div><span className="stat-delta up-good">+0.3%</span></div>
          <div className="stat-label">Overall accuracy</div>
          <div className="stat-value">{accuracy}</div>
          <svg className="spark" width="100%" height="34" viewBox="0 0 200 34" preserveAspectRatio="none"><polyline points="0,24 20,22 40,25 60,18 80,20 100,14 120,16 140,10 160,12 180,7 200,9" fill="none" stroke="#3FE0C5" strokeWidth="1.6"/></svg>
        </div>
        <div className="stat-card c-critical">
          <div className="stat-top"><div className="stat-icon critical"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 9v4M12 17h.01"/><path d="M10.3 4.5L2.7 18a1.8 1.8 0 001.5 2.7h15.6a1.8 1.8 0 001.5-2.7L13.7 4.5a1.8 1.8 0 00-3.4 0z"/></svg></div><span className="stat-delta up-bad">live</span></div>
          <div className="stat-label">Active alerts</div>
          <div className="stat-value">{activeAlertsCount}</div>
          <svg className="spark" width="100%" height="34" viewBox="0 0 200 34" preserveAspectRatio="none"><polyline points="0,26 20,24 40,20 60,22 80,14 100,17 120,9 140,13 160,6 180,10 200,4" fill="none" stroke="#FF5C72" strokeWidth="1.6"/></svg>
        </div>
        <div className="stat-card">
          <div className="stat-top"><div className="stat-icon info"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 12h16M4 6h16M4 18h16"/></svg></div><span className="stat-delta flat">steady</span></div>
          <div className="stat-label">Total analyzed</div>
          <div className="stat-value">{totalAnalyzed.toLocaleString()}</div>
          <svg className="spark" width="100%" height="34" viewBox="0 0 200 34" preserveAspectRatio="none"><polyline points="0,20 20,19 40,21 60,17 80,18 100,15 120,16 140,13 160,14 180,11 200,12" fill="none" stroke="#8B9BFF" strokeWidth="1.6"/></svg>
        </div>
        <div className="stat-card">
          <div className="stat-top"><div className="stat-icon warn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 3v4M8 3v4"/></svg></div><span className="stat-delta flat">tracked</span></div>
          <div className="stat-label">Monitored hosts</div>
          <div className="stat-value">{monitoredHosts}</div>
          <svg className="spark" width="100%" height="34" viewBox="0 0 200 34" preserveAspectRatio="none"><polyline points="0,18 20,18 40,17 60,17 80,16 100,16 120,15 140,15 160,14 180,14 200,13" fill="none" stroke="#F5B94E" strokeWidth="1.6"/></svg>
        </div>
      </div>

      <div className="dash-row">
        <div className="panel">
          <div className="panel-head">
            <div><div className="panel-title">Traffic &amp; threat volume</div><div className="panel-sub">FLOWS PER MINUTE · LAST {timeRange}</div></div>
          </div>
          <div className="chart-legend">
            <span><span className="legend-dot" style={{background: "#3FE0C5"}}></span>Normal flows</span>
            <span><span className="legend-dot" style={{background: "#FF5C72"}}></span>Flagged flows</span>
          </div>
          <div className="chart-wrap">
            <svg width="100%" height="200" viewBox="0 0 760 200" preserveAspectRatio="none">
              <defs>
                <linearGradient id="gArea" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#3FE0C5" stopOpacity="0.28"/>
                  <stop offset="100%" stopColor="#3FE0C5" stopOpacity="0"/>
                </linearGradient>
              </defs>
              <g stroke="#181F30" strokeWidth="1">
                <line x1="0" y1="40" x2="760" y2="40"/><line x1="0" y1="90" x2="760" y2="90"/><line x1="0" y1="140" x2="760" y2="140"/><line x1="0" y1="185" x2="760" y2="185"/>
              </g>
              <path d={pathD} fill="url(#gArea)"/>
              <polyline points={normalPts} fill="none" stroke="#3FE0C5" strokeWidth="2"/>
              <polyline points={flaggedPts} fill="none" stroke="#FF5C72" strokeWidth="1.6" opacity="0.85"/>
              {circs.map((c, i) => (
                <circle key={i} cx={c.x} cy={c.y} r="4" fill="#FF5C72"/>
              ))}
            </svg>
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><div><div className="panel-title">Threat breakdown</div><div className="panel-sub">ACTIVE ALERTS BY CLASS</div></div></div>
          <div className="donut-wrap">
            <div className="donut" style={donutStyle}><div className="donut-center"><b>{activeAlertsCount}</b><span>ALERTS</span></div></div>
            <div className="legend-list">
              <div className="legend-row"><span className="lname"><span className="legend-dot" style={{background: "var(--critical)"}}></span>Dos/DDoS</span><span className="lval">{activeAlertsCount === 0 ? "0%" : pDos + "%"}</span></div>
              <div className="legend-row"><span className="lname"><span className="legend-dot" style={{background: "var(--warn)"}}></span>PortScan</span><span className="lval">{activeAlertsCount === 0 ? "0%" : pPort + "%"}</span></div>
              <div className="legend-row"><span className="lname"><span className="legend-dot" style={{background: "var(--info)"}}></span>Brute Force</span><span className="lval">{activeAlertsCount === 0 ? "0%" : pBrute + "%"}</span></div>
              <div className="legend-row"><span className="lname"><span className="legend-dot" style={{background: "var(--violet)"}}></span>Web Attack</span><span className="lval">{activeAlertsCount === 0 ? "0%" : pWeb + "%"}</span></div>
              <div className="legend-row"><span className="lname"><span className="legend-dot" style={{background: "var(--signal)"}}></span>Other</span><span className="lval">{activeAlertsCount === 0 ? "0%" : pOther + "%"}</span></div>
            </div>
          </div>
        </div>
      </div>

      <div className="dash-row" style={{gridTemplateColumns: "1fr 2fr"}}>
        <div className="panel">
          <div className="panel-head"><div><div className="panel-title">Top talkers</div><div className="panel-sub">BY FLOW VOLUME</div></div></div>
          <div style={{paddingBottom: "8px"}}>
            {topTalkers.map((t, i) => (
              <div className="talker-row" key={i}>
                <span className="talker-ip">{t.ip}</span>
                <div className="talker-bar-track"><div className="talker-bar-fill" style={{width: `${t.pct}%`}}></div></div>
                <span className="talker-pct">{t.pct}%</span>
              </div>
            ))}
            {topTalkers.length === 0 && (
              <div style={{padding: "20px", textAlign: "center", color: "var(--text-tertiary)"}}>
                No traffic recorded yet.
              </div>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><div><div className="panel-title">Recent traffic log</div><div className="panel-sub">LATEST BIDIRECTIONAL FLOWS</div></div></div>
          <table>
            <thead><tr><th>Source</th><th>Dest</th><th>Proto</th><th>Class</th><th>Time</th></tr></thead>
            <tbody>
              {packets.slice(0, 5).map(p => (
                <tr key={p.id}>
                  <td className="ip">{p.src}</td>
                  <td className="ip">{p.dst}</td>
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
                  <td colSpan="5" style={{textAlign: "center", padding: "20px"}}>No recent traffic.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
