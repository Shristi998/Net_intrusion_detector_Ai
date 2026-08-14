import React from "react";

export default function Intel() {
  return (
    <div className="tab-page active" id="intel">
      <div className="page-head">
        <div><div className="eyebrow">ANALYZE / THREAT INTEL</div><div className="page-title">Threat intelligence feed</div></div>
      </div>
      <div className="panel">
        <div className="panel-head">
          <div><div className="panel-title">Indicators of compromise</div><div className="panel-sub">MATCHED AGAINST LIVE TRAFFIC</div></div>
        </div>
        <table>
          <thead>
            <tr><th>Indicator</th><th>Type</th><th>Source</th><th>Confidence</th><th>Last seen</th></tr>
          </thead>
          <tbody>
            <tr><td className="ip">34.49.39.67</td><td>IPv4</td><td>AbuseIPDB</td><td><span className="badge threat">HIGH</span></td><td>2 min ago</td></tr>
            <tr><td className="ip">204.79.197.203</td><td>IPv4</td><td>AlienVault OTX</td><td><span className="badge threat">HIGH</span></td><td>4 min ago</td></tr>
            <tr><td className="ip">botnet-ares-c2.net</td><td>Domain</td><td>Internal honeypot</td><td><span className="badge threat">HIGH</span></td><td>1 hr ago</td></tr>
            <tr><td className="ip">185.220.101.4</td><td>IPv4</td><td>Emerging Threats</td><td><span className="badge normal">MEDIUM</span></td><td>3 hr ago</td></tr>
            <tr><td className="ip">e8f1...c2b9 (SHA256)</td><td>File hash</td><td>VirusTotal</td><td><span className="badge normal">MEDIUM</span></td><td>1 day ago</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
