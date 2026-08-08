import React from 'react';
import { Network as NetworkIcon, Server, Shield, Activity, Cpu } from 'lucide-react';

export default function Network({ packets = [] }) {
  // Extract dynamic IP addresses from incoming live packets
  const dynamicHosts = new Map();

  packets.forEach(p => {
    if (p.src && !dynamicHosts.has(p.src)) {
      const isAttack = p.verdict && p.verdict !== 'Normal';
      dynamicHosts.set(p.src, {
        id: `Host-${p.src.split('.').pop() || 'Node'}`,
        ip: p.src,
        status: isAttack ? 'Warning' : 'Secure',
        load: `${Math.floor(Math.random() * 45 + 15)}%`,
        proto: p.proto || 'TCP'
      });
    }
  });

  const baseNodes = [
    { id: 'Gateway-01', ip: '192.168.1.1', status: 'Secure', load: '45%', proto: 'Gateway' },
    { id: 'Web-Server-Alpha', ip: '192.168.1.10', status: 'Warning', load: '82%', proto: 'HTTPS' },
    { id: 'DB-Primary', ip: '10.0.0.50', status: 'Secure', load: '12%', proto: 'SQL' },
    { id: 'App-Server-01', ip: '192.168.1.20', status: 'Secure', load: '34%', proto: 'HTTP' },
    { id: 'DMZ-Router', ip: '172.16.0.1', status: 'Critical', load: '98%', proto: 'BGP' },
  ];

  const allNodes = [...baseNodes];
  dynamicHosts.forEach(host => {
    if (!allNodes.some(n => n.ip === host.ip)) {
      allNodes.push(host);
    }
  });

  const getStatusColor = (status) => {
    if (status === 'Secure') return { text: 'var(--text-success)', bg: 'rgba(16, 185, 129, 0.15)', border: 'var(--text-success)' };
    if (status === 'Warning') return { text: 'var(--text-warning)', bg: 'var(--bg-warning)', border: 'var(--text-warning)' };
    return { text: 'var(--text-danger)', bg: 'var(--bg-danger)', border: 'var(--text-danger)' };
  };

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "12px", border: "1px solid var(--border)", padding: "1.5rem", marginBottom: "16px" }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
          <div style={{ background: 'var(--bg-accent)', padding: '12px', borderRadius: '12px' }}>
            <NetworkIcon size={24} color="var(--text-accent)" />
          </div>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: '600', margin: '0 0 4px 0', color: 'var(--text-main)' }}>Network Topology & Host Status</h2>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '13px' }}>Monitoring active subnet nodes and AI threat defense posture.</p>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
          {allNodes.map((node, i) => {
            const st = getStatusColor(node.status);
            return (
              <div key={i} className="card-anim" style={{ 
                border: '1px solid var(--border)', borderRadius: '12px', padding: '20px',
                position: 'relative', overflow: 'hidden', background: 'var(--surface-1)'
              }}>
                {/* Decorative top bar indicating status */}
                <div style={{ 
                  position: 'absolute', top: 0, left: 0, right: 0, height: '4px',
                  background: st.border
                }} />
                
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <Server size={20} color="var(--text-secondary)" />
                    <div>
                      <div style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-main)' }}>{node.id}</div>
                      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{node.ip}</div>
                    </div>
                  </div>
                  
                  <span style={{ 
                    padding: '3px 8px', borderRadius: '6px', fontSize: '11px', fontWeight: '600',
                    background: st.bg, color: st.text
                  }}>
                    {node.status}
                  </span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <div style={{ background: 'var(--bg-base)', padding: '10px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '2px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Activity size={12} /> Traffic Load
                    </div>
                    <div style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-main)' }}>{node.load}</div>
                  </div>
                  <div style={{ background: 'var(--bg-base)', padding: '10px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '2px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Shield size={12} /> Defense
                    </div>
                    <div style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-success)' }}>Active</div>
                  </div>
                </div>

              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

