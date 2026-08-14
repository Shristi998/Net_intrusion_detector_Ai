css = """
/* ---------- Admin Page Custom UI ---------- */
.admin-page {
    --text-dim: #8b98a5;
    --text-faint: #57626d;
    --admin-green: #34d399;
    --admin-amber: #f0b458;
    --admin-red: #f2555a;
    --admin-blue: #5b9df5;
}
.admin-page-title { font-size:26px; font-weight:800; letter-spacing:-0.3px; margin-bottom:26px; }
.admin-card {
    background: var(--bg-panel);
    border: 1px solid var(--border-soft);
    border-radius: 12px;
    overflow: hidden;
    margin-bottom: 24px;
}
.admin-stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); }
.admin-stat { padding: 18px 20px; border-right: 1px solid var(--border-soft); }
.admin-stat:last-child { border-right: none; }
.admin-stat .stat-label { font-size:12px; color: var(--text-dim); margin-bottom:9px; display:flex; align-items:center; gap:7px; }
.admin-stat .stat-label svg { width:13px; height:13px; opacity:0.7; }
.admin-stat .stat-value { font-family: var(--font-mono); font-size:15px; font-weight:600; }
.admin-stat .stat-value.mint { color: var(--admin-green); }
.admin-stat .stat-sub { font-family:var(--font-mono); font-size:11px; color:var(--text-faint); margin-top:4px; }

.admin-table { width:100%; border-collapse:collapse; }
.admin-table thead th {
    text-align:left; font-family:var(--font-mono); font-size:10.5px; color:var(--text-faint);
    text-transform:uppercase; letter-spacing:0.8px; font-weight:600;
    padding: 12px 22px; background: var(--bg-panel-alt); border-bottom:1px solid var(--border-soft);
}
.admin-table tbody td { padding: 16px 22px; font-size:13px; border-bottom:1px solid var(--border-soft); }
.admin-table tbody tr:last-child td { border-bottom:none; }
.admin-table .empty-row td {
    text-align:center; padding: 46px 20px; color: var(--text-faint);
    font-family:var(--font-mono); font-size:12.5px;
}
.admin-table .empty-row svg { display:block; margin:0 auto 12px; width:26px; height:26px; opacity:0.35; }

.ip-mono { font-family:var(--font-mono); color:var(--text-primary); }
.ip-mono.muted { color: var(--text-faint); }
.ip-mono.mint-text { color: var(--admin-green); }

.action-block { font-family:var(--font-body); font-size:12px; font-weight:600; color:var(--admin-red); display:inline-flex; align-items:center; gap:6px; cursor:pointer; }
.action-block:hover { text-decoration: underline; }

.config-grid { display:grid; grid-template-columns: repeat(2, 1fr); gap: 18px 22px; padding: 22px; }
.config-field { display:flex; flex-direction:column; gap:7px; }
.config-field label { font-family:var(--font-mono); font-size:11px; color:var(--text-faint); text-transform:uppercase; letter-spacing:0.6px; }
.config-field input, .config-field select {
    font-family: var(--font-mono); font-size:13px; color: var(--text-primary);
    background: var(--bg-panel-alt); border:1px solid var(--border);
    border-radius:7px; padding: 9px 12px; outline:none; appearance:none;
}
.config-field select {
    background-image: url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%238992ab' stroke-width='2'><polyline points='6 9 12 15 18 9'/></svg>\");
    background-repeat:no-repeat; background-position: right 10px center; background-size:14px; padding-right: 30px;
}
.config-field input:focus, .config-field select:focus { border-color: var(--admin-green); }
.config-footer { display:flex; align-items:center; justify-content:space-between; padding: 16px 22px; border-top:1px solid var(--border-soft); }

.role-tag { font-family:var(--font-mono); font-size:11px; font-weight:600; padding: 3px 9px; border-radius:5px; letter-spacing:0.3px; }
.role-admin { background: rgba(91,157,245,0.12); border:1px solid rgba(91,157,245,0.3); color: var(--admin-blue); }
.role-analyst { background: rgba(52,211,153,0.1); border:1px solid rgba(52,211,153,0.25); color: var(--admin-green); }
.role-viewer { background: rgba(139,152,165,0.1); border:1px solid rgba(139,152,165,0.25); color: var(--text-dim); }
.tag-neutral { font-family:var(--font-mono); font-size:11px; color: var(--text-faint); background: rgba(139,152,165,0.08); border:1px solid var(--border); padding: 3px 9px; border-radius:5px; }

.status-tag { display:inline-flex; align-items:center; gap:6px; font-family:var(--font-mono); font-size:12px; font-weight:600; color:var(--admin-green); background: rgba(52,211,153,0.1); border:1px solid rgba(52,211,153,0.25); padding:3px 9px; border-radius:5px; }
.status-tag .dot { width:5px; height:5px; background:var(--admin-green); border-radius:50%; }
.status-tag.warn { color: var(--admin-amber); background: rgba(240,180,88,0.1); border-color: rgba(240,180,88,0.28); }
.status-tag.warn .dot { background: var(--admin-amber); }

.member { display:flex; align-items:center; gap:11px; }
.member .avatar.small { width:30px; height:30px; font-size:11px; border-radius:7px; display:flex; align-items:center; justify-content:center; }
.member-name { font-size:13px; font-weight:600; }
.member-email { font-family:var(--font-mono); font-size:11px; color:var(--text-faint); margin-top:1px; }

.log-list { padding: 6px 0; }
.log-row { display:flex; align-items:flex-start; gap:14px; padding: 14px 22px; border-bottom:1px solid var(--border-soft); }
.log-row:last-child { border-bottom:none; }
.log-icon { width:30px; height:30px; border-radius:7px; flex-shrink:0; display:flex; align-items:center; justify-content:center; }
.log-icon svg { width:15px; height:15px; }
.log-icon.mint { background: rgba(52,211,153,0.1); color: var(--admin-green); }
.log-icon.red { background: rgba(242,85,90,0.1); color: var(--admin-red); }
.log-icon.amber { background: rgba(240,180,88,0.1); color: var(--admin-amber); }
.log-icon.blue { background: rgba(91,157,245,0.1); color: var(--admin-blue); }
.log-body { flex:1; font-size:13px; line-height:1.5; }
.log-body b { font-weight:600; color:var(--text-primary); }
.log-meta { font-family:var(--font-mono); font-size:11px; color:var(--text-faint); margin-top:2px; }
.log-time { font-family:var(--font-mono); font-size:11px; color:var(--text-faint); flex-shrink:0; padding-top:2px; }

/* Existing overrides */
.admin-card .btn { border:1px solid var(--border); background: var(--bg-panel-alt); color: var(--text-primary); padding: 8px 14px; border-radius:7px; font-family: var(--font-body); font-size:12.5px; font-weight:600; cursor:pointer; display:inline-flex; align-items:center; gap:7px; }
.admin-card .btn:hover { background:var(--bg-hover); border-color:var(--border-soft); }
.admin-card .btn.primary { background: linear-gradient(180deg, #1f9e70, #17835c); border-color:#1f9e70; color:#f2fff8; }
.admin-card .btn.primary:hover { filter:brightness(1.08); }
.admin-card .btn svg { width:14px; height:14px; }
"""

with open(r'e:\Nid\frontend\src\index.css', 'a') as f:
    f.write('\n\n' + css)
