// PATH: vulnassess-web/src/screens/Dashboard.jsx
import React, { useEffect, useState } from 'react';
import { api } from '../api';
import { DashboardSkeleton } from './Skeletons';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

const statusClass = st => ({
  completed: 'va-badge-completed',
  running:   'va-badge-running',
  failed:    'va-badge-failed',
  pending:   'va-badge-pending',
})[st] || 'va-badge-pending';

export default function Dashboard({ setScreen }) {
  const [scans,   setScans]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [proxyEnabled, setProxyEnabled] = useState(false);
  const [proxyUrl, setProxyUrl] = useState('');
  const [proxyType, setProxyType] = useState('http');
  const [proxyMsg, setProxyMsg] = useState('');

  useEffect(() => {
    api.getScans()
      .then(d => { setScans(Array.isArray(d) ? d : []); setLoading(false); })
      .catch(()  => setLoading(false));

    api.getProfile().then(p => {
      const cfg = p?.proxy_settings || {};
      setProxyEnabled(!!cfg.proxy_enabled);
      setProxyUrl(cfg.proxy_url || '');
      setProxyType(cfg.proxy_type || 'http');
    }).catch(() => {});
  }, []);

  const saveProxy = async () => {
    setProxyMsg('');
    const res = await api.updateProxySettings(proxyEnabled, proxyEnabled ? proxyUrl : null, proxyType).catch(() => null);
    if (res?.message) setProxyMsg('Proxy settings updated');
    else setProxyMsg(res?.detail || 'Failed to update proxy');
  };

  const total     = scans.length;
  const completed = scans.filter(s => s.status === 'completed').length;
  const running   = scans.filter(s => s.status === 'running').length;
  const failed    = scans.filter(s => s.status === 'failed').length;
  const allVulns  = scans.filter(s => s.status === 'completed')
                         .reduce((a, s) => a + (s.total_vulnerabilities || 0), 0);
  const critical  = scans.filter(s => s.status === 'completed')
                         .reduce((a, s) => a + (s.severity_counts?.critical || 0), 0);

  const stats = [
    { label:'TOTAL SCANS', value:total,     icon:'◎', color:'var(--accent)'  },
    { label:'COMPLETED',   value:completed,  icon:'✓', color:'var(--low)'     },
    { label:'RUNNING',     value:running,    icon:'◌', color:'var(--yellow)'  },
    { label:'TOTAL VULNS', value:allVulns,   icon:'⚠', color:'var(--orange)'  },
    { label:'CRITICAL',    value:critical,   icon:'☢', color:'var(--red)'     },
    { label:'FAILED',      value:failed,     icon:'✕', color:'var(--muted)'   },
  ];

  // Prepare chart data
  const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const scanCountsByMonth = {};
  
  scans.forEach(s => {
    if (s.created_at) {
      const d = new Date(s.created_at);
      const key = `${monthNames[d.getMonth()]} ${d.getFullYear()}`;
      if (!scanCountsByMonth[key]) scanCountsByMonth[key] = { name: key, scans: 0, vulns: 0 };
      scanCountsByMonth[key].scans += 1;
      if (s.status === 'completed') scanCountsByMonth[key].vulns += (s.total_vulnerabilities || 0);
    }
  });

  const chartData = Object.values(scanCountsByMonth);

  if (loading) return <DashboardSkeleton />;

  return (
    <div className="va-page animate-in">

      {/* Header */}
      <div className="va-page-header">
        <div>
          <h1 className="va-page-title">OPERATIONS OVERVIEW</h1>
          <p className="va-page-sub">Real-time vulnerability intelligence</p>
        </div>
        <button className="va-btn-primary" onClick={() => setScreen('new-scan')}>
          ⊕ LAUNCH SCAN
        </button>
      </div>

      {/* Stats */}
      <div className="va-stats-grid">
        {stats.map(st => (
          <div key={st.label} className="va-stat-card" style={{ borderLeftColor: st.color }}>
            <div className="va-stat-icon" style={{ color: st.color }}>{st.icon}</div>
            <div>
              <div className="va-stat-value" style={{ color: st.color }}>
                {st.value}
              </div>
              <div className="va-stat-label">{st.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Web Chart */}
      <div className="va-card" style={{ marginBottom: 20 }}>
        <div className="va-section-title">VULNERABILITY INTELLIGENCE TRENDS</div>
        <div style={{ width: '100%', height: 300, padding: '10px 0' }}>
          {chartData.length > 0 ? (
            <ResponsiveContainer>
              <BarChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                <XAxis dataKey="name" stroke="var(--textMuted)" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="var(--textMuted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip cursor={{ fill: 'var(--bg2)' }} contentStyle={{ backgroundColor: 'var(--card)', borderColor: 'var(--border)', borderRadius: 8 }} />
                <Bar dataKey="scans" name="Scans Run" fill="var(--accent)" radius={[4, 4, 0, 0]} maxBarSize={40} />
                <Bar dataKey="vulns" name="Vulnerabilities Found" fill="var(--orange)" radius={[4, 4, 0, 0]} maxBarSize={40} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="va-center">
              <p>No scanning data available for charts.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}