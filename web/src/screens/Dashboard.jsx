// PATH: vulnassess-web/src/screens/Dashboard.jsx
import React, { useEffect, useState } from 'react';
import { api } from '../api';
import { DashboardSkeleton } from './Skeletons';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell, AreaChart, Area, PieChart, Pie } from 'recharts';

const statusClass = st => ({
  completed: 'va-badge-completed',
  running:   'va-badge-running',
  failed:    'va-badge-failed',
  pending:   'va-badge-pending',
})[st] || 'va-badge-pending';

export default function Dashboard({ setScreen }) {
  const [scans,   setScans]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchText, setSearchText] = useState('');
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
  const latestMonth = chartData[chartData.length - 1] || { scans: 0, vulns: 0 };
  const previousMonth = chartData[chartData.length - 2] || latestMonth;
  const vulnDelta = latestMonth.vulns - previousMonth.vulns;
  const scanDelta = latestMonth.scans - previousMonth.scans;
  const chartSeries = chartData.map(item => ({
    ...item,
    scanRate: item.scans,
    vulnRate: item.vulns,
  }));

  const filteredScans = scans.filter(scan => {
    const term = searchText.trim().toLowerCase();
    if (!term) return true;
    return [scan.target_url, scan.status, scan.current_step]
      .filter(Boolean)
      .some(value => String(value).toLowerCase().includes(term));
  });

  const sideCards = [
    { label: 'Latest scans', value: latestMonth.scans, hint: `${scanDelta >= 0 ? '+' : ''}${scanDelta} vs previous month`, tone: 'var(--accent)' },
    { label: 'Latest vulns', value: latestMonth.vulns, hint: `${vulnDelta >= 0 ? '+' : ''}${vulnDelta} vs previous month`, tone: 'var(--orange)' },
    { label: 'Completion rate', value: total ? `${Math.round((completed / total) * 100)}%` : '0%', hint: `${completed} of ${total} scans`, tone: 'var(--low)' },
  ];

  if (loading) return <DashboardSkeleton />;

  const completionPct = total ? Math.round((completed / total) * 100) : 0;
  const memberTypeData = [
    { name: 'Completed', value: completed, color: 'var(--low)' },
    { name: 'Running', value: running, color: 'var(--yellow)' },
    { name: 'Failed', value: failed, color: 'var(--red)' },
  ];
  const severityBarData = [
    { name: 'Critical', value: critical, color: 'var(--red)' },
    { name: 'Other', value: Math.max(0, allVulns - critical), color: 'var(--orange)' },
  ];

  return (
    <div className="va-page va-dashboard-page animate-in">

      {/* Header */}
      <div className="va-page-header">
        <div>
          <h1 className="va-page-title">OPERATIONS OVERVIEW</h1>
          <p className="va-page-sub">Real-time vulnerability intelligence</p>
        </div>
        <div className="va-header-actions">
          <div className="va-search-shell">
            <span className="va-search-icon">⌕</span>
            <input
              className="va-search-input"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              placeholder="Search scans, URLs, status"
            />
          </div>
          <button className="va-btn-secondary" onClick={() => setScreen('scans')}>
            OPEN SCANS
          </button>
          <button className="va-btn-primary" onClick={() => setScreen('new-scan')}>
            ⊕ LAUNCH SCAN
          </button>
        </div>
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

      <div className="va-dashboard-grid">
        <div className="va-card va-dashboard-main">
          <div className="va-card-head">
            <div>
              <div className="va-section-title">VULNERABILITY INTELLIGENCE TRENDS</div>
              <div className="va-card-sub">Monthly scan activity and findings</div>
            </div>
            <div className="va-trend-pill">LIVE TREND</div>
          </div>

          <div className="va-chart-box" style={{ width: '100%', padding: '8px 0 0' }}>
            {chartSeries.length > 0 ? (
              <ResponsiveContainer>
                <AreaChart data={chartSeries} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="scanFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--accent)" stopOpacity={0.42} />
                      <stop offset="95%" stopColor="var(--accent)" stopOpacity={0.02} />
                    </linearGradient>
                    <linearGradient id="vulnFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--orange)" stopOpacity={0.42} />
                      <stop offset="95%" stopColor="var(--orange)" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="4 6" opacity={0.45} />
                  <XAxis dataKey="name" stroke="var(--textMuted)" fontSize={12} tickLine={false} axisLine={false} />
                  <YAxis stroke="var(--textMuted)" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip
                    cursor={{ fill: 'var(--bg2)' }}
                    contentStyle={{ backgroundColor: 'var(--card)', borderColor: 'var(--border)', borderRadius: 12 }}
                  />
                  <Area type="monotone" dataKey="scans" name="Scans Run" stroke="var(--accent)" fill="url(#scanFill)" strokeWidth={3} dot={{ r: 3 }} activeDot={{ r: 5 }} />
                  <Area type="monotone" dataKey="vulns" name="Vulnerabilities Found" stroke="var(--orange)" fill="url(#vulnFill)" strokeWidth={3} dot={{ r: 3 }} activeDot={{ r: 5 }} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="va-center">
                <p>No scanning data available for charts.</p>
              </div>
            )}
          </div>
        </div>

        <div className="va-dashboard-side">
          <div className="va-card va-side-stack">
            <div className="va-card-head">
              <div>
                <div className="va-section-title">FAST INSIGHTS</div>
                <div className="va-card-sub">Recent activity summary</div>
              </div>
            </div>
            <div className="va-side-cards">
              {sideCards.map(card => (
                <div className="va-side-card" key={card.label} style={{ borderLeftColor: card.tone }}>
                  <div className="va-side-card-label">{card.label}</div>
                  <div className="va-side-card-value" style={{ color: card.tone }}>{card.value}</div>
                  <div className="va-side-card-hint">{card.hint}</div>
                </div>
              ))}
            </div>

            <div className="va-mini-chart-wrap">
              <div className="va-section-title" style={{ marginBottom: 8 }}>MEMBER TYPE</div>
              <div className="va-chart-box-small" style={{ width: '100%' }}>
                {total > 0 ? (
                  <ResponsiveContainer>
                    <PieChart>
                      <Pie data={memberTypeData} dataKey="value" nameKey="name" cx="50%" cy="52%" innerRadius={44} outerRadius={70} paddingAngle={4}>
                        {memberTypeData.map((entry) => (
                          <Cell key={entry.name} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: 'var(--card)', borderColor: 'var(--border)', borderRadius: 12 }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="va-center">
                    <p>No member data available.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="va-dashboard-bottom-grid">
        <div className="va-card">
          <div className="va-card-head">
            <div>
              <div className="va-section-title">SEVERITY SNAPSHOT</div>
              <div className="va-card-sub">Critical vs non-critical findings</div>
            </div>
          </div>
          <div className="va-chart-box-small" style={{ width: '100%' }}>
            <ResponsiveContainer>
              <BarChart data={severityBarData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="4 6" opacity={0.28} vertical={false} />
                <XAxis dataKey="name" stroke="var(--textMuted)" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="var(--textMuted)" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--card)', borderColor: 'var(--border)', borderRadius: 12 }} />
                <Bar dataKey="value" radius={[8, 8, 0, 0]} barSize={28}>
                  {severityBarData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="va-card">
          <div className="va-card-head">
            <div>
              <div className="va-section-title">RUN SUMMARY</div>
              <div className="va-card-sub">Quick operational metrics</div>
            </div>
          </div>
          <div className="va-mini-list-items">
            <div className="va-mini-list-item">
              <div>
                <div className="va-mini-list-title">Completion</div>
                <div className="va-mini-list-sub">Successfully completed scans</div>
              </div>
              <span className="va-badge va-badge-completed">{completionPct}%</span>
            </div>
            <div className="va-mini-list-item">
              <div>
                <div className="va-mini-list-title">Latest target</div>
                <div className="va-mini-list-sub">Most recent scan URL</div>
              </div>
              <span className="va-badge va-badge-info">{(filteredScans[0]?.target_url || 'n/a').slice(0, 28)}</span>
            </div>
            <div className="va-mini-list-item">
              <div>
                <div className="va-mini-list-title">Health</div>
                <div className="va-mini-list-sub">Running queue state</div>
              </div>
              <span className={`va-badge ${running ? 'va-badge-running' : 'va-badge-completed'}`}>{running ? `${running} running` : 'idle'}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}