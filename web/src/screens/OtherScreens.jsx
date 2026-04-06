// PATH: vulnassess-web/src/screens/OtherScreens.jsx
import React, { useEffect, useState } from 'react';
import { api } from '../api';
import { ProfileSkeleton, TableSkeleton } from './Skeletons';

const PLAN_CATALOG = {
  monthly: {
    key: 'monthly',
    title: 'Monthly Plan',
    price: 5,
    suffix: '/month',
    features: [
      'AI remediation for all completed scans',
      'Priority remediation formatting',
      'Monthly billing and renewal',
    ],
  },
  yearly: {
    key: 'yearly',
    title: 'Yearly Plan',
    price: 50,
    suffix: '/year',
    features: [
      'Everything in Monthly plan',
      'Discounted annual billing',
      'Extended subscription validity',
    ],
  },
};

const FX_RATES = {
  USD: 1,
  INR: 83,
};

const detectRegionalCurrency = () => {
  const locale = (
    (typeof navigator !== 'undefined' && ((navigator.languages && navigator.languages[0]) || navigator.language)) || ''
  ).toUpperCase();
  return /(?:-|_)IN\b/.test(locale) ? 'INR' : 'USD';
};

const convertUsdAmount = (usdAmount, currency) => {
  const rate = FX_RATES[currency] || 1;
  return Number((Number(usdAmount || 0) * rate).toFixed(2));
};

const formatCurrency = (amount, currency) => {
  const locale = currency === 'INR' ? 'en-IN' : 'en-US';
  return new Intl.NumberFormat(locale, {
    style: 'currency',
    currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(Number(amount || 0));
};

// ── SCHEDULE ──────────────────────────────────────────────────────────────────
export function Schedule() {
  const [schedules, setSchedules] = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [showForm,  setShowForm]  = useState(false);
  const [target,    setTarget]    = useState('');
  const [freq,      setFreq]      = useState('daily');
  const [time,      setTime]      = useState('02:00');
  const [error,     setError]     = useState('');
  const [saving,    setSaving]    = useState(false);

  const load = async () => {
    const d = await api.getSchedules().catch(() => []);
    setSchedules(Array.isArray(d) ? d : []);
    setLoading(false);
  };
  useEffect(() => { load(); }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!target) { setError('Target required'); return; }
    setSaving(true);
    let url = target.trim();
    if (!url.startsWith('http')) url = 'https://' + url;
    const res = await api.createSchedule({ target_url: url, timeframe: freq }).catch(() => null);
    setSaving(false);
    if (res && (res._id || res.id)) { setShowForm(false); setTarget(''); load(); }
    else setError(res?.detail || 'Failed');
  };

  return (
    <div className="va-page animate-in">
      <div className="va-page-header">
        <div>
          <h1 className="va-page-title">SCHEDULED SCANS</h1>
          <p className="va-page-sub">Automate recurring vulnerability scans</p>
        </div>
        <button className="va-btn-primary" onClick={() => setShowForm(v => !v)}>
          {showForm ? '✕ CANCEL' : '⊕ NEW SCHEDULE'}
        </button>
      </div>

      {showForm && (
        <div className="va-card">
          <div className="va-section-title">CREATE SCHEDULE</div>
          {error && <div className="va-error">⚠ {error}</div>}
          <form onSubmit={handleCreate}>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12, marginBottom:16 }}>
              <div className="va-field">
                <label className="va-label">TARGET URL</label>
                <input value={target} onChange={e => { setTarget(e.target.value); setError(''); }} placeholder="https://example.com" />
              </div>
              <div className="va-field">
                <label className="va-label">FREQUENCY</label>
                <select value={freq} onChange={e => setFreq(e.target.value)}>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>
              <div className="va-field">
                <label className="va-label">TIME</label>
                <input type="time" value={time} onChange={e => setTime(e.target.value)} />
              </div>
            </div>
            <button type="submit" className="va-btn-primary" disabled={saving}>
              {saving ? '◌ SAVING...' : '→ CREATE'}
            </button>
          </form>
        </div>
      )}

      {loading ? (
        <TableSkeleton rows={4} />
      ) : schedules.length === 0 ? (
        <div className="va-center">
          <span className="va-empty-icon">◷</span>
          <p>No schedules configured</p>
        </div>
      ) : (
        <div className="va-table-wrap">
          <table style={{ width:'100%', borderCollapse:'collapse' }}>
            <thead>
              <tr>
                {['TARGET','FREQUENCY','TIME','STATUS','LAST RUN','ACTIONS'].map(h => (
                  <th key={h} className="va-th" style={{ padding:'10px 14px', textAlign:'left' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {schedules.map((sc, i) => (
                <tr key={sc._id || sc.id}
                  style={{ borderBottom:'1px solid var(--border)', background: i%2===1?'var(--bg2)':'transparent' }}>
                  <td className="va-td-url" style={{ padding:'10px 14px' }}>{sc.target_url}</td>
                  <td className="va-td-mono" style={{ padding:'10px 14px' }}>{(sc.timeframe_label || sc.timeframe)?.toUpperCase()}</td>
                  <td className="va-td-mono" style={{ padding:'10px 14px' }}>{sc.time || '—'}</td>
                  <td style={{ padding:'10px 14px' }}>
                    <span className={`va-badge ${sc.is_active ? 'va-badge-completed' : 'va-badge-pending'}`}>
                      {sc.is_active ? '● ACTIVE' : '○ PAUSED'}
                    </span>
                  </td>
                  <td className="va-td-mono" style={{ padding:'10px 14px' }}>
                    {sc.last_run ? new Date(sc.last_run).toLocaleDateString() : '—'}
                  </td>
                  <td style={{ padding:'10px 14px' }}>
                    <div style={{ display:'flex', gap:6 }}>
                      <button className="va-tbl-btn"
                        onClick={async () => { await api.toggleSchedule(sc._id||sc.id, !sc.is_active); load(); }}>
                        {sc.is_active ? 'PAUSE' : 'RESUME'}
                      </button>
                      <button className="va-tbl-btn-del"
                        onClick={async () => { if (window.confirm('Delete?')) { await api.deleteSchedule(sc._id||sc.id); load(); } }}>
                        ✕
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── COMPARE ───────────────────────────────────────────────────────────────────
export function Compare() {
  const [scans,   setScans]   = useState([]);
  const [scan1,   setScan1]   = useState('');
  const [scan2,   setScan2]   = useState('');
  const [result,  setResult]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');
  const [tab,     setTab]     = useState('overview');

  useEffect(() => {
    api.getScans().then(d => setScans(Array.isArray(d) ? d.filter(s => s.status === 'completed') : []));
  }, []);

  const handle = async () => {
    if (!scan1 || !scan2)  { setError('Select both scans'); return; }
    if (scan1 === scan2)   { setError('Select two different scans'); return; }
    setLoading(true); setError('');
    try {
      const res = await api.compareScans(scan1, scan2);
      // Safe error extraction — prevent React #31 crash from object detail
      if (res && res.scan1 && res.scan2 && res.summary) {
        setResult(res);
        setTab('overview');
      } else {
        const detail = typeof res?.detail === 'string' ? res.detail
          : Array.isArray(res?.detail) ? res.detail.map(e => e.msg || JSON.stringify(e)).join(', ')
          : 'Comparison failed';
        setError(detail);
      }
    } catch { setError('Cannot connect to server'); }
    setLoading(false);
  };

  const sevClass = s => ({
    Critical:'va-badge-critical', High:'va-badge-high',
    Medium:'va-badge-medium', Low:'va-badge-low', Info:'va-badge-info',
    critical:'va-badge-critical', high:'va-badge-high',
    medium:'va-badge-medium', low:'va-badge-low', info:'va-badge-info',
  })[s] || 'va-badge-info';

  const truncateUrl = url => url?.length > 45 ? url.slice(0, 42) + '...' : url;

  const FindingRow = ({ v, i }) => (
    <div key={i} style={{ display:'flex', alignItems:'center', gap:10, padding:'8px 0',
      borderBottom:'1px solid var(--border)' }}>
      <span className={`va-badge ${sevClass(v.severity)}`}>{v.severity?.toUpperCase()}</span>
      <span style={{ fontSize:13, color:'var(--text)', fontWeight:600, flex:1 }}>{v.name}</span>
      {v.url && <span style={{ fontSize:11, color:'var(--muted)', fontFamily:'monospace' }}
        title={v.url}>{truncateUrl(v.url)}</span>}
    </div>
  );

  return (
    <div className="va-page animate-in">
      <div className="va-page-header">
        <div>
          <h1 className="va-page-title">COMPARE SCANS</h1>
          <p className="va-page-sub">Diff two completed scans to track progress</p>
        </div>
      </div>

      <div className="va-card">
        <div className="va-section-title">SELECT SCANS TO COMPARE</div>
        {error && <div className="va-error">⚠ {error}</div>}
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16, marginBottom:16 }}>
          <div className="va-field">
            <label className="va-label">SCAN A</label>
            <select value={scan1} onChange={e => { setScan1(e.target.value); setError(''); setResult(null); }}>
              <option value="">Select scan...</option>
              {scans.map(s => (
                <option key={s._id||s.id} value={s._id||s.id}>
                  {truncateUrl(s.target_url || s.target)} — {new Date(s.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          </div>
          <div className="va-field">
            <label className="va-label">SCAN B</label>
            <select value={scan2} onChange={e => { setScan2(e.target.value); setError(''); setResult(null); }}>
              <option value="">Select scan...</option>
              {scans.map(s => (
                <option key={s._id||s.id} value={s._id||s.id}>
                  {truncateUrl(s.target_url || s.target)} — {new Date(s.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          </div>
        </div>
        <button className="va-btn-primary" onClick={handle} disabled={loading}>
          {loading ? '◌ COMPARING...' : '⇄ COMPARE NOW'}
        </button>
      </div>

      {result && (() => {
        const { scan1: s1, scan2: s2, summary } = result;
        const scoreDiff = summary.score_diff;
        const improved  = summary.improved;
        const TABS = [
          { key:'overview', label:'Overview' },
          { key:'new',      label:`New (${summary.new_findings_count})` },
          { key:'fixed',    label:`Fixed (${summary.fixed_findings_count})` },
          { key:'all',      label:`All (${s2.total_findings})` },
        ];
        return (
          <div className="animate-in">
            {/* Score cards */}
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12, marginBottom:16 }}>
              {[
                { label:'NEW ISSUES',   value:summary.new_findings_count,   color:'var(--critical)' },
                { label:'FIXED',        value:summary.fixed_findings_count,  color:'var(--low)'      },
                { label:'PERSISTING',   value:summary.common_findings_count, color:'var(--high)'     },
              ].map(m => (
                <div key={m.label} className="va-stat-card" style={{ borderLeftColor:m.color }}>
                  <div>
                    <div className="va-stat-value" style={{ color:m.color }}>{m.value}</div>
                    <div className="va-stat-label">{m.label}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Risk score comparison */}
            <div className="va-card" style={{ marginBottom:12 }}>
              <div className="va-section-title">RISK SCORE COMPARISON</div>
              <div style={{ display:'flex', alignItems:'center', justifyContent:'space-around', padding:'12px 0' }}>
                <div style={{ textAlign:'center' }}>
                  <div style={{ fontSize:11, color:'var(--muted)', marginBottom:4 }}>SCAN A</div>
                  <div style={{ fontSize:11, color:'var(--muted)', marginBottom:8 }}
                    title={s1.target_url}>{truncateUrl(s1.target_url)}</div>
                  <div style={{ fontSize:36, fontWeight:700, color: s1.severity_color || 'var(--text)' }}>
                    {s1.total_risk_score?.toFixed(1)}
                  </div>
                  <div style={{ fontSize:12, color: s1.severity_color }}>{s1.severity_label}</div>
                </div>
                <div style={{ textAlign:'center' }}>
                  <div style={{ fontSize:28, color:'var(--muted)' }}>{improved ? '↓' : scoreDiff===0 ? '=' : '↑'}</div>
                  <div style={{ fontSize:15, fontWeight:700,
                    color: improved ? 'var(--low)' : scoreDiff===0 ? 'var(--muted)' : 'var(--critical)' }}>
                    {scoreDiff===0 ? 'No change' : `${improved?'':'+'}${scoreDiff?.toFixed(1)}`}
                  </div>
                  <div style={{ fontSize:11, color:'var(--muted)' }}>{improved ? 'Improved' : scoreDiff===0 ? 'Same' : 'Worsened'}</div>
                </div>
                <div style={{ textAlign:'center' }}>
                  <div style={{ fontSize:11, color:'var(--muted)', marginBottom:4 }}>SCAN B</div>
                  <div style={{ fontSize:11, color:'var(--muted)', marginBottom:8 }}
                    title={s2.target_url}>{truncateUrl(s2.target_url)}</div>
                  <div style={{ fontSize:36, fontWeight:700, color: s2.severity_color || 'var(--text)' }}>
                    {s2.total_risk_score?.toFixed(1)}
                  </div>
                  <div style={{ fontSize:12, color: s2.severity_color }}>{s2.severity_label}</div>
                </div>
              </div>
            </div>

            {/* Tabs */}
            <div style={{ display:'flex', gap:4, marginBottom:12, borderBottom:'1px solid var(--border)', paddingBottom:4 }}>
              {TABS.map(t => (
                <button key={t.key} onClick={() => setTab(t.key)}
                  style={{ padding:'6px 14px', borderRadius:'6px 6px 0 0', border:'none', cursor:'pointer',
                    fontFamily:'var(--font)', fontSize:13, fontWeight:600,
                    background: tab===t.key ? 'var(--accent)' : 'transparent',
                    color: tab===t.key ? 'var(--card)' : 'var(--muted2)' }}>
                  {t.label}
                </button>
              ))}
            </div>

            {/* Tab content */}
            {tab === 'overview' && (
              <div className="va-card">
                <div className="va-section-title">SEVERITY BREAKDOWN</div>
                {['Critical','High','Medium','Low'].map(sev => {
                  const c1 = s1.severity_counts?.[sev] || 0;
                  const c2 = s2.severity_counts?.[sev] || 0;
                  const diff = c2 - c1;
                  const sevColors = { Critical:'var(--critical)', High:'var(--high)', Medium:'var(--medium)', Low:'var(--low)' };
                  return (
                    <div key={sev} style={{ display:'flex', alignItems:'center', padding:'8px 0',
                      borderBottom:'1px solid var(--border)', gap:12 }}>
                      <span style={{ width:70, fontSize:13, fontWeight:700, color:sevColors[sev] }}>{sev}</span>
                      <span style={{ width:28, fontSize:15, fontWeight:700, textAlign:'center', color:'var(--text)' }}>{c1}</span>
                      <span style={{ color:'var(--muted)', fontSize:14 }}>→</span>
                      <span style={{ width:28, fontSize:15, fontWeight:700, textAlign:'center', color:'var(--text)' }}>{c2}</span>
                      <span style={{ marginLeft:8, fontSize:13, fontWeight:700,
                        color: diff<0 ? 'var(--low)' : diff>0 ? 'var(--critical)' : 'var(--muted)' }}>
                        {diff>0 ? `+${diff}` : diff===0 ? '—' : diff}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}

            {tab === 'new' && (
              <div className="va-card va-card-accent" style={{ borderLeftColor:'var(--critical)' }}>
                <div className="va-section-title" style={{ color:'var(--critical)' }}>
                  NEW ISSUES ({summary.new_findings_count})
                </div>
                <p style={{ fontSize:13, color:'var(--muted)', marginBottom:12 }}>
                  Found in Scan B but not in Scan A
                </p>
                {summary.new_findings.length === 0
                  ? <p style={{ color:'var(--muted)', fontSize:13 }}>No new issues — great!</p>
                  : summary.new_findings.map((v, i) => <FindingRow key={i} v={v} i={i} />)
                }
              </div>
            )}

            {tab === 'fixed' && (
              <div className="va-card va-card-accent" style={{ borderLeftColor:'var(--low)' }}>
                <div className="va-section-title" style={{ color:'var(--low)' }}>
                  FIXED ISSUES ({summary.fixed_findings_count})
                </div>
                <p style={{ fontSize:13, color:'var(--muted)', marginBottom:12 }}>
                  Were in Scan A but resolved by Scan B
                </p>
                {summary.fixed_findings.length === 0
                  ? <p style={{ color:'var(--muted)', fontSize:13 }}>No issues fixed yet.</p>
                  : summary.fixed_findings.map((v, i) => <FindingRow key={i} v={v} i={i} />)
                }
              </div>
            )}

            {tab === 'all' && (
              <div className="va-card">
                <div className="va-section-title">ALL FINDINGS IN SCAN B ({s2.total_findings})</div>
                {s2.findings.length === 0
                  ? <p style={{ color:'var(--muted)', fontSize:13 }}>No vulnerabilities found.</p>
                  : s2.findings.map((v, i) => <FindingRow key={i} v={v} i={i} />)
                }
              </div>
            )}
          </div>
        );
      })()}
    </div>
  );
}

// ── PROFILE ───────────────────────────────────────────────────────────────────
export function Profile() {
  const [profile,     setProfile]     = useState(null);
  const [subscription, setSubscription] = useState(null);
  const [plan, setPlan] = useState('monthly');
  const [paymentMethod, setPaymentMethod] = useState('upi');
  const [upiId, setUpiId] = useState('');
  const [cardLast4, setCardLast4] = useState('');
  const [cryptoNetwork, setCryptoNetwork] = useState('');
  const [cryptoWallet, setCryptoWallet] = useState('');
  const [displayCurrency, setDisplayCurrency] = useState('USD');
  const [txId, setTxId] = useState('');
  const [receiptUrl, setReceiptUrl] = useState('');
  const [subMsg, setSubMsg] = useState('');
  const [name,        setName]        = useState('');
  const [currPass,    setCurrPass]    = useState('');
  const [newPass,     setNewPass]     = useState('');
  const [saving,      setSaving]      = useState(false);
  const [passLoading, setPassLoading] = useState(false);
  const [msg,         setMsg]         = useState('');
  const [passMsg,     setPassMsg]     = useState('');

  useEffect(() => {
    setDisplayCurrency(detectRegionalCurrency());
    api.getProfile().then(d => { setProfile(d); setName(d.full_name || ''); });
    api.getSubscription().then(setSubscription).catch(() => {});
  }, []);

  useEffect(() => {
    if (displayCurrency !== 'INR' && paymentMethod === 'upi') {
      setPaymentMethod('debit_card');
    }
  }, [displayCurrency, paymentMethod]);

  const loadSubscription = async () => {
    const s = await api.getSubscription().catch(() => null);
    if (s) setSubscription(s);
  };

  const handleSubscription = async (e) => {
    e.preventDefault();
    setSubMsg('');
    if (!txId.trim() || txId.trim().length < 8) {
      setSubMsg('Transaction ID must be at least 8 characters');
      return;
    }
    if (!receiptUrl.trim()) {
      setSubMsg('Receipt URL is required');
      return;
    }

    if (paymentMethod === 'upi' && !upiId.trim()) {
      setSubMsg('UPI ID is required for UPI payments');
      return;
    }
    if (paymentMethod === 'debit_card' && (cardLast4 || '').replace(/\D/g, '').length < 4) {
      setSubMsg('Enter valid debit card last 4 digits');
      return;
    }
    if (paymentMethod === 'crypto' && (!cryptoNetwork.trim() || !cryptoWallet.trim())) {
      setSubMsg('Crypto network and wallet are required');
      return;
    }

    const selectedPlan = PLAN_CATALOG[plan] || PLAN_CATALOG.monthly;
    const convertedAmount = convertUsdAmount(selectedPlan.price, displayCurrency);
    const payload = {
      plan,
      amount: convertedAmount,
      transaction_id: txId.trim(),
      receipt_url: receiptUrl.trim(),
      currency: displayCurrency,
      payment_method: paymentMethod,
      upi_id: paymentMethod === 'upi' ? upiId.trim() : null,
      card_last4: paymentMethod === 'debit_card' ? (cardLast4 || '').replace(/\D/g, '').slice(-4) : null,
      crypto_network: paymentMethod === 'crypto' ? cryptoNetwork.trim() : null,
      crypto_wallet: paymentMethod === 'crypto' ? cryptoWallet.trim() : null,
    };
    const res = await api.requestSubscription(payload).catch(() => null);
    if (res?.id) {
      setSubMsg(res.message || 'Payment submitted');
      setTxId('');
      setReceiptUrl('');
      setUpiId('');
      setCardLast4('');
      setCryptoNetwork('');
      setCryptoWallet('');
      loadSubscription();
    } else {
      setSubMsg(res?.detail || 'Failed to submit payment');
    }
  };

  const handleSave = async (e) => {
    e.preventDefault(); setSaving(true); setMsg('');
    const res = await api.updateProfile(name).catch(() => null);
    setSaving(false);
    setMsg(res?.message || (res?.full_name ? 'Profile updated!' : 'Update failed'));
  };

  const handlePass = async (e) => {
    e.preventDefault(); setPassLoading(true); setPassMsg('');
    const res = await api.changePassword(currPass, newPass).catch(() => null);
    setPassLoading(false);
    if (res?.message && res.message.toLowerCase().includes('changed')) {
      setPassMsg('✓ Password changed successfully!');
      setCurrPass(''); setNewPass('');
    } else {
      setPassMsg(res?.detail || res?.message || 'Failed to change password');
    }
  };

  if (!profile) return <ProfileSkeleton />;

  const selectedPlan = PLAN_CATALOG[plan] || PLAN_CATALOG.monthly;
  const selectedDisplayAmount = convertUsdAmount(selectedPlan.price, displayCurrency);
  const paymentMethodOptions = displayCurrency === 'INR'
    ? [
        { key: 'upi', label: 'UPI' },
        { key: 'debit_card', label: 'DEBIT CARD' },
        { key: 'crypto', label: 'CRYPTO' },
      ]
    : [
        { key: 'debit_card', label: 'DEBIT CARD' },
        { key: 'crypto', label: 'CRYPTO' },
      ];

  return (
    <div className="va-page animate-in">
      <div className="va-page-header">
        <div>
          <h1 className="va-page-title">PROFILE</h1>
          <p className="va-page-sub">Manage your account settings</p>
        </div>
      </div>
      <div className="va-two-col-grid">

        <div className="va-card">
          <div className="va-section-title">ACCOUNT INFO</div>
          <div style={{ width:64, height:64, borderRadius:'50%', background:'var(--accent)', color:'var(--card)',
                        display:'flex', alignItems:'center', justifyContent:'center',
                        fontFamily:'var(--font-mono)', fontSize:26, fontWeight:700, margin:'0 auto 16px' }}>
            {(profile.email || 'U')[0].toUpperCase()}
          </div>
          <div style={{ textAlign:'center', marginBottom:20 }}>
            <div style={{ fontFamily:'var(--font-mono)', color:'var(--accent)', fontSize:14 }}>{profile.email}</div>
            <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--muted)', marginTop:4 }}>
              {profile.role === 'admin' ? '★ ADMIN' : '◆ USER'} · {profile.is_active ? '● ACTIVE' : '○ INACTIVE'}
            </div>
          </div>
          <form onSubmit={handleSave}>
            <div className="va-field">
              <label className="va-label">DISPLAY NAME</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="Your name" />
            </div>
            {msg && (
              <div className={msg.toLowerCase().includes('fail') ? 'va-error' : 'va-success'} style={{ marginBottom:12 }}>
                {msg}
              </div>
            )}
            <button type="submit" className="va-btn-primary va-btn-full" disabled={saving}>
              {saving ? '◌ SAVING...' : '→ SAVE PROFILE'}
            </button>
          </form>
        </div>

        <div className="va-card">
          <div className="va-section-title">CHANGE PASSWORD</div>
          <form onSubmit={handlePass}>
            <div className="va-field">
              <label className="va-label">CURRENT PASSWORD</label>
              <input type="password" value={currPass} onChange={e => setCurrPass(e.target.value)} placeholder="••••••••" />
            </div>
            <div className="va-field">
              <label className="va-label">NEW PASSWORD</label>
              <input type="password" value={newPass} onChange={e => setNewPass(e.target.value)} placeholder="••••••••" />
            </div>
            {passMsg && (
              <div className={passMsg.includes('changed') ? 'va-success' : 'va-error'} style={{ marginBottom:12 }}>
                {passMsg}
              </div>
            )}
            <button type="submit" className="va-btn-primary va-btn-full" disabled={passLoading}>
              {passLoading ? '◌ UPDATING...' : '→ CHANGE PASSWORD'}
            </button>
          </form>
        </div>

        <div className="va-card" style={{ transform:'perspective(1000px) rotateX(1deg)' }}>
          <div className="va-section-title">AI FIX SUBSCRIPTION</div>
          <div style={{ marginBottom:12, fontSize:12, color:'var(--muted2)' }}>
            Status: {subscription?.subscription_status || profile?.subscription?.subscription_status || 'inactive'}
            {subscription?.subscription_expires_at && (
              <span> · Expires {new Date(subscription.subscription_expires_at).toLocaleDateString()}</span>
            )}
          </div>
          <form onSubmit={handleSubscription}>
            <div className="va-plan-grid">
              {Object.values(PLAN_CATALOG).map(p => (
                <button
                  key={p.key}
                  type="button"
                  className={`va-plan-card${plan === p.key ? ' active' : ''}`}
                  onClick={() => setPlan(p.key)}
                >
                  <div className="va-plan-title">{p.title}</div>
                  <div className="va-plan-price">{formatCurrency(convertUsdAmount(p.price, displayCurrency), displayCurrency)}</div>
                  <div className="va-plan-sub">{p.suffix}</div>
                  {p.features.map(feature => (
                    <span className="va-plan-feature" key={feature}>• {feature}</span>
                  ))}
                </button>
              ))}
            </div>

            <div className="va-hint" style={{ marginTop: 4 }}>
              Selected: <strong>{selectedPlan.title}</strong> ·
              {' '}<strong>{formatCurrency(selectedDisplayAmount, displayCurrency)}{selectedPlan.suffix}</strong>
              {displayCurrency === 'INR' && (
                <span>{' '}· Base {formatCurrency(selectedPlan.price, 'USD')}</span>
              )}
            </div>

            <div className="va-hint" style={{ marginTop: 4 }}>
              Billing currency based on your region: <strong>{displayCurrency}</strong>
            </div>

            <div className="va-field">
              <label className="va-label">PAYMENT METHOD</label>
              <select value={paymentMethod} onChange={e => setPaymentMethod(e.target.value)}>
                {paymentMethodOptions.map(m => (
                  <option key={m.key} value={m.key}>{m.label}</option>
                ))}
              </select>
            </div>

            {paymentMethod === 'upi' && (
              <div className="va-field">
                <label className="va-label">UPI ID</label>
                <input value={upiId} onChange={e => setUpiId(e.target.value)} placeholder="name@bank" />
              </div>
            )}

            {paymentMethod === 'debit_card' && (
              <div className="va-field">
                <label className="va-label">DEBIT CARD LAST 4 DIGITS</label>
                <input
                  value={cardLast4}
                  onChange={e => setCardLast4((e.target.value || '').replace(/\D/g, '').slice(-4))}
                  placeholder="1234"
                />
              </div>
            )}

            {paymentMethod === 'crypto' && (
              <>
                <div className="va-field">
                  <label className="va-label">CRYPTO NETWORK</label>
                  <input value={cryptoNetwork} onChange={e => setCryptoNetwork(e.target.value)} placeholder="USDT-TRC20 / BTC / ETH" />
                </div>
                <div className="va-field">
                  <label className="va-label">WALLET ADDRESS</label>
                  <input value={cryptoWallet} onChange={e => setCryptoWallet(e.target.value)} placeholder="Wallet address" />
                </div>
              </>
            )}

            <div className="va-field">
              <label className="va-label">TRANSACTION ID</label>
              <input value={txId} onChange={e => setTxId(e.target.value)} placeholder="TXN123456" />
            </div>
            <div className="va-field">
              <label className="va-label">RECEIPT URL</label>
              <input value={receiptUrl} onChange={e => setReceiptUrl(e.target.value)} placeholder="https://..." />
            </div>
            {subMsg && (
              <div className={subMsg.toLowerCase().includes('failed') ? 'va-error' : 'va-success'} style={{ marginBottom:12 }}>
                {subMsg}
              </div>
            )}
            <button type="submit" className="va-btn-primary va-btn-full">SUBMIT PAYMENT</button>
          </form>
        </div>
      </div>
    </div>
  );
}

// ── ADMIN ─────────────────────────────────────────────────────────────────────
export function Admin() {
  const [users,   setUsers]   = useState([]);
  const [stats,   setStats]   = useState(null);
  const [payments, setPayments] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    const [u, st, p] = await Promise.all([
      api.getUsers().catch(() => []),
      api.getAdminStats().catch(() => null),
      api.getPayments().catch(() => []),
    ]);
    setUsers(Array.isArray(u) ? u : []);
    setStats(st);
    setPayments(Array.isArray(p) ? p : []);
    setLoading(false);
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="va-page animate-in">
      <div className="va-page-header">
        <div>
          <h1 className="va-page-title">ADMIN PANEL</h1>
          <p className="va-page-sub">System management and user control</p>
        </div>
      </div>

      {stats && (
        <div className="va-stats-grid">
          {[
            { label:'TOTAL USERS',     value:stats.total_users,         color:'var(--accent)'   },
            { label:'TOTAL SCANS',     value:stats.total_scans,         color:'var(--low)'      },
            { label:'ACTIVE SCANS',    value:stats.active_scans,        color:'var(--yellow)'   },
            { label:'VULNERABILITIES', value:stats.total_vulnerabilities,color:'var(--critical)'},
          ].map(m => (
            <div key={m.label} className="va-stat-card" style={{ borderLeftColor:m.color }}>
              <div>
                <div className="va-stat-value" style={{ color:m.color }}>{m.value ?? '—'}</div>
                <div className="va-stat-label">{m.label}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {loading ? (
        <TableSkeleton rows={8} />
      ) : (
        <div style={{ display:'grid', gap:16 }}>
          <div className="va-table-wrap">
            <table style={{ width:'100%', borderCollapse:'collapse' }}>
              <thead>
                <tr>
                  {['EMAIL','ROLE','STATUS','JOINED','ACTIONS'].map(h => (
                    <th key={h} className="va-th" style={{ padding:'10px 14px', textAlign:'left' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.map((u, i) => (
                  <tr key={u._id || u.id}
                    style={{ borderBottom:'1px solid var(--border)', background: i%2===1?'var(--bg2)':'transparent' }}>
                    <td className="va-td-url" style={{ padding:'10px 14px' }}>{u.email}</td>
                    <td style={{ padding:'10px 14px' }}>
                      <span className={`va-badge ${u.role === 'admin' ? 'va-badge-running' : 'va-badge-pending'}`}>
                        {u.role === 'admin' ? '★ ADMIN' : '◆ USER'}
                      </span>
                    </td>
                    <td style={{ padding:'10px 14px' }}>
                      <span className={`va-badge ${u.is_active ? 'va-badge-completed' : 'va-badge-failed'}`}>
                        {u.is_active ? '● ACTIVE' : '○ INACTIVE'}
                      </span>
                    </td>
                    <td className="va-td-mono" style={{ padding:'10px 14px' }}>
                      {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                    </td>
                    <td style={{ padding:'10px 14px' }}>
                      <div style={{ display:'flex', gap:6 }}>
                        <button className="va-tbl-btn"
                          onClick={async () => { await api.updateUserRole(u._id||u.id, u.role==='admin'?'user':'admin'); load(); }}>
                          {u.role === 'admin' ? 'DEMOTE' : 'PROMOTE'}
                        </button>
                        <button className="va-tbl-btn"
                          onClick={async () => { await api.toggleUser(u._id||u.id, !u.is_active); load(); }}>
                          {u.is_active ? 'DISABLE' : 'ENABLE'}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="va-table-wrap" style={{ transform:'perspective(1000px) rotateX(1deg)' }}>
            <div style={{ padding:'10px 14px', fontFamily:'var(--font-mono)', fontSize:12, color:'var(--accent)' }}>
              PAYMENTS ({payments.length})
            </div>
            <table style={{ width:'100%', borderCollapse:'collapse' }}>
              <thead>
                <tr>
                  {['USER','PLAN','AMOUNT','STATUS','TRANSACTION','ACTIONS'].map(h => (
                    <th key={h} className="va-th" style={{ padding:'10px 14px', textAlign:'left' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {payments.map((p, i) => (
                  <tr key={p.id} style={{ borderBottom:'1px solid var(--border)', background: i%2===1?'var(--bg2)':'transparent' }}>
                    <td className="va-td-mono" style={{ padding:'10px 14px' }}>{(p.user_id || '').slice(0, 10)}...</td>
                    <td className="va-td-mono" style={{ padding:'10px 14px' }}>{(p.plan || '').toUpperCase()}</td>
                    <td className="va-td-mono" style={{ padding:'10px 14px' }}>{p.amount} {p.currency || 'USD'}</td>
                    <td style={{ padding:'10px 14px' }}>
                      <span className={`va-badge ${p.status === 'verified' ? 'va-badge-completed' : p.status === 'rejected' ? 'va-badge-failed' : 'va-badge-pending'}`}>
                        {(p.status || 'pending').toUpperCase()}
                      </span>
                    </td>
                    <td className="va-td-mono" style={{ padding:'10px 14px' }}>{p.transaction_id}</td>
                    <td style={{ padding:'10px 14px' }}>
                      <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
                        <button className="va-tbl-btn" onClick={async () => { await api.autoVerifyPayment(p.id); load(); }}>AUTO</button>
                        <button className="va-tbl-btn" onClick={async () => { await api.updatePaymentStatus(p.id, 'verified', 'Approved by admin'); load(); }}>VERIFY</button>
                        <button className="va-tbl-btn-del" onClick={async () => { await api.updatePaymentStatus(p.id, 'rejected', 'Rejected by admin'); load(); }}>REJECT</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}