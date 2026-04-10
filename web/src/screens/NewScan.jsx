// PATH: vulnassess-web/src/screens/NewScan.jsx
import React, { useState, useEffect } from 'react';
import { api } from '../api';

const ALL_MODULES = [
  { key:'auth_test',         label:'Authentication Testing',     desc:'Auth bypass & forced browsing',         fixed:true },
  { key:'sql_injection',     label:'SQL Injection',              desc:'Error, boolean & union-based SQLi'              },
  { key:'xss',               label:'Cross-Site Scripting (XSS)', desc:'Reflected & DOM-based XSS'                     },
  { key:'command_injection', label:'OS Command Injection',       desc:'Linux & Windows command injection'              },
  { key:'ssrf',              label:'SSRF',                       desc:'Server-side request forgery'                    },
  { key:'xxe',               label:'XXE Injection',              desc:'XML external entity attacks'                    },
  { key:'path_traversal',    label:'Path Traversal / LFI',       desc:'Directory traversal & file inclusion'           },
  { key:'idor',              label:'IDOR',                       desc:'Insecure direct object reference'               },
  { key:'open_redirect',     label:'Open Redirect',              desc:'Unvalidated URL redirect'                       },
  { key:'file_upload',       label:'File Upload',                desc:'Unrestricted file upload / RCE'                 },
  { key:'csrf',              label:'CSRF Protection',            desc:'Cross-site request forgery'                     },
  { key:'security_headers',  label:'Security Headers',           desc:'Missing HTTP security headers'                  },
  { key:'ssl_tls',           label:'SSL / TLS Analysis',         desc:'HTTPS & certificate checks'                    },
  { key:'cors_check',        label:'CORS Misconfiguration',      desc:'Cross-origin resource sharing'                  },
  { key:'cookie_security',   label:'Cookie Security',            desc:'HttpOnly, Secure, SameSite flags'               },
  { key:'clickjacking',      label:'Clickjacking',               desc:'X-Frame-Options & CSP check'                    },
  { key:'info_disclosure',   label:'Information Disclosure',     desc:'Sensitive files & data leakage'                 },
  { key:'rate_limiting',     label:'Rate Limiting',              desc:'Brute force protection check'                   },
  { key:'graphql',           label:'GraphQL Security',           desc:'Introspection & BOLA attacks'                   },
  { key:'api_key_leakage',   label:'API Key Leakage',            desc:'Secrets in JS & error pages'                    },
  { key:'jwt',               label:'JWT Security',               desc:'Algorithm confusion & weak secrets'             },
  { key:'rate_limit',        label:'Rate Limit Bypass',          desc:'IP spoofing header bypass'                      },
];

export default function NewScan({ setScreen }) {
  const [target,       setTarget]       = useState('');
  const [selected,     setSelected]     = useState(ALL_MODULES.map(m => m.key));
  const [loading,      setLoading]      = useState(false);
  const [verifying,    setVerifying]    = useState(false);
  const [error,        setError]        = useState('');
  const [verifyToken,  setVerifyToken]  = useState('');
  const [verifiedUrl,  setVerifiedUrl]  = useState('');
  const [siteTitle,    setSiteTitle]    = useState('');
  const [faviconUrl,   setFaviconUrl]   = useState('');
  const [dbModules,    setDbModules]    = useState([]);
  const [statusModal,  setStatusModal]  = useState(null);
  const [confirmModal, setConfirmModal] = useState(false);
  const [confirmPass,  setConfirmPass]  = useState('');
  const [confirmShow,  setConfirmShow]  = useState(false);
  const [confirmError, setConfirmError] = useState('');
  const [confirming,   setConfirming]   = useState(false);

  useEffect(() => {
    api.getModules().then(d => {
      if (Array.isArray(d)) setDbModules(d.map(m => m.module_key));
    }).catch(() => {});
  }, []);

  const modules  = dbModules.length > 0 ? ALL_MODULES.filter(m => dbModules.includes(m.key)) : ALL_MODULES;
  const selCount = selected.length;
  const total    = modules.length;

  const toggle = (key, fixed) => {
    if (fixed) return;
    setSelected(s => s.includes(key) ? s.filter(k => k !== key) : [...s, key]);
  };

  const toggleAll = () => {
    const nonFixed  = modules.filter(m => !m.fixed).map(m => m.key);
    const allActive = nonFixed.every(k => selected.includes(k));
    setSelected(allActive
      ? modules.filter(m => m.fixed).map(m => m.key)
      : modules.map(m => m.key));
  };

  const handleVerify = async () => {
    if (!target.trim()) { setError('Target URL is required'); return; }
    setVerifying(true);
    setError('');
    setVerifyToken('');
    setVerifiedUrl('');
    setSiteTitle('');
    setFaviconUrl('');
    try {
      const res = await api.verifyTarget(target.trim());
      if (res?.verified && res?.verification_token) {
        setVerifyToken(res.verification_token);
        setVerifiedUrl(res.normalized_url || '');
        setSiteTitle(res.title || '');
        setFaviconUrl(res.favicon_url || '');
        setStatusModal({
          type: 'success',
          title: 'Target Verified',
          message: 'Target URL is reachable and verified. You can launch the scan now.',
          action: 'Close',
        });
      } else if (String(res?.detail || '').toLowerCase().includes('permission')) {
        setError('You do not have permission to scan this URL');
        setStatusModal({
          type: 'error',
          title: 'Permission Denied',
          message: 'You do not have permission to scan this URL.',
          action: 'Try Again',
        });
      } else {
        const msg = res?.message || res?.detail || 'Target URL not found';
        setError(msg);
        setStatusModal({
          type: 'error',
          title: 'Something Went Wrong',
          message: msg,
          action: 'Try Again',
        });
      }
    } catch (e) {
      const message = e?.message || '';
      if (message.toLowerCase().includes('permission')) {
        setError('You do not have permission to scan this URL');
        setStatusModal({
          type: 'error',
          title: 'Permission Denied',
          message: 'You do not have permission to scan this URL.',
          action: 'Try Again',
        });
      } else {
        setError('Target URL not found');
        setStatusModal({
          type: 'error',
          title: 'Something Went Wrong',
          message: 'We could not verify that target URL. Please check the URL and try again.',
          action: 'Try Again',
        });
      }
    }
    setVerifying(false);
  };

  const handleScan = async () => {
    if (!target.trim())        { setError('Target URL is required'); return; }
    if (selected.length === 0) { setError('Select at least one module'); return; }
    if (!verifyToken)          { setError('Verify URL first'); return; }

    setConfirmError('');
    setConfirmPass('');
    setConfirmShow(false);
    setConfirmModal(true);
  };

  const handleConfirmStart = async () => {
    if (!confirmPass) {
      setConfirmError('Password is required to confirm scan start');
      return;
    }

    const url = verifiedUrl || target.trim();

    setLoading(true);
    setConfirming(true);
    setError('');
    try {
      const passCheck = await api.verifyPassword(confirmPass);
      if (!passCheck?.valid) {
        setConfirmError(passCheck?.detail || 'Incorrect password');
        return;
      }

      const data = await api.startScan({
        target_url:    url,
        verify_token:  verifyToken,
      });

      // Fix: React error #31 — data might be a validation error object, not a scan
      if (data && (data.scan_id || data._id || data.id)) {
        setConfirmModal(false);
        setConfirmPass('');
        setConfirmShow(false);
        setConfirmError('');
        setScreen('scans');
      } else if (data && data.detail) {
        // data.detail could be a string OR a Pydantic validation array — handle both
        const detail = typeof data.detail === 'string'
          ? data.detail
          : Array.isArray(data.detail)
            ? data.detail.map(e => e.msg || JSON.stringify(e)).join(', ')
            : JSON.stringify(data.detail);
        setError(detail);
      } else {
        setError('Failed to start scan');
      }
    } catch { setError('Cannot connect to server'); }
    finally {
      setLoading(false);
      setConfirming(false);
    }
  };

  return (
    <div className="va-page animate-in">
      <div style={{ marginBottom:20 }}>
        <h1 className="va-page-title">LAUNCH SCAN</h1>
        <p className="va-page-sub">Configure target and select attack modules</p>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:20, alignItems:'start' }}>

        {/* ── LEFT — configuration ── */}
        <div style={{ display:'flex', flexDirection:'column', gap:14 }}>

          {/* Target */}
          <div className="va-card" style={{ marginBottom:0 }}>
            <div className="va-section-title">TARGET CONFIGURATION</div>
            {error && <div className="va-error">⚠ {error}</div>}
            <div className="va-field">
              <label className="va-label">TARGET URL</label>
              <input value={target}
                onChange={e => {
                  setTarget(e.target.value);
                  setError('');
                  setVerifyToken('');
                  setVerifiedUrl('');
                  setSiteTitle('');
                  setFaviconUrl('');
                }}
                placeholder="https://example.com" />
            </div>
            <div style={{ display:'flex', gap:10, marginTop:12, alignItems:'center' }}>
              <button className="va-btn-secondary" onClick={handleVerify} disabled={verifying || loading}>
                {verifying ? '◌ VERIFYING...' : 'VERIFY URL'}
              </button>
              <span style={{ fontFamily:'var(--font-mono)', fontSize:11, color: verifyToken ? 'var(--low)' : 'var(--muted)' }}>
                {verifyToken ? 'VERIFIED' : 'NOT VERIFIED'}
              </span>
            </div>
            {verifyToken && (
              <div className="va-card" style={{ marginTop:12, marginBottom:0, transform:'perspective(900px) rotateX(2deg)' }}>
                <div style={{ display:'flex', alignItems:'center', gap:10 }}>
                  {faviconUrl && <img src={faviconUrl} alt="site icon" style={{ width:22, height:22, borderRadius:5 }} />}
                  <div>
                    <div style={{ fontFamily:'var(--font-mono)', fontSize:12, color:'var(--text)', fontWeight:700 }}>
                      {siteTitle || 'Verified target'}
                    </div>
                    <div style={{ fontSize:11, color:'var(--muted)', wordBreak:'break-all' }}>{verifiedUrl}</div>
                  </div>
                </div>
              </div>
            )}
            <div className="va-hint">
              ℹ Only scan systems you own or have explicit written permission to test.
            </div>
          </div>

          <div className="va-card" style={{ marginBottom:0 }}>
            <div className="va-section-title">PROXY SETTINGS</div>
            <p style={{ fontFamily:'var(--font)', fontSize:13, color:'var(--muted)', lineHeight:1.5 }}>
              Proxy is now managed from Dashboard/Profile for account-wide consistency.
            </p>
          </div>

          {/* Launch button */}
          <button
            className="va-btn-primary va-btn-full"
            onClick={handleScan}
            disabled={loading || !verifyToken}
            style={loading ? { opacity:0.6, cursor:'not-allowed' } : {}}>
            {loading ? '◌ SCANNING...' : `⊕ LAUNCH SCAN (${selCount} modules)`}
          </button>
        </div>

        {/* ── RIGHT — modules ── */}
        <div className="va-card" style={{ marginBottom:0 }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:14 }}>
            <div className="va-section-title" style={{ marginBottom:0 }}>MODULES ({selCount}/{total})</div>
            <button className="va-btn-ghost" onClick={toggleAll}>
              {modules.filter(m => !m.fixed).every(m => selected.includes(m.key)) ? 'DESELECT ALL' : 'SELECT ALL'}
            </button>
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap:4, maxHeight:600, overflowY:'auto' }}>
            {modules.map(m => {
              const active = selected.includes(m.key);
              return (
                <button
                  key={m.key}
                  className={`va-module-item${active ? ' active' : ''}`}
                  onClick={() => toggle(m.key, m.fixed)}
                  style={m.fixed ? { opacity:0.7 } : {}}>
                  <div>
                    <div className={`va-module-label${active ? '' : ' inactive'}`}>
                      {m.label}
                      {m.fixed && <span className="va-module-fixed-tag">FIXED</span>}
                    </div>
                    <div className="va-module-desc">{m.desc}</div>
                  </div>
                  <div className={`va-checkbox${active ? ' checked' : ''}`}>{active && '✓'}</div>
                </button>
              );
            })}
          </div>
        </div>

      </div>

      {statusModal && (
        <div className="va-overlay" onClick={() => setStatusModal(null)}>
          <div className="va-status-modal" onClick={e => e.stopPropagation()}>
            <button className="va-status-close" onClick={() => setStatusModal(null)} aria-label="Close status popup">x</button>
            <div className={`va-status-icon ${statusModal.type === 'success' ? 'ok' : 'bad'}`}>
              {statusModal.type === 'success' ? '✓' : '!'}
            </div>
            <h3 className="va-status-title">{statusModal.title}</h3>
            <p className="va-status-text">{statusModal.message}</p>
            <button
              className={statusModal.type === 'success' ? 'va-status-btn ok' : 'va-status-btn bad'}
              onClick={() => setStatusModal(null)}
            >
              {statusModal.action}
            </button>
          </div>
        </div>
      )}

      {confirmModal && (
        <div className="va-overlay" onClick={() => { if (!confirming) { setConfirmModal(false); setConfirmPass(''); setConfirmShow(false); setConfirmError(''); } }}>
          <div className="va-modal" onClick={e => e.stopPropagation()}>
            <div className="va-modal-title">CONFIRM SCAN START</div>
            <p style={{ color:'var(--muted2)', fontSize:13, marginBottom:14, lineHeight:1.5 }}>
              Verify with your account password before launching this scan.
            </p>
            {confirmError && <div className="va-error" style={{ marginBottom: 10 }}>⚠ {confirmError}</div>}
            <div className="va-input-wrap" style={{ marginBottom: 14 }}>
              <input
                type={confirmShow ? 'text' : 'password'}
                value={confirmPass}
                onChange={e => { setConfirmPass(e.target.value); setConfirmError(''); }}
                placeholder="Your account password"
                style={{ paddingRight: 76, marginBottom: 0 }}
              />
              <button type="button" className="va-pass-toggle" onClick={() => setConfirmShow(v => !v)}>
                {confirmShow ? 'HIDE' : 'SHOW'}
              </button>
            </div>
            <div style={{ display:'flex', gap:10 }}>
              <button
                className="va-btn-secondary"
                style={{ flex:1 }}
                disabled={confirming}
                onClick={() => { setConfirmModal(false); setConfirmPass(''); setConfirmShow(false); setConfirmError(''); }}
              >
                CANCEL
              </button>
              <button
                className="va-btn-primary"
                style={{ flex:1 }}
                disabled={confirming}
                onClick={handleConfirmStart}
              >
                {confirming ? 'CONFIRMING...' : 'START SCAN'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}