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
  // Auth state
  const [username,     setUsername]     = useState('');
  const [password,     setPassword]     = useState('');

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
      } else if (String(res?.detail || '').toLowerCase().includes('permission')) {
        setError('u dont have permission to scan this url');
        window.alert('u dont have permission to scan this url');
      } else {
        setError('url not found');
        window.alert('url not found');
      }
    } catch (e) {
      const message = e?.message || '';
      if (message.toLowerCase().includes('permission')) {
        setError('u dont have permission to scan this url');
        window.alert('u dont have permission to scan this url');
      } else {
        setError('url not found');
        window.alert('url not found');
      }
    }
    setVerifying(false);
  };

  const handleScan = async () => {
    if (!target.trim())        { setError('Target URL is required'); return; }
    if (selected.length === 0) { setError('Select at least one module'); return; }
    if (!verifyToken)          { setError('Verify URL first'); return; }

    const url = verifiedUrl || target.trim();

    setLoading(true);
    setError('');
    try {
      const data = await api.startScan({
        target_url:    url,
        username:      username.trim() || null,
        password:      password || null,
        verify_token:  verifyToken,
      });

      // Fix: React error #31 — data might be a validation error object, not a scan
      if (data && (data.scan_id || data._id || data.id)) {
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
    setLoading(false);
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

          {/* Authenticated scanning */}
          <div className="va-card" style={{ marginBottom:0 }}>
            <div className="va-section-title">LOGIN CREDENTIALS <span style={{ color:'var(--muted)', fontWeight:400 }}>(OPTIONAL)</span></div>
            <p style={{ fontFamily:'var(--font)', fontSize:13, color:'var(--muted)', marginBottom:14, lineHeight:1.5 }}>
              Provide credentials to scan behind a login wall. The engine will auto-detect the login form.
            </p>
            <div className="va-field">
              <label className="va-label">USERNAME / EMAIL</label>
              <input value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="admin@example.com"
                autoComplete="off" />
            </div>
            <div className="va-field">
              <label className="va-label">PASSWORD</label>
              <input type="password" value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="off" />
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
    </div>
  );
}