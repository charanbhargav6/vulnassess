// PATH: vulnassess-web/src/screens/Scans.jsx
import React, { useEffect, useState, useCallback } from 'react';
import { api } from '../api';
import { ScanCardsSkeleton, ScanDetailSkeleton } from './Skeletons';

const SEV = {
  critical: 'var(--critical)',
  high:     'var(--high)',
  medium:   'var(--medium)',
  low:      'var(--low)',
  info:     'var(--info-c)',
};

const STC = {
  completed: 'var(--status-completed)',
  running:   'var(--status-running)',
  failed:    'var(--status-failed)',
  pending:   'var(--status-pending)',
  cancelled: 'var(--status-pending)',
};

export default function Scans({ setScreen }) {
  const [scans,      setScans]      = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [selId,      setSelId]      = useState(null);
  const [detail,     setDetail]     = useState(null);
  const [detLoading, setDetLoading] = useState(false);
  const [filter,     setFilter]     = useState('all');
  const [search,     setSearch]     = useState('');
  const [delModal,   setDelModal]   = useState(null);
  const [delPass,    setDelPass]    = useState('');
  const [delErr,     setDelErr]     = useState('');
  const [pdfLoading, setPdfLoading] = useState(false);

  const getId = s => s._id || s.id;

  const load = useCallback(async () => {
    const d = await api.getScans().catch(() => []);
    setScans(Array.isArray(d) ? d : []);
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    const running = scans.some(s => s.status === 'running' || s.status === 'pending');
    if (!running) return;
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [scans, load]);

  useEffect(() => {
    if (!selId || !detail) return;
    if (detail.status !== 'running' && detail.status !== 'pending') return;
    const t = setInterval(async () => {
      const d = await api.getScan(selId).catch(() => null);
      if (d) setDetail(d);
    }, 4000);
    return () => clearInterval(t);
  }, [selId, detail]);

  const openDetail = async (scan) => {
    setSelId(getId(scan));
    setDetLoading(true);
    const d = await api.getScan(getId(scan)).catch(() => null);
    setDetail(d);
    setDetLoading(false);
  };

  const handleDelete = async () => {
    const res = await api.deleteScan(getId(delModal), delPass);
    if (res.message || res.success) {
      setDelModal(null); setDelPass(''); setDelErr('');
      setSelId(null); setDetail(null); load();
    } else {
      setDelErr(res.detail || 'Wrong password');
    }
  };

  const handlePDF = async (scanId) => {
    setPdfLoading(true);
    const blob = await api.downloadPDF(scanId).catch(() => null);
    if (blob) {
      const u = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = u; a.download = `vulnassess-report-${scanId}.pdf`; a.click();
      URL.revokeObjectURL(u);
    }
    setPdfLoading(false);
  };

  const filtered = scans.filter(s =>
    (filter === 'all' || s.status === filter) &&
    (!search || (s.target_url || s.target || '').toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="va-page animate-in">
      <div className="va-page-header" style={{ marginBottom: 12 }}>
        <div>
          <h1 className="va-page-title">SCAN HISTORY</h1>
          <p className="va-page-sub">Track scan progress and review reports in card format</p>
        </div>
        <button className="va-btn-secondary" onClick={load}>REFRESH</button>
      </div>

      <div className="va-card" style={{ marginBottom: 12 }}>
        <div className="va-scan-toolbar">
          <div>
            <label className="va-label">SEARCH TARGET</label>
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="https://example.com"
            />
          </div>
          <div>
            <label className="va-label">STATUS FILTER</label>
            <div style={{ display:'flex', gap:4, flexWrap:'wrap' }}>
              {['all','completed','running','failed','pending'].map(f => (
                <button
                  key={f}
                  className={`va-filter-btn${filter === f ? ' active' : ''}`}
                  onClick={() => setFilter(f)}
                >
                  {f.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        </div>

        {loading ? (
          <ScanCardsSkeleton cards={8} />
        ) : filtered.length === 0 ? (
          <div className="va-center">No scans found for this filter.</div>
        ) : (
          <div className="va-scan-cards">
            {filtered.map(scan => {
              const sc = scan.severity_counts || {};
              const url = scan.target_url || scan.target || '';
              return (
                <button
                  key={getId(scan)}
                  className={`va-scan-card${selId === getId(scan) ? ' active' : ''}`}
                  onClick={() => openDetail(scan)}
                >
                  <div className="va-scan-card-url">{url}</div>
                  <div className="va-scan-card-meta">
                    <span className={`va-badge ${scan.status === 'completed' ? 'va-badge-completed' : scan.status === 'running' ? 'va-badge-running' : scan.status === 'failed' ? 'va-badge-failed' : 'va-badge-pending'}`}>
                      {(scan.status || 'pending').toUpperCase()}
                    </span>
                    <span className="va-td-mono" style={{ color:'var(--muted)' }}>
                      {scan.created_at ? new Date(scan.created_at).toLocaleDateString() : '—'}
                    </span>
                  </div>

                  {(scan.status === 'running' || scan.status === 'pending') && (
                    <div style={{ height:4, background:'var(--border)', borderRadius:2, overflow:'hidden', marginBottom:8 }}>
                      <div style={{ height:'100%', background:'var(--accent)', width:`${scan.progress||0}%`, transition:'width 0.5s' }} />
                    </div>
                  )}

                  {scan.status === 'completed' && (
                    <div style={{ display:'flex', gap:5, flexWrap:'wrap' }}>
                      {['critical','high','medium','low'].map(sv => sc[sv] > 0 && (
                        <span key={sv} className={`va-badge va-badge-${sv}`}>{sc[sv]} {sv}</span>
                      ))}
                      {!sc.critical && !sc.high && !sc.medium && !sc.low && (
                        <span className="va-badge va-badge-low">CLEAN</span>
                      )}
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {!selId ? (
        <div className="va-card">
          <div className="va-center" style={{ padding: 26 }}>
            <span className="va-empty-icon">◎</span>
            <p>Select a scan card to open full details</p>
          </div>
        </div>
      ) : detLoading ? (
        <ScanDetailSkeleton />
      ) : detail ? (
        <div className="va-scan-detail" style={{ minHeight: 460 }}>
          <ScanDetail
            scan={detail}
            onCancel={() => { api.cancelScan(getId(detail)); load(); }}
            onDelete={() => setDelModal(detail)}
            onPDF={handlePDF}
            pdfLoading={pdfLoading}
            onAI={id => setScreen('ai-remediation:' + id)}
          />
        </div>
      ) : (
        <div className="va-card"><div className="va-center">Failed to load scan details.</div></div>
      )}

      {/* DELETE MODAL */}
      {delModal && (
        <div className="va-overlay" onClick={() => { setDelModal(null); setDelPass(''); setDelErr(''); }}>
          <div className="va-modal" onClick={e => e.stopPropagation()}>
            <div className="va-modal-title" style={{ color:'var(--critical)' }}>CONFIRM DELETE</div>
            <p style={{ color:'var(--muted2)', fontSize:13, marginBottom:16, lineHeight:1.5 }}>
              Enter password to delete scan for{' '}
              <strong style={{ color:'var(--accent)' }}>{delModal.target_url || delModal.target}</strong>
            </p>
            {delErr && <div className="va-error" style={{ marginBottom:10 }}>⚠ {delErr}</div>}
            <input type="password" value={delPass}
              onChange={e => { setDelPass(e.target.value); setDelErr(''); }}
              placeholder="Your password" style={{ marginBottom:16 }} />
            <div style={{ display:'flex', gap:10 }}>
              <button className="va-btn-secondary" style={{ flex:1 }}
                onClick={() => { setDelModal(null); setDelPass(''); setDelErr(''); }}>
                CANCEL
              </button>
              <button className="va-btn-danger" style={{ flex:1, padding:'10px 0', fontSize:12, letterSpacing:'0.1em' }}
                onClick={handleDelete}>
                DELETE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ScanDetail({ scan, onCancel, onDelete, onPDF, pdfLoading, onAI }) {
  const [exp, setExp] = useState(null);
  const id    = scan._id || scan.id;
  const vulns = scan.vulnerabilities || [];
  const sc    = scan.severity_counts || {};
  const url   = scan.target_url || scan.target || '';

  return (
    <div style={{ height:'100%', overflowY:'auto', padding:20 }}>

      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:20 }}>
        <div>
          <div style={{ fontFamily:'var(--font-mono)', fontSize:14, fontWeight:700,
                        color:'var(--accent)', marginBottom:6, wordBreak:'break-all' }}>
            {url}
          </div>
          <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:STC[scan.status]||'var(--muted)' }}>
            ● {scan.status?.toUpperCase()} · {scan.created_at ? new Date(scan.created_at).toLocaleString() : ''}
          </div>
          {scan.pages_crawled > 0 && (
            <div style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'var(--muted)', marginTop:4 }}>
              {scan.pages_crawled} pages crawled · {scan.requests_made} requests
            </div>
          )}
        </div>
        <div style={{ display:'flex', gap:8, flexShrink:0 }}>
          {scan.status === 'running' && (
            <button className="va-btn-scan-stop" onClick={onCancel}>⏹ STOP</button>
          )}
          {scan.status === 'completed' && (
            <>
              <button className="va-btn-scan-pdf" onClick={() => onPDF(id)} disabled={pdfLoading}>
                {pdfLoading ? '◌' : '↓'} PDF
              </button>
              <button className="va-btn-scan-ai" onClick={() => onAI(id)}>
                🤖 AI FIX
              </button>
            </>
          )}
          <button className="va-btn-scan-del" onClick={onDelete}>✕</button>
        </div>
      </div>

      {/* Progress (running) */}
      {(scan.status === 'running' || scan.status === 'pending') && (
        <div className="va-card" style={{ marginBottom:20 }}>
          <div style={{ display:'flex', justifyContent:'space-between',
                        fontFamily:'var(--font-mono)', fontSize:11, color:'var(--muted2)', marginBottom:8 }}>
            <span>{scan.current_step || 'Initializing...'}</span>
            <span>{scan.progress || 0}%</span>
          </div>
          <div style={{ height:4, background:'var(--border)', borderRadius:2, overflow:'hidden' }}>
            <div style={{ height:'100%', background:'var(--accent)', borderRadius:2,
                          width:`${scan.progress||0}%`, transition:'width 0.5s' }} />
          </div>
        </div>
      )}

      {/* Severity counts (completed) */}
      {scan.status === 'completed' && (
        <div style={{ display:'flex', gap:8, marginBottom:20, flexWrap:'wrap' }}>
          {['critical','high','medium','low','info'].map(sv => (
            <div key={sv} className="va-card" style={{ padding:'10px 16px', textAlign:'center',
                                                       minWidth:70, marginBottom:0, borderLeftColor:SEV[sv], borderLeftWidth:3 }}>
              <div style={{ fontFamily:'var(--font-mono)', fontSize:22, fontWeight:700,
                            color:SEV[sv], marginBottom:2 }}>
                {sc[sv] || 0}
              </div>
              <div style={{ fontFamily:'var(--font-mono)', fontSize:9, color:'var(--muted)', letterSpacing:'0.1em' }}>
                {sv.toUpperCase()}
              </div>
            </div>
          ))}
          <div className="va-card" style={{ padding:'10px 16px', textAlign:'center', minWidth:70, marginBottom:0 }}>
            <div style={{ fontFamily:'var(--font-mono)', fontSize:22, fontWeight:700, color:'var(--text)', marginBottom:2 }}>
              {scan.total_risk_score?.toFixed(1) || '0.0'}
            </div>
            <div style={{ fontFamily:'var(--font-mono)', fontSize:9, color:'var(--muted)', letterSpacing:'0.1em' }}>RISK</div>
          </div>
        </div>
      )}

      {/* Vulnerabilities */}
      {vulns.length > 0 && (
        <div>
          <div className="va-section-title">VULNERABILITIES ({vulns.length})</div>
          <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
            {vulns.map((v, i) => (
              <div key={i} className="va-card"
                style={{ marginBottom:0, borderLeftColor:SEV[v.severity]||'var(--border)', borderLeftWidth:3 }}>
                <button onClick={() => setExp(exp === i ? null : i)}
                  style={{ width:'100%', display:'flex', justifyContent:'space-between', alignItems:'center',
                           padding:'10px 12px', background:'none', cursor:'pointer', textAlign:'left', border:'none' }}>
                  <div style={{ display:'flex', alignItems:'center', gap:10, flex:1, minWidth:0 }}>
                    <span className={`va-badge va-badge-${v.severity||'info'}`}>
                      {v.severity?.toUpperCase() || 'INFO'}
                    </span>
                    <span style={{ fontFamily:'var(--font-mono)', fontSize:12, color:'var(--text)',
                                   fontWeight:600, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                      {v.vuln_type || v.type || v.name}
                    </span>
                  </div>
                  <span style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'var(--muted)', marginLeft:8 }}>
                    {exp === i ? '▲' : '▼'}
                  </span>
                </button>
                {exp === i && (
                  <div style={{ padding:'0 12px 12px', borderTop:'1px solid var(--border)' }}>
                    {v.url && (
                      <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--muted2)', marginTop:8, wordBreak:'break-all' }}>
                        <span style={{ color:'var(--muted)', fontWeight:700 }}>URL: </span>{v.url}
                      </div>
                    )}
                    {v.param && v.param !== 'N/A' && (
                      <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--muted2)', marginTop:4 }}>
                        <span style={{ color:'var(--muted)', fontWeight:700 }}>Param: </span>{v.param}
                      </div>
                    )}
                    {v.payload && (
                      <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--yellow)', marginTop:4, wordBreak:'break-all' }}>
                        <span style={{ color:'var(--muted)', fontWeight:700 }}>Payload: </span>{v.payload}
                      </div>
                    )}
                    {v.evidence && (
                      <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--muted2)', marginTop:4 }}>
                        <span style={{ color:'var(--muted)', fontWeight:700 }}>Evidence: </span>{v.evidence}
                      </div>
                    )}
                    {v.cve_id && (
                      <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--accent)', marginTop:4 }}>
                        <span style={{ color:'var(--muted)', fontWeight:700 }}>CVE: </span>{v.cve_id}
                      </div>
                    )}
                    {v.risk_score && (
                      <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--orange)', marginTop:4 }}>
                        <span style={{ color:'var(--muted)', fontWeight:700 }}>Risk Score: </span>{v.risk_score}/10
                      </div>
                    )}
                    {v.reproduction_steps?.length > 0 && (
                      <div style={{ marginTop:8 }}>
                        <div style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'var(--muted)', fontWeight:700, marginBottom:4 }}>
                          REPRODUCTION:
                        </div>
                        {v.reproduction_steps.map((step, si) => (
                          <div key={si} style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--muted2)', marginBottom:2 }}>
                            {si + 1}. {step}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {scan.status === 'completed' && vulns.length === 0 && (
        <div className="va-center" style={{ color:'var(--low)' }}>
          <div style={{ fontSize:32 }}>✓</div>
          <p>No vulnerabilities detected</p>
        </div>
      )}
    </div>
  );
}