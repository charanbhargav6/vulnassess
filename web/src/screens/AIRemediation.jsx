// PATH: vulnassess-web/src/screens/AIRemediation.jsx
import { useState, useEffect } from 'react';
import { api } from '../api';
import { SkeletonBlock } from './Skeletons';

export default function AIRemediation({ scanId, onBack }) {
  const [data,       setData]       = useState(null);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState('');
  const [expanded,   setExpanded]   = useState({});
  const [pdfLoading, setPdfLoading] = useState(false);

  useEffect(() => { load(); }, [scanId]);

  const load = async () => {
    setLoading(true); setError('');
    try {
      const res = await api.getAIRemediation(scanId);
      if (res.detail) setError(res.detail);
      else setData(res);
    } catch { setError('Failed to load AI remediation. Check server connection.'); }
    setLoading(false);
  };

  const toggle = id => setExpanded(prev => ({ ...prev, [id]: !prev[id] }));

  const handleDownloadPDF = async () => {
    setPdfLoading(true);
    try {
      const blob = await api.downloadAIPDF(scanId);
      if (blob) {
        const url = URL.createObjectURL(blob);
        const a   = document.createElement('a');
        a.href     = url;
        a.download = `vulnassess-ai-remediation-${scanId}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch {}
    setPdfLoading(false);
  };

  const priorityColor = p =>
    p === 1 ? 'var(--critical)' : p === 2 ? 'var(--high)' : p <= 3 ? 'var(--yellow)' : 'var(--muted)';

  const sevClass = s => ({
    critical:'va-badge-critical', high:'va-badge-high',
    medium:'va-badge-medium', low:'va-badge-low',
  })[s?.toLowerCase()] || 'va-badge-info';

  if (loading) return (
    <div style={{ padding:'20px 24px', maxWidth:900, margin:'0 auto' }} className="fade-in">
      <div className="va-card" style={{ marginBottom: 12 }}>
        <SkeletonBlock height={30} width="48%" style={{ marginBottom: 8 }} />
        <SkeletonBlock height={14} width="70%" />
      </div>
      <div className="va-card" style={{ marginBottom: 12 }}>
        <SkeletonBlock height={14} width="40%" style={{ marginBottom: 12 }} />
        <SkeletonBlock height={12} width="100%" style={{ marginBottom: 8 }} />
        <SkeletonBlock height={12} width="92%" style={{ marginBottom: 8 }} />
        <SkeletonBlock height={12} width="86%" />
      </div>
      {Array.from({ length: 3 }).map((_, i) => (
        <div className="va-card" key={i} style={{ marginBottom: 10 }}>
          <SkeletonBlock height={16} width="55%" style={{ marginBottom: 10 }} />
          <SkeletonBlock height={12} width="95%" style={{ marginBottom: 7 }} />
          <SkeletonBlock height={12} width="80%" />
        </div>
      ))}
    </div>
  );

  return (
    <div style={{ padding:'20px 24px', maxWidth:900, margin:'0 auto' }}>

      {/* Header */}
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:24 }}>
        <div style={{ display:'flex', alignItems:'center', gap:16 }}>
          <button className="va-btn-secondary" onClick={onBack}>← BACK</button>
          <div>
            <h1 className="va-page-title" style={{ marginBottom:0 }}>
              AI REMEDIATION
              <span className="va-ai-badge" style={{ marginLeft:10 }}>Claude AI</span>
            </h1>
          </div>
        </div>
        {data && (
          <button
            className="va-btn-secondary"
            onClick={handleDownloadPDF}
            disabled={pdfLoading}
            style={{ color:'#A78BFA', borderColor:'rgba(139,92,246,0.4)', background:'rgba(139,92,246,0.1)' }}
          >
            {pdfLoading ? '◌ GENERATING…' : '↓ DOWNLOAD AI PDF'}
          </button>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="va-card" style={{ borderLeftColor:'var(--critical)', borderLeftWidth:3, marginBottom:20 }}>
          <strong style={{ color:'var(--critical)' }}>Error:</strong>{' '}{error}
          <button className="va-btn-secondary" style={{ marginLeft:16 }} onClick={load}>Retry</button>
        </div>
      )}

      {data && (
        <>
          {/* Executive summary */}
          {data.executive_summary && (
            <div className="va-card" style={{ marginBottom:20 }}>
              <div className="va-section-title" style={{ color:'#8B5CF6', marginBottom:10 }}>EXECUTIVE SUMMARY</div>
              <p style={{ fontFamily:'var(--font)', fontSize:15, color:'var(--text)', lineHeight:1.6 }}>
                {data.executive_summary}
              </p>
            </div>
          )}

          {/* Critical action */}
          {data.critical_action && (
            <div className="va-critical-action">
              <span className="va-critical-icon">⚡</span>
              <div>
                <div className="va-critical-label">IMMEDIATE ACTION REQUIRED</div>
                <div className="va-critical-text">{data.critical_action}</div>
              </div>
            </div>
          )}

          {/* Empty state */}
          {(data.remediations || []).length === 0 && (
            <div className="va-center">
              <div style={{ fontSize:40 }}>✅</div>
              <p>No remediations needed.</p>
            </div>
          )}

          {/* Remediation cards */}
          {(data.remediations || []).map(r => {
            const open = expanded[r.id];
            return (
              <div key={r.id} className="va-card" style={{ marginBottom:12 }}>

                {/* Card header — clickable */}
                <div style={{ padding:'14px 18px', cursor:'pointer', display:'flex',
                              justifyContent:'space-between', alignItems:'center' }}
                  onClick={() => toggle(r.id)}>
                  <div style={{ display:'flex', alignItems:'center', gap:10, flexWrap:'wrap' }}>
                    <span className="va-badge" style={{ background:priorityColor(r.priority)+'25',
                      color:priorityColor(r.priority), border:`1px solid ${priorityColor(r.priority)}40` }}>
                      P{r.priority}
                    </span>
                    <span style={{ fontFamily:'var(--font-mono)', fontSize:14, fontWeight:700, color:'var(--text)' }}>
                      {r.vuln_type}
                    </span>
                    <span className={`va-badge ${sevClass(r.severity)}`}>
                      {(r.severity || 'info').toUpperCase()}
                    </span>
                    {r.estimated_effort && (
                      <span className="va-badge va-badge-info">{r.estimated_effort} effort</span>
                    )}
                    {r.cve_id && (
                      <span style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--muted)' }}>
                        {r.cve_id}
                      </span>
                    )}
                  </div>
                  <span style={{ color:'var(--muted)', fontSize:14,
                                 transform: open ? 'rotate(180deg)' : 'none', transition:'transform 0.2s' }}>
                    ▼
                  </span>
                </div>

                {/* Card body */}
                {open && (
                  <div style={{ padding:'0 18px 18px', borderTop:'1px solid var(--border)' }}>
                    {r.summary && (
                      <p style={{ fontFamily:'var(--font)', fontSize:14, color:'var(--text-secondary)',
                                  lineHeight:1.6, padding:'12px 0' }}>
                        {r.summary}
                      </p>
                    )}

                    {r.fix_steps?.length > 0 && (
                      <>
                        <div className="va-section-title" style={{ marginTop:12 }}>FIX STEPS</div>
                        <ul style={{ listStyle:'none', paddingLeft:0, margin:0 }}>
                          {r.fix_steps.map((step, i) => (
                            <li key={i} style={{ display:'flex', gap:10, marginBottom:8,
                                                 fontFamily:'var(--font)', fontSize:14, color:'var(--text)', lineHeight:1.5 }}>
                              <span className="va-step-num"
                                style={{ background:'var(--blue)', color:'#fff', borderRadius:'50%', width:22, height:22,
                                         display:'flex', alignItems:'center', justifyContent:'center',
                                         fontSize:11, fontWeight:700, flexShrink:0, marginTop:1,
                                         fontFamily:'var(--font-mono)' }}>
                                {i + 1}
                              </span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ul>
                      </>
                    )}

                    {r.code_example && (
                      <>
                        <div className="va-section-title" style={{ marginTop:12 }}>CODE EXAMPLE</div>
                        <div className="va-code-block">{r.code_example}</div>
                      </>
                    )}

                    {r.references?.length > 0 && (
                      <>
                        <div className="va-section-title" style={{ marginTop:12 }}>REFERENCES</div>
                        <div style={{ display:'flex', flexWrap:'wrap', gap:8, marginTop:4 }}>
                          {r.references.map((ref, i) => (
                            <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                              className="va-ref-link">
                              {ref.replace('https://', '').split('/')[0]}
                            </a>
                          ))}
                        </div>
                      </>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </>
      )}
    </div>
  );
}