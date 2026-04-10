// PATH: vulnassess-web/src/screens/Register.jsx
import React, { useState } from 'react';
import { api } from '../api';

const rules = [
  { id:'len',   label:'At least 8 characters',          test: p => p.length >= 8 },
  { id:'upper', label:'One uppercase letter',            test: p => /[A-Z]/.test(p) },
  { id:'lower', label:'One lowercase letter',            test: p => /[a-z]/.test(p) },
  { id:'num',   label:'One number',                      test: p => /\d/.test(p) },
  { id:'spec',  label:'One special character (!@#$...)', test: p => /[!@#$%^&*]/.test(p) },
];

export default function Register({ goLogin }) {
  const [email,    setEmail]    = useState('');
  const [password, setPassword] = useState('');
  const [confirm,  setConfirm]  = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');
  const [success,  setSuccess]  = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const [resendMsg, setResendMsg] = useState('');

  const allPass = rules.every(r => r.test(password));

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!email || !password || !confirm) { setError('All fields required'); return; }
    if (password !== confirm)             { setError('Passwords do not match'); return; }
    if (!allPass)                         { setError('Password does not meet requirements'); return; }
    setLoading(true);
    try {
      const data = await api.register(email, password);
      if (data.email || data.message) {
        setSuccessMessage(data.message || 'Registration successful. Please verify your email.');
        setSuccess(true);
      }
      else setError(data.detail || 'Registration failed');
    } catch { setError('Cannot connect to server'); }
    setLoading(false);
  };

  const handleResendVerification = async () => {
    setResendMsg('');
    try {
      const data = await api.resendVerificationEmail(email);
      setResendMsg(data?.message || data?.detail || 'Verification email request sent');
    } catch {
      setResendMsg('Unable to resend email right now. Try again.');
    }
  };

  if (success) return (
    <div className="va-auth-page animate-in">
      <div className="va-auth-container">
        <div className="va-auth-logo">
          <span className="va-auth-logo-icon">⬡</span>
          <span className="va-auth-logo-text">VULNASSESS</span>
        </div>
        <div className="va-auth-card" style={{ textAlign:'center' }}>
          <div className="va-success-icon">✉</div>
          <div className="va-success-title">CHECK YOUR EMAIL</div>
          <p className="va-success-text">
            {successMessage || 'A verification link was sent to'}<br />
            <span className="va-success-email">{email}</span>
          </p>
          <button className="va-btn-secondary" onClick={handleResendVerification} style={{ width: '100%', marginBottom: 10 }}>
            RESEND VERIFICATION EMAIL
          </button>
          {resendMsg && <div className={String(resendMsg).toLowerCase().includes('unable') ? 'va-error' : 'va-success'}>{resendMsg}</div>}
          <div className="va-auth-divider" />
          <button className="va-auth-link" onClick={goLogin}>← BACK TO LOGIN</button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="va-auth-page animate-in">
      <div className="va-auth-container">

        <div className="va-auth-logo">
          <span className="va-auth-logo-icon">⬡</span>
          <span className="va-auth-logo-text">VULNASSESS</span>
        </div>

        <div className="va-auth-card">
          <h1 className="va-auth-title">REQUEST ACCESS</h1>
          <p className="va-auth-subtitle">Create your operator account</p>

          <form onSubmit={handleRegister} style={{ display:'flex', flexDirection:'column', gap:16 }}>
            {error && <div className="va-error">⚠ {error}</div>}

            <div className="va-field">
              <label className="va-label">EMAIL ADDRESS</label>
              <input
                type="email" value={email} autoFocus
                onChange={e => { setEmail(e.target.value); setError(''); }}
                placeholder="operator@domain.com"
              />
            </div>

            <div className="va-field">
              <label className="va-label">PASSWORD</label>
              <div className="va-input-wrap">
                <input
                  type={showPassword ? 'text' : 'password'} value={password}
                  onChange={e => { setPassword(e.target.value); setError(''); }}
                  placeholder="••••••••"
                  style={{ paddingRight: 76 }}
                />
                <button type="button" className="va-pass-toggle" onClick={() => setShowPassword(v => !v)}>
                  {showPassword ? 'HIDE' : 'SHOW'}
                </button>
              </div>
              {password && (
                <div className="va-rules-box">
                  {rules.map(r => (
                    <div key={r.id} className={`va-rule-row ${r.test(password) ? 'pass' : 'fail'}`}>
                      <span>{r.test(password) ? '✓' : '○'}</span>
                      <span>{r.label}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="va-field">
              <label className="va-label">CONFIRM PASSWORD</label>
              <div className="va-input-wrap">
                <input
                  type={showConfirm ? 'text' : 'password'} value={confirm}
                  onChange={e => { setConfirm(e.target.value); setError(''); }}
                  placeholder="••••••••"
                  style={{ paddingRight: 76 }}
                />
                <button type="button" className="va-pass-toggle" onClick={() => setShowConfirm(v => !v)}>
                  {showConfirm ? 'HIDE' : 'SHOW'}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="va-btn-primary va-btn-full"
              disabled={loading}
              style={loading ? { opacity:0.6, cursor:'not-allowed' } : {}}
            >
              {loading ? '◌ REGISTERING...' : '→ CREATE ACCOUNT'}
            </button>
          </form>

          <div className="va-auth-divider" />
          <p className="va-auth-footer">
            Already have an account?{' '}
            <button className="va-auth-link" onClick={goLogin}>SIGN IN</button>
          </p>
        </div>
      </div>
    </div>
  );
}