// PATH: vulnassess-web/src/screens/Login.jsx
import React, { useState } from 'react';
import { api } from '../api';

export default function Login({ onLogin, goRegister }) {
  const [email,    setEmail]    = useState('');
  const [password, setPassword] = useState('');
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!email || !password) { setError('All fields required'); return; }
    setLoading(true);
    try {
      const data = await api.login(email, password);
      if (data.access_token || data.email) {
        const me = await api.getMe().catch(() => null);
        if (me?.email) {
          onLogin(me);
        } else {
          setError('Login succeeded but session was not established. Check cookie settings.');
        }
      } else {
        setError(data.detail || 'Login failed');
      }
    } catch { setError('Cannot connect to server'); }
    setLoading(false);
  };

  return (
    <div className="va-auth-page animate-in">
      <div className="va-auth-container">

        <div className="va-auth-logo">
          <span className="va-auth-logo-icon">⬡</span>
          <span className="va-auth-logo-text">VULNASSESS</span>
        </div>

        <div className="va-auth-card">
          <h1 className="va-auth-title">SYSTEM LOGIN</h1>
          <p className="va-auth-subtitle">Authenticate to access the scanner</p>

          <form onSubmit={handleLogin} style={{ display:'flex', flexDirection:'column', gap:16 }}>
            {error && <div className="va-error">⚠ {error}</div>}

            <div className="va-field">
              <label className="va-label">EMAIL</label>
              <input
                type="email" value={email} autoFocus
                onChange={e => { setEmail(e.target.value); setError(''); }}
                placeholder="operator@domain.com"
              />
            </div>

            <div className="va-field">
              <label className="va-label">PASSWORD</label>
              <input
                type="password" value={password}
                onChange={e => { setPassword(e.target.value); setError(''); }}
                placeholder="••••••••"
              />
            </div>

            <button
              type="submit"
              className="va-btn-primary va-btn-full"
              disabled={loading}
              style={loading ? { opacity:0.6, cursor:'not-allowed' } : {}}
            >
              {loading ? '◌ AUTHENTICATING...' : '→ AUTHENTICATE'}
            </button>
          </form>

          <div className="va-auth-divider" />

          <p className="va-auth-footer">
            No account?{' '}
            <button className="va-auth-link" onClick={goRegister}>REQUEST ACCESS</button>
          </p>
        </div>

        <p className="va-auth-sec-note">
          <span style={{ color:'var(--low)' }}>●</span> SECURE · vulnassess-backend.onrender.com
        </p>
      </div>
    </div>
  );
}