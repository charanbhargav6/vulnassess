// PATH: vulnassess-web/src/screens/Login.jsx
import React, { useState } from 'react';
import { api } from '../api';

export default function Login({ onLogin, goRegister }) {
  const [mode, setMode] = useState('login');
  const [step, setStep] = useState(1);
  const [showPassword, setShowPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [email,    setEmail]    = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');
  const [success, setSuccess] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!email || !password) { setError('All fields required'); return; }
    setLoading(true);
    try {
      const check = await api.checkEmail(email);
      if (!check?.exists) {
        setError('Email does not exist. Please register first.');
        return;
      }
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
    finally { setLoading(false); }
  };

  const startForgot = () => {
    setMode('forgot');
    setStep(1);
    setPassword('');
    setOtp('');
    setNewPassword('');
    setConfirmPassword('');
    setError('');
    setSuccess('');
    setShowPassword(false);
    setShowNewPassword(false);
    setShowConfirmPassword(false);
  };

  const backToLogin = () => {
    setMode('login');
    setStep(1);
    setOtp('');
    setNewPassword('');
    setConfirmPassword('');
    setError('');
    setSuccess('');
    setShowPassword(false);
    setShowNewPassword(false);
    setShowConfirmPassword(false);
  };

  const sendOtp = async () => {
    const normalizedEmail = (email || '').trim().toLowerCase();
    if (!normalizedEmail) { setError('Enter your email first'); return; }
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const res = await api.sendForgotPasswordOtp(normalizedEmail);
      if (res?.message) {
        setSuccess(res.message);
        setStep(2);
      } else {
        setError(res?.detail || 'Failed to send OTP');
      }
    } catch {
      setError('Cannot connect to server');
    } finally {
      setLoading(false);
    }
  };

  const verifyOtp = async () => {
    const normalizedEmail = (email || '').trim().toLowerCase();
    const normalizedOtp = (otp || '').trim();
    if (!normalizedEmail || !normalizedOtp) {
      setError('Email and OTP are required');
      return;
    }
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const res = await api.verifyForgotPasswordOtp(normalizedEmail, normalizedOtp);
      if (res?.valid) {
        setSuccess('OTP verified. Set your new password.');
        setStep(3);
      } else {
        setError(res?.detail || 'Invalid OTP');
      }
    } catch {
      setError('Cannot connect to server');
    } finally {
      setLoading(false);
    }
  };

  const resetWithOtp = async () => {
    const normalizedEmail = (email || '').trim().toLowerCase();
    const normalizedOtp = (otp || '').trim();
    if (!normalizedEmail || !normalizedOtp || !newPassword || !confirmPassword) {
      setError('All fields are required');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('New password and confirm password do not match');
      return;
    }
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const res = await api.resetPasswordWithOtp(normalizedEmail, normalizedOtp, newPassword);
      if (res?.message) {
        setSuccess('Password reset successful. You can login now.');
        setMode('login');
        setStep(1);
        setPassword('');
        setOtp('');
        setNewPassword('');
        setConfirmPassword('');
      } else {
        setError(res?.detail || 'Password reset failed');
      }
    } catch {
      setError('Cannot connect to server');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="va-auth-page animate-in">
      <div className="va-auth-container">

        <div className="va-auth-logo">
          <span className="va-auth-logo-icon">⬡</span>
          <span className="va-auth-logo-text">VULNASSESS</span>
        </div>

        <div className="va-auth-card">
          <h1 className="va-auth-title">{mode === 'login' ? 'SYSTEM LOGIN' : 'RESET PASSWORD'}</h1>
          <p className="va-auth-subtitle">
            {mode === 'login' ? 'Authenticate to access the scanner' : 'Request OTP, verify it, then set a new password'}
          </p>

          {error && <div className="va-error">⚠ {error}</div>}
          {success && <div className="va-success">✓ {success}</div>}

          {mode === 'login' ? (
            <form onSubmit={handleLogin} style={{ display:'flex', flexDirection:'column', gap:16 }}>
              <div className="va-field">
                <label className="va-label">EMAIL</label>
                <input
                  type="email" value={email} autoFocus
                  onChange={e => { setEmail(e.target.value); setError(''); setSuccess(''); }}
                  placeholder="operator@domain.com"
                />
              </div>

              <div className="va-field">
                <label className="va-label">PASSWORD</label>
                <div className="va-input-wrap">
                  <input
                    type={showPassword ? 'text' : 'password'} value={password}
                    onChange={e => { setPassword(e.target.value); setError(''); setSuccess(''); }}
                    placeholder="••••••••"
                    style={{ paddingRight: 76 }}
                  />
                  <button type="button" className="va-pass-toggle" onClick={() => setShowPassword(v => !v)}>
                    {showPassword ? 'HIDE' : 'SHOW'}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                className="va-btn-primary va-btn-full"
                disabled={loading}
                style={loading ? { opacity:0.6, cursor:'not-allowed' } : {}}
              >
                {loading ? '◌ AUTHENTICATING...' : '→ AUTHENTICATE'}
              </button>

              <button
                type="button"
                className="va-auth-link"
                onClick={startForgot}
                style={{ alignSelf: 'center', marginTop: 4 }}
              >
                Forgot password?
              </button>
            </form>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="va-field">
                <label className="va-label">EMAIL</label>
                <input
                  type="email"
                  value={email}
                  onChange={e => { setEmail(e.target.value); setError(''); setSuccess(''); }}
                  placeholder="operator@domain.com"
                />
              </div>

              {step >= 2 && (
                <div className="va-field">
                  <label className="va-label">OTP CODE</label>
                  <input
                    type="text"
                    value={otp}
                    maxLength={6}
                    onChange={e => { setOtp(e.target.value.replace(/\D/g, '')); setError(''); setSuccess(''); }}
                    placeholder="6-digit OTP"
                  />
                </div>
              )}

              {step === 3 && (
                <>
                  <div className="va-field">
                    <label className="va-label">NEW PASSWORD</label>
                    <div className="va-input-wrap">
                      <input
                        type={showNewPassword ? 'text' : 'password'}
                        value={newPassword}
                        onChange={e => { setNewPassword(e.target.value); setError(''); setSuccess(''); }}
                        placeholder="At least 8 chars, uppercase/lowercase/number"
                        style={{ paddingRight: 76 }}
                      />
                      <button type="button" className="va-pass-toggle" onClick={() => setShowNewPassword(v => !v)}>
                        {showNewPassword ? 'HIDE' : 'SHOW'}
                      </button>
                    </div>
                  </div>
                  <div className="va-field">
                    <label className="va-label">CONFIRM PASSWORD</label>
                    <div className="va-input-wrap">
                      <input
                        type={showConfirmPassword ? 'text' : 'password'}
                        value={confirmPassword}
                        onChange={e => { setConfirmPassword(e.target.value); setError(''); setSuccess(''); }}
                        placeholder="Re-enter new password"
                        style={{ paddingRight: 76 }}
                      />
                      <button type="button" className="va-pass-toggle" onClick={() => setShowConfirmPassword(v => !v)}>
                        {showConfirmPassword ? 'HIDE' : 'SHOW'}
                      </button>
                    </div>
                  </div>
                </>
              )}

              {step === 1 && (
                <button
                  type="button"
                  className="va-btn-primary va-btn-full"
                  disabled={loading}
                  style={loading ? { opacity:0.6, cursor:'not-allowed' } : {}}
                  onClick={sendOtp}
                >
                  {loading ? '◌ SENDING OTP...' : '→ SEND OTP'}
                </button>
              )}

              {step === 2 && (
                <>
                  <button
                    type="button"
                    className="va-btn-primary va-btn-full"
                    disabled={loading}
                    style={loading ? { opacity:0.6, cursor:'not-allowed' } : {}}
                    onClick={verifyOtp}
                  >
                    {loading ? '◌ VERIFYING...' : '→ VERIFY OTP'}
                  </button>
                  <button
                    type="button"
                    className="va-auth-link"
                    onClick={sendOtp}
                    style={{ alignSelf: 'center' }}
                  >
                    Resend OTP
                  </button>
                </>
              )}

              {step === 3 && (
                <button
                  type="button"
                  className="va-btn-primary va-btn-full"
                  disabled={loading}
                  style={loading ? { opacity:0.6, cursor:'not-allowed' } : {}}
                  onClick={resetWithOtp}
                >
                  {loading ? '◌ RESETTING...' : '→ RESET PASSWORD'}
                </button>
              )}

              <button
                type="button"
                className="va-auth-link"
                onClick={backToLogin}
                style={{ alignSelf: 'center' }}
              >
                Back to login
              </button>
            </div>
          )}

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