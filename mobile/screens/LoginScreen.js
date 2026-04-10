// PATH: vulnassess-app/screens/LoginScreen.js
import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ActivityIndicator } from 'react-native';
import { api } from '../services/api';
import { useTheme } from '../context/ThemeContext';

export default function LoginScreen({ navigation }) {
  const { theme } = useTheme();
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

  const handleLogin = async () => {
    setError('');
    const normalizedEmail = (email || '').trim().toLowerCase();
    const rawPassword = password || '';
    if (!normalizedEmail || !rawPassword) { setError('Please enter email and password'); return; }
    setLoading(true);
    try {
      const data = await api.login(normalizedEmail, rawPassword);
      if (data.access_token) {
        navigation.reset({ index: 0, routes: [{ name: 'Dashboard' }] });
      } else {
        setError(data.detail || 'Invalid credentials');
      }
    } catch (err) {
      const detail = err?.message || err?.detail || '';
      setError(detail || 'Cannot connect to server');
    }
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
        setMode('login');
        setStep(1);
        setPassword('');
        setOtp('');
        setNewPassword('');
        setConfirmPassword('');
        setError('');
        setSuccess('Password reset successful. You can login now.');
      } else {
        setError(res?.detail || 'Password reset failed');
      }
    } catch {
      setError('Cannot connect to server');
    } finally {
      setLoading(false);
    }
  };

  const s = styles(theme);
  return (
    <View style={s.container}>
      <View style={s.card}>
        <Text style={s.logo}>⬡</Text>
        <Text style={s.title}>VULNASSESS</Text>
        <Text style={s.subtitle}>{mode === 'login' ? 'Web Vulnerability Scanner' : 'Request OTP, verify, and reset password'}</Text>

        {!!error && (
          <View style={s.errorBox}>
            <Text style={s.errorText}>⚠ {error}</Text>
          </View>
        )}

        {!!success && (
          <View style={s.successBox}>
            <Text style={s.successText}>✓ {success}</Text>
          </View>
        )}

        <Text style={s.label}>EMAIL</Text>
        <TextInput
          style={s.input} placeholder="operator@domain.com"
          placeholderTextColor={theme.textMuted} value={email}
          onChangeText={t => { setEmail(t); setError(''); setSuccess(''); }}
          autoCapitalize="none" autoCorrect={false} keyboardType="email-address"
        />

        {mode === 'login' ? (
          <>
            <Text style={s.label}>PASSWORD</Text>
            <View style={s.inputRow}>
              <TextInput
                style={[s.input, { flex: 1, marginBottom: 0 }]}
                placeholder="••••••••"
                placeholderTextColor={theme.textMuted}
                value={password}
                onChangeText={t => { setPassword(t); setError(''); setSuccess(''); }}
                secureTextEntry={!showPassword}
                autoCapitalize="none"
                autoCorrect={false}
              />
              <TouchableOpacity onPress={() => setShowPassword(v => !v)} style={s.showBtn}>
                <Text style={s.showBtnText}>{showPassword ? 'HIDE' : 'SHOW'}</Text>
              </TouchableOpacity>
            </View>

            <TouchableOpacity style={[s.btn, loading && s.btnDisabled]} onPress={handleLogin} disabled={loading}>
              {loading ? <ActivityIndicator color={theme.card} /> : <Text style={s.btnText}>→ AUTHENTICATE</Text>}
            </TouchableOpacity>

            <TouchableOpacity onPress={startForgot}>
              <Text style={s.link}>Forgot password?</Text>
            </TouchableOpacity>
          </>
        ) : (
          <>
            {step >= 2 && (
              <>
                <Text style={s.label}>OTP CODE</Text>
                <TextInput
                  style={s.input}
                  placeholder="6-digit OTP"
                  placeholderTextColor={theme.textMuted}
                  value={otp}
                  onChangeText={t => { setOtp((t || '').replace(/\D/g, '').slice(0, 6)); setError(''); setSuccess(''); }}
                  keyboardType="number-pad"
                  autoCapitalize="none"
                  autoCorrect={false}
                />
              </>
            )}

            {step === 3 && (
              <>
                <Text style={s.label}>NEW PASSWORD</Text>
                <View style={s.inputRow}>
                  <TextInput
                    style={[s.input, { flex: 1, marginBottom: 0 }]}
                    placeholder="At least 8 chars, uppercase/lowercase/number"
                    placeholderTextColor={theme.textMuted}
                    value={newPassword}
                    onChangeText={t => { setNewPassword(t); setError(''); setSuccess(''); }}
                    secureTextEntry={!showNewPassword}
                    autoCapitalize="none"
                    autoCorrect={false}
                  />
                  <TouchableOpacity onPress={() => setShowNewPassword(v => !v)} style={s.showBtn}>
                    <Text style={s.showBtnText}>{showNewPassword ? 'HIDE' : 'SHOW'}</Text>
                  </TouchableOpacity>
                </View>

                <Text style={s.label}>CONFIRM PASSWORD</Text>
                <View style={s.inputRow}>
                  <TextInput
                    style={[s.input, { flex: 1, marginBottom: 0 }]}
                    placeholder="Re-enter new password"
                    placeholderTextColor={theme.textMuted}
                    value={confirmPassword}
                    onChangeText={t => { setConfirmPassword(t); setError(''); setSuccess(''); }}
                    secureTextEntry={!showConfirmPassword}
                    autoCapitalize="none"
                    autoCorrect={false}
                  />
                  <TouchableOpacity onPress={() => setShowConfirmPassword(v => !v)} style={s.showBtn}>
                    <Text style={s.showBtnText}>{showConfirmPassword ? 'HIDE' : 'SHOW'}</Text>
                  </TouchableOpacity>
                </View>
              </>
            )}

            {step === 1 && (
              <TouchableOpacity style={[s.btn, loading && s.btnDisabled]} onPress={sendOtp} disabled={loading}>
                {loading ? <ActivityIndicator color={theme.card} /> : <Text style={s.btnText}>→ SEND OTP</Text>}
              </TouchableOpacity>
            )}

            {step === 2 && (
              <>
                <TouchableOpacity style={[s.btn, loading && s.btnDisabled]} onPress={verifyOtp} disabled={loading}>
                  {loading ? <ActivityIndicator color={theme.card} /> : <Text style={s.btnText}>→ VERIFY OTP</Text>}
                </TouchableOpacity>
                <TouchableOpacity onPress={sendOtp}>
                  <Text style={s.link}>Resend OTP</Text>
                </TouchableOpacity>
              </>
            )}

            {step === 3 && (
              <TouchableOpacity style={[s.btn, loading && s.btnDisabled]} onPress={resetWithOtp} disabled={loading}>
                {loading ? <ActivityIndicator color={theme.card} /> : <Text style={s.btnText}>→ RESET PASSWORD</Text>}
              </TouchableOpacity>
            )}

            <TouchableOpacity onPress={backToLogin}>
              <Text style={s.link}>Back to login</Text>
            </TouchableOpacity>
          </>
        )}

        <View style={s.divider} />
        {mode === 'login' && (
          <TouchableOpacity onPress={() => navigation.navigate('Register')}>
            <Text style={s.link}>No account? <Text style={{ fontWeight: 'bold' }}>REQUEST ACCESS</Text></Text>
          </TouchableOpacity>
        )}
      </View>
    </View>
  );
}

const styles = t => StyleSheet.create({
  container:  { flex:1, justifyContent:'center', padding:20, backgroundColor:t.bg },
  card:       { backgroundColor:t.card, borderRadius:16, padding:28, borderWidth:1, borderColor:t.border, maxWidth:420, width:'100%', alignSelf:'center' },
  logo:       { fontSize:36, color:t.accent, textAlign:'center', marginBottom:4 },
  title:      { fontSize:22, fontWeight:'bold', color:t.accent, textAlign:'center', letterSpacing:3, marginBottom:2 },
  subtitle:   { fontSize:13, color:t.textMuted, textAlign:'center', marginBottom:24 },
  label:      { fontSize:10, fontWeight:'bold', color:t.textSecondary, letterSpacing:2, marginBottom:6, marginTop:4 },
  input:      { backgroundColor:t.input, borderWidth:1, borderColor:t.inputBorder, borderRadius:8, padding:12, fontSize:14, color:t.text, marginBottom:4 },
  inputRow:   { flexDirection:'row', alignItems:'center', gap:8, marginBottom:4 },
  showBtn:    { borderWidth:1, borderColor:t.border, borderRadius:8, paddingVertical:10, paddingHorizontal:10, backgroundColor:t.bg2 },
  showBtnText:{ color:t.textSecondary, fontSize:11, fontWeight:'700', letterSpacing:0.8 },
  errorBox:   { backgroundColor:t.dangerBg, borderWidth:1, borderColor:t.dangerBorder, borderRadius:8, padding:12, marginBottom:16 },
  errorText:  { color:t.danger, fontSize:13, fontWeight:'600' },
  successBox: { backgroundColor:'rgba(16,185,129,0.12)', borderWidth:1, borderColor:'rgba(16,185,129,0.5)', borderRadius:8, padding:12, marginBottom:16 },
  successText:{ color:'#34D399', fontSize:13, fontWeight:'600' },
  btn:        { backgroundColor:t.accent, borderRadius:8, padding:14, alignItems:'center', marginTop:16 },
  btnDisabled:{ opacity:0.6 },
  btnText:    { color:t.card, fontWeight:'bold', fontSize:14, letterSpacing:1 },
  divider:    { height:1, backgroundColor:t.border, marginVertical:20 },
  link:       { textAlign:'center', color:t.textMuted, fontSize:13 },
});