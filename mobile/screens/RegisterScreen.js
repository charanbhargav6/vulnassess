// PATH: vulnassess-app/screens/RegisterScreen.js
import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ActivityIndicator, ScrollView } from 'react-native';
import { api } from '../services/api';
import { useTheme } from '../context/ThemeContext';

const RULES = [
  { label:'At least 8 characters',       test: p => p.length >= 8 },
  { label:'One uppercase letter (A–Z)',   test: p => /[A-Z]/.test(p) },
  { label:'One lowercase letter (a–z)',   test: p => /[a-z]/.test(p) },
  { label:'One number (0–9)',             test: p => /\d/.test(p) },
];

export default function RegisterScreen({ navigation }) {
  const { theme } = useTheme();
  const [email,    setEmail]    = useState('');
  const [password, setPassword] = useState('');
  const [confirm,  setConfirm]  = useState('');
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');
  const [success,  setSuccess]  = useState(false);

  const handleRegister = async () => {
    setError('');
    if (!email || !password || !confirm) { setError('All fields are required'); return; }
    if (password !== confirm)            { setError('Passwords do not match'); return; }
    if (!RULES.every(r => r.test(password))) { setError('Password does not meet requirements'); return; }
    setLoading(true);
    try {
      const data = await api.register(email, password);
      if (data.id || data.email || data.message) setSuccess(true);
      else setError(data.detail || 'Registration failed');
    } catch { setError('Cannot connect to server'); }
    setLoading(false);
  };

  const s = styles(theme);

  if (success) return (
    <View style={s.container}>
      <View style={s.card}>
        <Text style={s.successIcon}>✉</Text>
        <Text style={s.successTitle}>CHECK YOUR EMAIL</Text>
        <Text style={s.successSub}>Verification link sent to:</Text>
        <Text style={s.successEmail}>{email}</Text>
        <TouchableOpacity style={s.btn} onPress={() => navigation.replace('Login')}>
          <Text style={s.btnText}>← BACK TO LOGIN</Text>
        </TouchableOpacity>
      </View>
    </View>
  );

  return (
    <ScrollView style={{ backgroundColor:theme.bg }} contentContainerStyle={{ padding:20, paddingVertical:40 }}>
      <View style={s.card}>
        <Text style={s.title}>REQUEST ACCESS</Text>
        <Text style={s.subtitle}>Create your operator account</Text>

        {!!error && <View style={s.errorBox}><Text style={s.errorText}>⚠ {error}</Text></View>}

        <Text style={s.label}>EMAIL ADDRESS</Text>
        <TextInput style={s.input} placeholder="operator@domain.com" placeholderTextColor={theme.textMuted}
          value={email} onChangeText={t=>{setEmail(t);setError('');}} autoCapitalize="none" keyboardType="email-address"/>

        <Text style={s.label}>PASSWORD</Text>
        <TextInput style={s.input} placeholder="••••••••" placeholderTextColor={theme.textMuted}
          value={password} onChangeText={t=>{setPassword(t);setError('');}} secureTextEntry/>

        {password.length > 0 && (
          <View style={s.rulesBox}>
            {RULES.map((r,i) => (
              <Text key={i} style={[s.rule, { color: r.test(password) ? theme.success : theme.textMuted }]}>
                {r.test(password) ? '✓' : '○'} {r.label}
              </Text>
            ))}
          </View>
        )}

        <Text style={s.label}>CONFIRM PASSWORD</Text>
        <TextInput style={s.input} placeholder="••••••••" placeholderTextColor={theme.textMuted}
          value={confirm} onChangeText={t=>{setConfirm(t);setError('');}} secureTextEntry/>

        <TouchableOpacity style={[s.btn, loading && s.btnDisabled]} onPress={handleRegister} disabled={loading}>
          {loading ? <ActivityIndicator color={theme.card} /> : <Text style={s.btnText}>→ CREATE ACCOUNT</Text>}
        </TouchableOpacity>

        <View style={s.divider}/>
        <TouchableOpacity onPress={() => navigation.navigate('Login')}>
          <Text style={s.link}>Already have an account? <Text style={{fontWeight:'bold'}}>SIGN IN</Text></Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
}

const styles = t => StyleSheet.create({
  container:    { flex:1, justifyContent:'center', padding:20, backgroundColor:t.bg },
  card:         { backgroundColor:t.card, borderRadius:16, padding:28, borderWidth:1, borderColor:t.border, maxWidth:420, width:'100%', alignSelf:'center' },
  title:        { fontSize:20, fontWeight:'bold', color:t.accent, textAlign:'center', letterSpacing:2, marginBottom:2 },
  subtitle:     { fontSize:13, color:t.textMuted, textAlign:'center', marginBottom:20 },
  label:        { fontSize:10, fontWeight:'bold', color:t.textSecondary, letterSpacing:2, marginBottom:6, marginTop:8 },
  input:        { backgroundColor:t.input, borderWidth:1, borderColor:t.inputBorder, borderRadius:8, padding:12, fontSize:14, color:t.text, marginBottom:2 },
  errorBox:     { backgroundColor:t.dangerBg, borderWidth:1, borderColor:t.dangerBorder, borderRadius:8, padding:12, marginBottom:14 },
  errorText:    { color:t.danger, fontSize:13, fontWeight:'600' },
  rulesBox:     { backgroundColor:t.mediumBg, borderWidth:1, borderColor:t.mediumBorder, borderRadius:8, padding:12, marginBottom:8 },
  rule:         { fontSize:12, marginBottom:3 },
  btn:          { backgroundColor:t.accent, borderRadius:8, padding:14, alignItems:'center', marginTop:16 },
  btnDisabled:  { opacity:0.6 },
  btnText:      { color:t.card, fontWeight:'bold', fontSize:14, letterSpacing:1 },
  divider:      { height:1, backgroundColor:t.border, marginVertical:16 },
  link:         { textAlign:'center', color:t.textMuted, fontSize:13 },
  successIcon:  { fontSize:48, textAlign:'center', marginBottom:12 },
  successTitle: { fontSize:20, fontWeight:'bold', color:t.accent, textAlign:'center', letterSpacing:2, marginBottom:8 },
  successSub:   { fontSize:13, color:t.textMuted, textAlign:'center' },
  successEmail: { fontSize:15, fontWeight:'bold', color:t.accent, textAlign:'center', marginVertical:10 },
});