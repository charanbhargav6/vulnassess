// PATH: vulnassess-app/screens/LoginScreen.js
import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ActivityIndicator } from 'react-native';
import { api } from '../services/api';
import { useTheme } from '../context/ThemeContext';

export default function LoginScreen({ navigation }) {
  const { theme } = useTheme();
  const [email,    setEmail]    = useState('');
  const [password, setPassword] = useState('');
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');

  const handleLogin = async () => {
    await api.storage.clear();
    setError('');
    const normalizedEmail = (email || '').trim().toLowerCase();
    const rawPassword = password || '';
    if (!normalizedEmail || !rawPassword) { setError('Please enter email and password'); return; }
    setLoading(true);
    try {
      const data = await api.login(normalizedEmail, rawPassword);
      if (data.access_token) {
        // Must use token directly or re-fetch me if needed
        navigation.replace('Dashboard');
      } else {
        setError(data.detail || 'Invalid credentials');
      }
    } catch { setError('Cannot connect to server'); }
    setLoading(false);
  };

  const s = styles(theme);
  return (
    <View style={s.container}>
      <View style={s.card}>
        <Text style={s.logo}>⬡</Text>
        <Text style={s.title}>VULNASSESS</Text>
        <Text style={s.subtitle}>Web Vulnerability Scanner</Text>

        {!!error && (
          <View style={s.errorBox}>
            <Text style={s.errorText}>⚠ {error}</Text>
          </View>
        )}

        <Text style={s.label}>EMAIL</Text>
        <TextInput
          style={s.input} placeholder="operator@domain.com"
          placeholderTextColor={theme.textMuted} value={email}
          onChangeText={t => { setEmail(t); setError(''); }}
          autoCapitalize="none" autoCorrect={false} keyboardType="email-address"
        />

        <Text style={s.label}>PASSWORD</Text>
        <TextInput
          style={s.input} placeholder="••••••••"
          placeholderTextColor={theme.textMuted} value={password}
          onChangeText={t => { setPassword(t); setError(''); }}
          secureTextEntry autoCapitalize="none" autoCorrect={false}
        />

        <TouchableOpacity style={[s.btn, loading && s.btnDisabled]} onPress={handleLogin} disabled={loading}>
          {loading ? <ActivityIndicator color={theme.card} /> : <Text style={s.btnText}>→ AUTHENTICATE</Text>}
        </TouchableOpacity>

        <View style={s.divider} />
        <TouchableOpacity onPress={() => navigation.navigate('Register')}>
          <Text style={s.link}>No account? <Text style={{ fontWeight: 'bold' }}>REQUEST ACCESS</Text></Text>
        </TouchableOpacity>
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
  errorBox:   { backgroundColor:t.dangerBg, borderWidth:1, borderColor:t.dangerBorder, borderRadius:8, padding:12, marginBottom:16 },
  errorText:  { color:t.danger, fontSize:13, fontWeight:'600' },
  btn:        { backgroundColor:t.accent, borderRadius:8, padding:14, alignItems:'center', marginTop:16 },
  btnDisabled:{ opacity:0.6 },
  btnText:    { color:t.card, fontWeight:'bold', fontSize:14, letterSpacing:1 },
  divider:    { height:1, backgroundColor:t.border, marginVertical:20 },
  link:       { textAlign:'center', color:t.textMuted, fontSize:13 },
});