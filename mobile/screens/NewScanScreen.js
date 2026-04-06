// PATH: vulnassess-app/screens/NewScanScreen.js
import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ActivityIndicator, ScrollView, Alert, Image } from 'react-native';
import { api } from '../services/api';
import { useTheme } from '../context/ThemeContext';

const ALL_MODULES = [
  { key:'auth_test',         label:'Authentication Testing',     fixed:true  },
  { key:'sql_injection',     label:'SQL Injection'                            },
  { key:'xss',               label:'Cross-Site Scripting (XSS)'              },
  { key:'command_injection', label:'OS Command Injection'                     },
  { key:'ssrf',              label:'SSRF'                                     },
  { key:'xxe',               label:'XXE Injection'                            },
  { key:'path_traversal',    label:'Path Traversal / LFI'                    },
  { key:'idor',              label:'IDOR'                                     },
  { key:'open_redirect',     label:'Open Redirect'                           },
  { key:'file_upload',       label:'File Upload'                             },
  { key:'csrf',              label:'CSRF Protection'                         },
  { key:'security_headers',  label:'Security Headers'                        },
  { key:'ssl_tls',           label:'SSL / TLS Analysis'                      },
  { key:'cors_check',        label:'CORS Misconfiguration'                   },
  { key:'cookie_security',   label:'Cookie Security'                         },
  { key:'clickjacking',      label:'Clickjacking'                            },
  { key:'info_disclosure',   label:'Information Disclosure'                  },
  { key:'rate_limiting',     label:'Rate Limiting'                           },
  { key:'graphql',           label:'GraphQL Security'                        },
  { key:'api_key_leakage',   label:'API Key Leakage'                         },
  { key:'jwt',               label:'JWT Security'                            },
  { key:'rate_limit',        label:'Rate Limit Bypass'                       },
];

export default function NewScanScreen({ navigation }) {
  const { theme } = useTheme();
  const [targetUrl,     setTargetUrl]     = useState('');
  const [selected,      setSelected]      = useState(ALL_MODULES.map(m => m.key));
  const [loading,       setLoading]       = useState(false);
  const [verifying,     setVerifying]     = useState(false);
  const [error,         setError]         = useState('');
  const [verifyToken,   setVerifyToken]   = useState('');
  const [verifiedUrl,   setVerifiedUrl]   = useState('');
  const [siteTitle,     setSiteTitle]     = useState('');
  const [faviconUrl,    setFaviconUrl]    = useState('');
  const [showModules,   setShowModules]   = useState(false);

  const toggle = key => {
    const m = ALL_MODULES.find(x => x.key === key);
    if (m?.fixed) return;
    setSelected(prev => prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]);
  };

  const toggleAll = () => {
    const nonFixed = ALL_MODULES.filter(m => !m.fixed).map(m => m.key);
    const allOn = nonFixed.every(k => selected.includes(k));
    setSelected(allOn ? ALL_MODULES.filter(m => m.fixed).map(m => m.key) : ALL_MODULES.map(m => m.key));
  };

  const handleVerify = async () => {
    if (!targetUrl) { setError('Target URL is required'); return; }
    setVerifying(true);
    setError('');
    setVerifyToken('');
    setVerifiedUrl('');
    setSiteTitle('');
    setFaviconUrl('');
    try {
      const res = await api.verifyTarget(targetUrl.trim());
      if (res?.verified && res?.verification_token) {
        setVerifyToken(res.verification_token);
        setVerifiedUrl(res.normalized_url || '');
        setSiteTitle(res.title || '');
        setFaviconUrl(res.favicon_url || '');
      } else if (String(res?.detail || '').toLowerCase().includes('permission')) {
        setError('u dont have permission to scan this url');
        Alert.alert('Permission', 'u dont have permission to scan this url');
      } else {
        setError('url not found');
        Alert.alert('Error', 'url not found');
      }
    } catch (e) {
      const msg = e?.message || '';
      if (msg.toLowerCase().includes('permission')) {
        setError('u dont have permission to scan this url');
        Alert.alert('Permission', 'u dont have permission to scan this url');
      } else {
        setError('url not found');
        Alert.alert('Error', 'url not found');
      }
    }
    setVerifying(false);
  };

  const handleStart = async () => {
    if (!targetUrl) { setError('Target URL is required'); return; }
    if (!verifyToken) { setError('Verify URL first'); return; }
    const url = verifiedUrl || targetUrl.trim();
    setLoading(true);
    try {
      const data = await api.startScan({ target_url: url, verify_token: verifyToken });
      if (data.scan_id || data._id || data.id) {
        navigation.replace('ScanProgress', { scanId: data.scan_id || data._id || data.id });
      } else {
        setError(data.detail || 'Failed to start scan');
      }
    } catch { setError('Cannot connect to server'); }
    setLoading(false);
  };

  const s = StyleSheet.create({
    container:  { flex:1, backgroundColor:theme.bg },
    section:    { backgroundColor:theme.card, borderRadius:14, margin:12, marginBottom:0, padding:16, borderWidth:1, borderColor:theme.border },
    sTitle:     { fontSize:11, fontWeight:'bold', color:theme.textSecondary, letterSpacing:2, marginBottom:14 },
    label:      { fontSize:10, fontWeight:'bold', color:theme.textSecondary, letterSpacing:1.5, marginBottom:6, marginTop:10 },
    input:      { backgroundColor:theme.input, borderWidth:1, borderColor:theme.inputBorder, borderRadius:8, padding:12, fontSize:14, color:theme.text },
    errorBox:   { backgroundColor:theme.dangerBg, borderWidth:1, borderColor:theme.dangerBorder, borderRadius:8, padding:12, marginBottom:12 },
    errorText:  { color:theme.danger, fontSize:13 },
    hint:       { backgroundColor:theme.accentMuted, borderRadius:8, padding:12, marginTop:12, borderWidth:1, borderColor:theme.mediumBorder },
    hintText:   { color:theme.textSecondary, fontSize:12, lineHeight:18 },
    btn:        { backgroundColor:theme.accent, borderRadius:10, padding:15, alignItems:'center', margin:12, marginTop:14 },
    btnDisabled:{ opacity:0.6 },
    btnText:    { color:theme.card, fontWeight:'bold', fontSize:15, letterSpacing:1 },
    verifyRow:  { flexDirection:'row', alignItems:'center', justifyContent:'space-between', marginTop:10 },
    verifyBtn:  { paddingHorizontal:14, paddingVertical:8, borderRadius:8, borderWidth:1, borderColor:theme.border, backgroundColor:theme.bg },
    verifyText: { color:theme.textSecondary, fontWeight:'bold', fontSize:12 },
    verifiedCard:{ marginTop:10, borderWidth:1, borderColor:theme.border, borderRadius:10, padding:10, backgroundColor:theme.bg2 },
    verifiedTitle:{ color:theme.text, fontWeight:'bold', fontSize:12 },
    verifiedUrl:{ color:theme.textMuted, fontSize:11, marginTop:2 },
    modHeader:  { flexDirection:'row', justifyContent:'space-between', alignItems:'center' },
    modToggle:  { color:theme.accent, fontSize:12, fontWeight:'bold' },
    modItem:    { flexDirection:'row', justifyContent:'space-between', alignItems:'center',
                  paddingVertical:10, borderBottomWidth:1, borderBottomColor:theme.border },
    modLabel:   { fontSize:13, color:theme.text, flex:1 },
    modFixed:   { fontSize:9, color:theme.accent, marginLeft:6, letterSpacing:1 },
    checkbox:   { width:20, height:20, borderRadius:5, borderWidth:1, borderColor:theme.border,
                  alignItems:'center', justifyContent:'center' },
    checkOn:    { backgroundColor:theme.accent, borderColor:theme.accent },
    checkMark:  { color:'#fff', fontSize:11, fontWeight:'bold' },
  });

  return (
    <ScrollView style={s.container} contentContainerStyle={{ paddingBottom:40 }}>
      {/* Target */}
      <View style={s.section}>
        <Text style={s.sTitle}>TARGET CONFIGURATION</Text>
        {!!error && <View style={s.errorBox}><Text style={s.errorText}>⚠ {error}</Text></View>}
        <Text style={s.label}>TARGET URL</Text>
        <TextInput style={s.input} placeholder="https://example.com" placeholderTextColor={theme.textMuted}
          value={targetUrl} onChangeText={t => {
            setTargetUrl(t);
            setError('');
            setVerifyToken('');
            setVerifiedUrl('');
            setSiteTitle('');
            setFaviconUrl('');
          }} autoCapitalize="none" keyboardType="url"/>
        <View style={s.verifyRow}>
          <TouchableOpacity style={s.verifyBtn} onPress={handleVerify} disabled={verifying || loading}>
            <Text style={s.verifyText}>{verifying ? 'VERIFYING...' : 'VERIFY URL'}</Text>
          </TouchableOpacity>
          <Text style={{ color: verifyToken ? theme.success : theme.textMuted, fontSize:11, fontWeight:'bold' }}>
            {verifyToken ? 'VERIFIED' : 'NOT VERIFIED'}
          </Text>
        </View>
        {!!verifyToken && (
          <View style={s.verifiedCard}>
            <View style={{ flexDirection:'row', alignItems:'center', gap:8 }}>
              {!!faviconUrl && <Image source={{ uri: faviconUrl }} style={{ width:20, height:20, borderRadius:4 }} />}
              <View style={{ flex:1 }}>
                <Text style={s.verifiedTitle}>{siteTitle || 'Verified target'}</Text>
                <Text style={s.verifiedUrl} numberOfLines={1}>{verifiedUrl}</Text>
              </View>
            </View>
          </View>
        )}
        <View style={s.hint}>
          <Text style={s.hintText}>ℹ Only scan systems you own or have explicit written permission to test.</Text>
        </View>
      </View>

      <View style={s.section}>
        <Text style={s.sTitle}>PROXY</Text>
        <Text style={{ color:theme.textSecondary, fontSize:12 }}>
          Proxy can be changed from Dashboard or Profile only.
        </Text>
      </View>

      {/* Modules */}
      <View style={s.section}>
        <View style={s.modHeader}>
          <Text style={s.sTitle}>MODULES ({selected.length}/{ALL_MODULES.length})</Text>
          <TouchableOpacity onPress={() => setShowModules(v => !v)}>
            <Text style={s.modToggle}>{showModules ? 'HIDE ▲' : 'SHOW ▼'}</Text>
          </TouchableOpacity>
        </View>
        {showModules && (
          <>
            <TouchableOpacity onPress={toggleAll} style={{ alignSelf:'flex-end', marginBottom:8 }}>
              <Text style={s.modToggle}>
                {ALL_MODULES.filter(m => !m.fixed).every(m => selected.includes(m.key)) ? 'DESELECT ALL' : 'SELECT ALL'}
              </Text>
            </TouchableOpacity>
            {ALL_MODULES.map(m => (
              <TouchableOpacity key={m.key} style={s.modItem} onPress={() => toggle(m.key)}>
                <Text style={[s.modLabel, !selected.includes(m.key) && { color:theme.textMuted }]}>
                  {m.label}
                  {m.fixed && <Text style={s.modFixed}> FIXED</Text>}
                </Text>
                <View style={[s.checkbox, selected.includes(m.key) && s.checkOn]}>
                  {selected.includes(m.key) && <Text style={s.checkMark}>✓</Text>}
                </View>
              </TouchableOpacity>
            ))}
          </>
        )}
      </View>

      <TouchableOpacity style={[s.btn, (loading || !verifyToken) && s.btnDisabled]} onPress={handleStart} disabled={loading || !verifyToken}>
        {loading ? <ActivityIndicator color={theme.card}/> : <Text style={s.btnText}>⊕ LAUNCH SCAN ({selected.length} modules)</Text>}
      </TouchableOpacity>
    </ScrollView>
  );
}