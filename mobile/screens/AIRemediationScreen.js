// PATH: vulnassess-app/screens/AIRemediationScreen.js
import React, { useState, useEffect } from 'react';
import { View, Text, ScrollView, TouchableOpacity, ActivityIndicator, Alert } from 'react-native';
import * as WebBrowser from 'expo-web-browser';
import { api } from '../services/api';
import { BASE_URL } from '../services/apiCore';
import { useTheme } from '../context/ThemeContext';

export default function AIRemediationScreen({ route, navigation }) {
  const { theme } = useTheme();
  const { scanId } = route.params;
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

  const handlePDF = async () => {
    setPdfLoading(true);
    try {
      const downloadSession = await api.getReportDownloadToken(scanId).catch(() => null);
      if (!downloadSession?.token) {
        Alert.alert('Error', 'Could not create secure download link. Please try again.');
        setPdfLoading(false);
        return;
      }
      await WebBrowser.openBrowserAsync(`${BASE_URL}/reports/${scanId}/ai-remediation/pdf?token=${encodeURIComponent(downloadSession.token)}`);
    } catch { Alert.alert('Error', 'Could not open AI PDF'); }
    setPdfLoading(false);
  };

  const sevColor = sev => ({
    critical:theme.critical, high:theme.high,
    medium:theme.medium, low:theme.low,
  })[sev?.toLowerCase()] || theme.blue;

  const priorityColor = p => p===1 ? theme.critical : p===2 ? theme.high : p<=3 ? theme.warning : theme.textMuted;

  if (loading) return (
    <View style={{ flex:1, justifyContent:'center', alignItems:'center', backgroundColor:theme.bg }}>
      <Text style={{ fontSize:40, marginBottom:16 }}>🤖</Text>
      <ActivityIndicator color={theme.accent} size="large"/>
      <Text style={{ color:theme.textSecondary, marginTop:16, fontWeight:'bold', letterSpacing:1, fontSize:12 }}>
        ANALYSING VULNERABILITIES…
      </Text>
      <Text style={{ color:theme.textMuted, marginTop:6, fontSize:12 }}>This may take 15–30 seconds</Text>
    </View>
  );

  return (
    <ScrollView style={{ backgroundColor:theme.bg }} contentContainerStyle={{ padding:16, paddingBottom:40 }}>
      {/* Header */}
      <View style={{ flexDirection:'row', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
        <View style={{ flex:1 }}>
          <Text style={{ fontSize:18, fontWeight:'bold', color:theme.text, letterSpacing:1 }}>AI REMEDIATION</Text>
          <View style={{ flexDirection:'row', alignItems:'center', gap:8, marginTop:4 }}>
            <View style={{ backgroundColor:theme.mediumBg, borderRadius:20, paddingHorizontal:10, paddingVertical:3, borderWidth:1, borderColor:theme.mediumBorder }}>
              <Text style={{ color:theme.medium, fontSize:10, fontWeight:'bold', letterSpacing:1 }}>Claude AI</Text>
            </View>
          </View>
        </View>
        {data && (
          <TouchableOpacity
            style={{ backgroundColor:'rgba(139,92,246,0.12)', borderRadius:10, padding:10, borderWidth:1, borderColor:'rgba(139,92,246,0.35)', opacity:pdfLoading?0.6:1 }}
            onPress={handlePDF} disabled={pdfLoading}>
            <Text style={{ color:'#A78BFA', fontWeight:'bold', fontSize:12 }}>
              {pdfLoading ? '◌ Loading…' : '↓ PDF'}
            </Text>
          </TouchableOpacity>
        )}
      </View>

      {/* Error */}
      {!!error && (
        <View style={{ backgroundColor:theme.dangerBg, borderRadius:12, padding:16, marginBottom:14, borderWidth:1, borderColor:theme.dangerBorder, borderLeftWidth:3, borderLeftColor:theme.danger }}>
          <Text style={{ color:theme.danger, fontWeight:'bold', marginBottom:8 }}>Error</Text>
          <Text style={{ color:theme.danger, fontSize:13 }}>{error}</Text>
          <TouchableOpacity style={{ marginTop:10, alignSelf:'flex-start', borderWidth:1, borderColor:theme.dangerBorder, borderRadius:8, paddingHorizontal:12, paddingVertical:6 }}
            onPress={load}>
            <Text style={{ color:theme.danger, fontWeight:'bold', fontSize:12 }}>Retry</Text>
          </TouchableOpacity>
        </View>
      )}

      {data && (
        <>
          {/* Executive Summary */}
          {data.executive_summary && (
            <View style={{ backgroundColor:theme.card, borderRadius:14, padding:16, marginBottom:12, borderWidth:1, borderColor:theme.border }}>
              <Text style={{ fontSize:10, fontWeight:'bold', color:'#8B5CF6', letterSpacing:2, marginBottom:8 }}>EXECUTIVE SUMMARY</Text>
              <Text style={{ color:theme.text, fontSize:14, lineHeight:22 }}>{data.executive_summary}</Text>
            </View>
          )}

          {/* Critical Action */}
          {data.critical_action && (
            <View style={{ backgroundColor:theme.criticalBg, borderRadius:14, padding:16, marginBottom:12,
              borderWidth:1, borderColor:theme.criticalBorder, flexDirection:'row', gap:12 }}>
              <Text style={{ fontSize:22 }}>⚡</Text>
              <View style={{ flex:1 }}>
                <Text style={{ fontSize:10, fontWeight:'bold', color:theme.critical, letterSpacing:2, marginBottom:6 }}>
                  IMMEDIATE ACTION REQUIRED
                </Text>
                <Text style={{ color:theme.critical, fontSize:13, lineHeight:20 }}>{data.critical_action}</Text>
              </View>
            </View>
          )}

          {(data.remediations||[]).length === 0 && (
            <View style={{ alignItems:'center', padding:40 }}>
              <Text style={{ fontSize:40 }}>✅</Text>
              <Text style={{ color:theme.textSecondary, marginTop:12, fontSize:15 }}>No remediations needed.</Text>
            </View>
          )}

          {(data.remediations||[]).map(r => {
            const open = expanded[r.id];
            return (
              <View key={r.id} style={{ backgroundColor:theme.card, borderRadius:14, marginBottom:10, borderWidth:1, borderColor:theme.border, overflow:'hidden' }}>
                <TouchableOpacity
                  style={{ padding:14, flexDirection:'row', justifyContent:'space-between', alignItems:'center' }}
                  onPress={() => toggle(r.id)}>
                  <View style={{ flex:1, flexDirection:'row', alignItems:'center', flexWrap:'wrap', gap:8 }}>
                    <View style={{ backgroundColor:priorityColor(r.priority)+'25', borderRadius:6, paddingHorizontal:7, paddingVertical:3 }}>
                      <Text style={{ color:priorityColor(r.priority), fontSize:10, fontWeight:'bold' }}>P{r.priority}</Text>
                    </View>
                    <Text style={{ color:theme.text, fontSize:14, fontWeight:'bold', flex:1 }} numberOfLines={1}>{r.vuln_type}</Text>
                    <View style={{ backgroundColor:sevColor(r.severity)+'25', borderRadius:5, paddingHorizontal:7, paddingVertical:3 }}>
                      <Text style={{ color:sevColor(r.severity), fontSize:9, fontWeight:'bold', letterSpacing:1 }}>
                        {(r.severity||'info').toUpperCase()}
                      </Text>
                    </View>
                  </View>
                  <Text style={{ color:theme.textMuted, fontSize:14, marginLeft:8,
                    transform:[{rotate: open ? '180deg' : '0deg'}] }}>▼</Text>
                </TouchableOpacity>

                {open && (
                  <View style={{ paddingHorizontal:14, paddingBottom:14, borderTopWidth:1, borderTopColor:theme.border }}>
                    {r.summary && (
                      <Text style={{ color:theme.textSecondary, fontSize:13, lineHeight:20, paddingVertical:10 }}>
                        {r.summary}
                      </Text>
                    )}

                    {r.fix_steps?.length > 0 && (
                      <>
                        <Text style={{ fontSize:10, fontWeight:'bold', color:theme.textSecondary, letterSpacing:2, marginTop:8, marginBottom:8 }}>FIX STEPS</Text>
                        {r.fix_steps.map((step, i) => (
                          <View key={i} style={{ flexDirection:'row', gap:10, marginBottom:8 }}>
                            <View style={{ backgroundColor:theme.blue, borderRadius:11, width:22, height:22,
                              alignItems:'center', justifyContent:'center', flexShrink:0, marginTop:1 }}>
                              <Text style={{ color:'#fff', fontSize:10, fontWeight:'bold' }}>{i+1}</Text>
                            </View>
                            <Text style={{ color:theme.text, fontSize:13, flex:1, lineHeight:20 }}>{step}</Text>
                          </View>
                        ))}
                      </>
                    )}

                    {r.code_example && (
                      <>
                        <Text style={{ fontSize:10, fontWeight:'bold', color:theme.textSecondary, letterSpacing:2, marginTop:10, marginBottom:6 }}>CODE EXAMPLE</Text>
                        <View style={{ backgroundColor:theme.bg, borderRadius:8, padding:12, borderWidth:1, borderColor:theme.border }}>
                          <Text style={{ color:theme.text, fontSize:11, fontFamily:'monospace', lineHeight:18 }}>{r.code_example}</Text>
                        </View>
                      </>
                    )}

                    {r.references?.length > 0 && (
                      <>
                        <Text style={{ fontSize:10, fontWeight:'bold', color:theme.textSecondary, letterSpacing:2, marginTop:10, marginBottom:6 }}>REFERENCES</Text>
                        <View style={{ flexDirection:'row', flexWrap:'wrap', gap:8 }}>
                          {r.references.map((ref, i) => (
                            <TouchableOpacity key={i}
                              style={{ backgroundColor:theme.mediumBg, borderRadius:6, paddingHorizontal:10, paddingVertical:5, borderWidth:1, borderColor:theme.mediumBorder }}
                              onPress={() => WebBrowser.openBrowserAsync(ref)}>
                              <Text style={{ color:theme.medium, fontSize:11 }}>
                                {ref.replace('https://','').split('/')[0]}
                              </Text>
                            </TouchableOpacity>
                          ))}
                        </View>
                      </>
                    )}

                    {r.estimated_effort && (
                      <Text style={{ color:theme.textMuted, fontSize:11, marginTop:10 }}>
                        Estimated effort: <Text style={{ fontWeight:'bold', color:theme.textSecondary }}>{r.estimated_effort}</Text>
                      </Text>
                    )}
                  </View>
                )}
              </View>
            );
          })}
        </>
      )}
    </ScrollView>
  );
}