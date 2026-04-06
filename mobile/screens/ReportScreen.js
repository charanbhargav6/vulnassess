// PATH: vulnassess-app/screens/ReportScreen.js
import React, { useState, useEffect } from 'react';
import { View, Text, ScrollView, TouchableOpacity, StyleSheet, ActivityIndicator, Alert } from 'react-native';
import * as WebBrowser from 'expo-web-browser';
import { api } from '../services/api';
import { BASE_URL } from '../services/apiCore';
import { useTheme } from '../context/ThemeContext';

export default function ReportScreen({ route, navigation }) {
  const { theme } = useTheme();
  const { scanId } = route.params;
  const [scan,        setScan]        = useState(null);
  const [loading,     setLoading]     = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [aiLoading,   setAiLoading]   = useState(false);
  const [expandedIdx, setExpandedIdx] = useState(null);

  useEffect(() => { fetchScan(); }, []);

  const fetchScan = async () => {
    try {
      const data = await api.getScan(scanId);
      setScan(data);
    } catch { Alert.alert('Error', 'Failed to load report'); }
    setLoading(false);
  };

  const handleDownloadPDF = async () => {
    setDownloading(true);
    try {
      const downloadSession = await api.getReportDownloadToken(scanId).catch(() => null);
      if (!downloadSession?.token) {
        Alert.alert('Error', 'Could not create secure download link. Please try again.');
        setDownloading(false);
        return;
      }
      await WebBrowser.openBrowserAsync(`${BASE_URL}/reports/${scanId}/pdf?token=${encodeURIComponent(downloadSession.token)}`);
    } catch { Alert.alert('Error', 'Could not open PDF'); }
    setDownloading(false);
  };

  const handleAI = () => navigation.navigate('AIRemediation', { scanId });

  const sevColor = sev => ({
    critical: theme.critical, high: theme.high,
    medium: theme.medium, low: theme.low, info: theme.blue,
  })[sev?.toLowerCase()] || theme.textMuted;

  if (loading) return (
    <View style={{ flex:1, justifyContent:'center', alignItems:'center', backgroundColor:theme.bg }}>
      <ActivityIndicator size="large" color={theme.accent}/>
    </View>
  );

  const sc     = scan?.severity_counts || {};
  const vulns  = scan?.vulnerabilities || [];

  return (
    <ScrollView style={{ backgroundColor:theme.bg }}>
      {/* Header */}
      <View style={{ backgroundColor:theme.header, padding:24, paddingTop:20 }}>
        <Text style={{ color:'#FDFFF5', fontSize:20, fontWeight:'bold', marginBottom:6 }}>Security Report</Text>
        <Text style={{ color:'rgba(253,255,245,0.8)', fontSize:13 }} numberOfLines={2}>
          {scan?.target_url}
        </Text>
        <Text style={{ color:'rgba(253,255,245,0.5)', fontSize:11, marginTop:4 }}>
          {scan?.created_at ? new Date(scan.created_at).toLocaleString() : ''}
        </Text>
      </View>

      {/* Action buttons */}
      <View style={{ flexDirection:'row', padding:12, gap:10 }}>
        <TouchableOpacity
          style={{ flex:1, backgroundColor:theme.success, borderRadius:10, padding:14, alignItems:'center', opacity:downloading?0.6:1 }}
          onPress={handleDownloadPDF} disabled={downloading}>
          {downloading ? <ActivityIndicator color="#fff"/> : <Text style={{ color:'#fff', fontWeight:'bold', fontSize:13 }}>↓ PDF Report</Text>}
        </TouchableOpacity>
        <TouchableOpacity
          style={{ flex:1, backgroundColor:'rgba(139,92,246,0.15)', borderRadius:10, padding:14, alignItems:'center', borderWidth:1, borderColor:'rgba(139,92,246,0.4)' }}
          onPress={handleAI}>
          <Text style={{ color:'#A78BFA', fontWeight:'bold', fontSize:13 }}>🤖 AI Fix</Text>
        </TouchableOpacity>
      </View>

      {/* Risk Score */}
      <View style={{ backgroundColor:theme.card, borderRadius:14, margin:12, marginTop:0, padding:20, alignItems:'center', borderWidth:1, borderColor:theme.border }}>
        <Text style={{ color:theme.textSecondary, fontSize:12, marginBottom:6, letterSpacing:1 }}>TOTAL RISK SCORE</Text>
        <Text style={{ fontSize:48, fontWeight:'bold', color: (scan?.total_risk_score||0)>=7 ? theme.critical : (scan?.total_risk_score||0)>=4 ? theme.high : theme.success }}>
          {scan?.total_risk_score?.toFixed(1) || '0.0'}
        </Text>
        <Text style={{ color:theme.textMuted, fontSize:13 }}>/ 10.0</Text>
      </View>

      {/* Severity counts — from severity_counts field */}
      <View style={{ flexDirection:'row', paddingHorizontal:12, gap:6, marginBottom:14 }}>
        {['critical','high','medium','low','info'].map(sev => (
          <View key={sev} style={{ flex:1, backgroundColor:theme.card, borderRadius:10, padding:8,
            alignItems:'center', borderWidth:1, borderColor:theme.border, borderTopWidth:3, borderTopColor:sevColor(sev) }}>
            <Text style={{ fontSize:18, fontWeight:'bold', color:sevColor(sev) }}>{sc[sev]||0}</Text>
            <Text style={{ fontSize:8, color:theme.textMuted, marginTop:2 }}>{sev.toUpperCase()}</Text>
          </View>
        ))}
      </View>

      {/* Scan meta */}
      <View style={{ backgroundColor:theme.card, borderRadius:14, marginHorizontal:12, marginBottom:14, padding:14, borderWidth:1, borderColor:theme.border }}>
        {[
          ['Pages Crawled',  scan?.pages_crawled ?? '—'],
          ['Requests Made',  scan?.requests_made ?? '—'],
          ['Total Vulns',    scan?.total_vulnerabilities ?? '—'],
          ['Completed At',   scan?.completed_at ? new Date(scan.completed_at).toLocaleString() : '—'],
        ].map(([label, val]) => (
          <View key={label} style={{ flexDirection:'row', justifyContent:'space-between', paddingVertical:6, borderBottomWidth:1, borderBottomColor:theme.border }}>
            <Text style={{ color:theme.textSecondary, fontSize:12 }}>{label}</Text>
            <Text style={{ color:theme.text, fontSize:12, fontWeight:'600' }}>{String(val)}</Text>
          </View>
        ))}
      </View>

      {/* Vulnerability list — from vulnerabilities[] field */}
      <Text style={{ fontSize:12, fontWeight:'bold', color:theme.textSecondary, letterSpacing:2, marginHorizontal:14, marginBottom:8 }}>
        VULNERABILITIES ({vulns.length})
      </Text>

      {vulns.length === 0 ? (
        <View style={{ backgroundColor:theme.lowBg, borderRadius:14, margin:12, padding:30, alignItems:'center', borderWidth:1, borderColor:theme.lowBorder }}>
          <Text style={{ fontSize:18, fontWeight:'bold', color:theme.success }}>✓ No vulnerabilities found!</Text>
          <Text style={{ color:theme.textSecondary, marginTop:6, fontSize:13 }}>Target passed all security checks.</Text>
        </View>
      ) : vulns.map((v, i) => (
        <TouchableOpacity key={i}
          style={{ backgroundColor:theme.card, borderRadius:12, marginHorizontal:12, marginBottom:8,
                   borderWidth:1, borderColor:theme.border, borderLeftWidth:3, borderLeftColor:sevColor(v.severity), overflow:'hidden' }}
          onPress={() => setExpandedIdx(expandedIdx === i ? null : i)}>
          <View style={{ flexDirection:'row', alignItems:'center', padding:14, justifyContent:'space-between' }}>
            <View style={{ flex:1 }}>
              <View style={{ flexDirection:'row', alignItems:'center', gap:8, marginBottom:4 }}>
                <View style={{ backgroundColor:sevColor(v.severity)+'25', borderRadius:5, paddingHorizontal:7, paddingVertical:2, borderWidth:1, borderColor:sevColor(v.severity)+'50' }}>
                  <Text style={{ color:sevColor(v.severity), fontSize:9, fontWeight:'bold', letterSpacing:1 }}>
                    {v.severity?.toUpperCase()||'INFO'}
                  </Text>
                </View>
                <Text style={{ color:theme.text, fontSize:13, fontWeight:'bold', flex:1 }}>
                  {v.vuln_type}
                </Text>
              </View>
              <Text style={{ color:theme.textMuted, fontSize:11 }} numberOfLines={1}>{v.url}</Text>
            </View>
            <Text style={{ color:theme.textMuted, fontSize:12, marginLeft:8 }}>{expandedIdx === i ? '▲':'▼'}</Text>
          </View>

          {expandedIdx === i && (
            <View style={{ paddingHorizontal:14, paddingBottom:14, borderTopWidth:1, borderTopColor:theme.border }}>
              {v.param && v.param !== 'N/A' && (
                <Text style={{ color:theme.textSecondary, fontSize:12, marginTop:8 }}>
                  <Text style={{ fontWeight:'bold', color:theme.textMuted }}>Param: </Text>{v.param}
                </Text>
              )}
              {v.payload && (
                <View style={{ backgroundColor:theme.bg, borderRadius:6, padding:8, marginTop:8 }}>
                  <Text style={{ color:theme.warning, fontSize:11, fontFamily:'monospace' }}>{v.payload}</Text>
                </View>
              )}
              {v.evidence && (
                <Text style={{ color:theme.textSecondary, fontSize:12, marginTop:8, lineHeight:18 }}>
                  <Text style={{ fontWeight:'bold', color:theme.textMuted }}>Evidence: </Text>{v.evidence}
                </Text>
              )}
              {v.cve_id && (
                <Text style={{ color:theme.accent, fontSize:12, marginTop:6 }}>
                  <Text style={{ fontWeight:'bold', color:theme.textMuted }}>CVE: </Text>{v.cve_id}
                </Text>
              )}
              {v.risk_score && (
                <Text style={{ color:theme.high, fontSize:12, marginTop:4 }}>
                  <Text style={{ fontWeight:'bold', color:theme.textMuted }}>Risk Score: </Text>{v.risk_score}/10
                </Text>
              )}
              {v.reproduction_steps?.length > 0 && (
                <View style={{ marginTop:8 }}>
                  <Text style={{ fontSize:10, fontWeight:'bold', color:theme.textMuted, letterSpacing:1, marginBottom:4 }}>REPRODUCTION:</Text>
                  {v.reproduction_steps.map((step, si) => (
                    <Text key={si} style={{ color:theme.textSecondary, fontSize:12, marginBottom:2 }}>{si+1}. {step}</Text>
                  ))}
                </View>
              )}
            </View>
          )}
        </TouchableOpacity>
      ))}

      <View style={{ height:40 }}/>
    </ScrollView>
  );
}