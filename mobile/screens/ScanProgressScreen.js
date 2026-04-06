// PATH: vulnassess-app/screens/ScanProgressScreen.js
import React, { useState, useEffect, useRef } from 'react';
import { View, Text, ScrollView, TouchableOpacity, StyleSheet, ActivityIndicator, Alert, Modal, TextInput } from 'react-native';
import { api } from '../services/api';
import { useTheme } from '../context/ThemeContext';
import { useNotifications } from '../context/NotificationContext';

export default function ScanProgressScreen({ route, navigation }) {
  const { theme } = useTheme();
  const { addNotification } = useNotifications();
  const { scanId } = route.params;
  const [scan,      setScan]      = useState(null);
  const [loading,   setLoading]   = useState(true);
  const [cancelling,setCancelling]= useState(false);
  const [showDel,   setShowDel]   = useState(false);
  const [delPass,   setDelPass]   = useState('');
  const [delErr,    setDelErr]    = useState('');
  const [deleting,  setDeleting]  = useState(false);
  const intervalRef  = useRef(null);
  const notifiedRef  = useRef(false);

  useEffect(() => {
    fetchScan();
    intervalRef.current = setInterval(fetchScan, 3000);
    return () => clearInterval(intervalRef.current);
  }, []);

  const fetchScan = async () => {
    try {
      const data = await api.getScan(scanId);
      setScan(data);
      setLoading(false);
      if (['completed','failed','cancelled'].includes(data.status)) {
        clearInterval(intervalRef.current);
        if (!notifiedRef.current) {
          notifiedRef.current = true;
          if (data.status === 'completed') {
            addNotification('Scan Complete',
              `${data.target_url} — Risk: ${data.total_risk_score?.toFixed(1)||'0.0'}/10`, 'success', scanId);
          } else if (data.status === 'cancelled') {
            addNotification('Scan Cancelled', `${data.target_url} — partial results saved.`, 'info', scanId);
          } else {
            addNotification('Scan Failed', `${data.target_url} — error occurred.`, 'error', scanId);
          }
        }
      }
    } catch { setLoading(false); }
  };

  const handleCancel = () => {
    Alert.alert('Stop Scan', `Stop scanning "${scan?.target_url}"? Partial results will be saved.`,
      [{ text:'Keep Running', style:'cancel' },
       { text:'Stop Scan', style:'destructive', onPress: async () => {
           setCancelling(true);
           try { await api.cancelScan(scanId); await fetchScan(); } catch {}
           setCancelling(false);
         }
       }]
    );
  };

  const handleDelete = async () => {
    setDelErr('');
    if (!delPass) { setDelErr('Enter your password'); return; }
    setDeleting(true);
    const res = await api.deleteScanVerified(scanId, delPass).catch(() => null);
    setDeleting(false);
    if (res?.message || res?.success) {
      setShowDel(false); setDelPass('');
      navigation.replace('Dashboard');
    } else {
      setDelErr(res?.detail || 'Wrong password');
    }
  };

  const sevColor = sev => ({
    critical:theme.critical, high:theme.high,
    medium:theme.medium, low:theme.low, info:theme.blue,
  })[sev?.toLowerCase()] || theme.textMuted;

  const statusColor = st => ({
    completed:theme.success, running:theme.medium,
    failed:theme.danger, cancelled:theme.warning,
  })[st] || theme.textMuted;

  const s = StyleSheet.create({
    container:  { flex:1, backgroundColor:theme.bg },
    center:     { flex:1, justifyContent:'center', alignItems:'center', backgroundColor:theme.bg },
    header:     { backgroundColor:theme.header, padding:20, paddingTop:20 },
    headerUrl:  { color:'#FDFFF5', fontSize:15, fontWeight:'bold', marginBottom:4 },
    headerMeta: { color:'rgba(253,255,245,0.6)', fontSize:11 },
    btnRow:     { flexDirection:'row', padding:12, gap:10 },
    actionBtn:  { flex:1, borderRadius:10, padding:12, alignItems:'center', borderWidth:1 },
    actionText: { fontWeight:'bold', fontSize:12, letterSpacing:0.5 },
    card:       { backgroundColor:theme.card, borderRadius:14, margin:12, marginBottom:0, padding:16, borderWidth:1, borderColor:theme.border },
    sTitle:     { fontSize:10, fontWeight:'bold', color:theme.textSecondary, letterSpacing:2, marginBottom:12 },
    progressBar:{ height:6, backgroundColor:theme.border, borderRadius:3, overflow:'hidden', marginBottom:8 },
    progressFill:{ height:'100%', borderRadius:3, backgroundColor:theme.accent },
    stepText:   { color:theme.textSecondary, fontSize:12 },
    pctText:    { color:theme.accent, fontSize:12, fontWeight:'bold' },
    sevRow:     { flexDirection:'row', gap:8, flexWrap:'wrap', marginBottom:8 },
    sevCard:    { flex:1, borderRadius:10, padding:10, alignItems:'center', borderWidth:1, minWidth:60, borderTopWidth:3 },
    sevNum:     { fontSize:20, fontWeight:'bold', marginBottom:2 },
    sevLabel:   { fontSize:8, letterSpacing:1 },
    vulnItem:   { borderRadius:10, marginBottom:8, borderWidth:1, borderLeftWidth:3, overflow:'hidden' },
    vulnHeader: { flexDirection:'row', alignItems:'center', padding:12, justifyContent:'space-between' },
    vulnType:   { fontSize:13, fontWeight:'bold', flex:1, color:theme.text },
    badge:      { paddingHorizontal:7, paddingVertical:3, borderRadius:5 },
    badgeText:  { fontSize:9, fontWeight:'bold', letterSpacing:0.5 },
    vulnDetail: { paddingHorizontal:12, paddingBottom:12, borderTopWidth:1, borderTopColor:theme.border },
    detailRow:  { marginTop:6 },
    detailLabel:{ fontSize:10, fontWeight:'bold', color:theme.textMuted, letterSpacing:1 },
    detailVal:  { color:theme.textSecondary, fontSize:12, marginTop:2 },
    codeBox:    { backgroundColor:theme.bg, borderRadius:6, padding:8, marginTop:4 },
    codeText:   { color:theme.warning, fontSize:11, fontFamily:'monospace' },
    modalOverlay:{ flex:1, backgroundColor:'rgba(0,0,0,0.6)', justifyContent:'center', alignItems:'center', padding:24 },
    modal:      { backgroundColor:theme.card, borderRadius:16, padding:24, width:'100%', maxWidth:380,
                  borderWidth:1, borderColor:theme.dangerBorder },
    modalTitle: { fontSize:16, fontWeight:'bold', color:theme.danger, marginBottom:8 },
    modalDesc:  { fontSize:13, color:theme.textSecondary, marginBottom:14, lineHeight:20 },
    modalInput: { borderWidth:1, borderColor:theme.inputBorder, borderRadius:8, padding:12,
                  fontSize:14, color:theme.text, backgroundColor:theme.input, marginBottom:12 },
    modalErr:   { backgroundColor:theme.dangerBg, borderRadius:8, padding:10, marginBottom:12, borderWidth:1, borderColor:theme.dangerBorder },
    modalBtns:  { flexDirection:'row', gap:10 },
    modalBtn:   { flex:1, padding:13, borderRadius:10, alignItems:'center' },
    modalBtnText:{ color:'#fff', fontWeight:'bold', fontSize:14 },
  });

  const [expandedIdx, setExpandedIdx] = useState(null);

  if (loading) return <View style={s.center}><ActivityIndicator size="large" color={theme.accent}/></View>;

  const sc    = scan?.severity_counts || {};
  const vulns = scan?.vulnerabilities || [];
  const isRunning = ['running','pending'].includes(scan?.status);

  return (
    <ScrollView style={s.container}>
      {/* Header */}
      <View style={s.header}>
        <Text style={s.headerUrl} numberOfLines={2}>{scan?.target_url || scan?.target}</Text>
        <Text style={[s.headerMeta, { color: statusColor(scan?.status) }]}>
          ● {scan?.status?.toUpperCase()} {scan?.created_at ? '· ' + new Date(scan.created_at).toLocaleString() : ''}
        </Text>
        {scan?.pages_crawled > 0 && (
          <Text style={s.headerMeta}>{scan.pages_crawled} pages · {scan.requests_made} requests</Text>
        )}
      </View>

      {/* Buttons */}
      <View style={s.btnRow}>
        {isRunning && (
          <TouchableOpacity style={[s.actionBtn, { backgroundColor:theme.dangerBg, borderColor:theme.dangerBorder }]}
            onPress={handleCancel} disabled={cancelling}>
            {cancelling ? <ActivityIndicator color={theme.danger} size="small"/>
              : <Text style={[s.actionText, { color:theme.danger }]}>⏹ STOP SCAN</Text>}
          </TouchableOpacity>
        )}
        {scan?.status === 'completed' && (
          <TouchableOpacity style={[s.actionBtn, { backgroundColor:theme.successBg, borderColor:theme.successBorder }]}
            onPress={() => navigation.navigate('Report', { scanId })}>
            <Text style={[s.actionText, { color:theme.success }]}>↗ FULL REPORT</Text>
          </TouchableOpacity>
        )}
        {scan?.status === 'completed' && (
          <TouchableOpacity style={[s.actionBtn, { backgroundColor:'rgba(139,92,246,0.12)', borderColor:'rgba(139,92,246,0.35)' }]}
            onPress={() => navigation.navigate('AIRemediation', { scanId })}>
            <Text style={[s.actionText, { color:'#A78BFA' }]}>🤖 AI FIX</Text>
          </TouchableOpacity>
        )}
        <TouchableOpacity style={[s.actionBtn, { backgroundColor:theme.dangerBg, borderColor:theme.dangerBorder }]}
          onPress={() => { setDelErr(''); setDelPass(''); setShowDel(true); }}>
          <Text style={[s.actionText, { color:theme.danger }]}>✕ DELETE</Text>
        </TouchableOpacity>
      </View>

      {/* Progress */}
      {isRunning && (
        <View style={s.card}>
          <Text style={s.sTitle}>SCAN PROGRESS</Text>
          <View style={{ flexDirection:'row', justifyContent:'space-between', marginBottom:6 }}>
            <Text style={s.stepText}>{scan?.current_step || 'Initializing…'}</Text>
            <Text style={s.pctText}>{scan?.progress || 0}%</Text>
          </View>
          <View style={s.progressBar}>
            <View style={[s.progressFill, { width:`${scan?.progress||0}%` }]}/>
          </View>
        </View>
      )}

      {/* Severity summary */}
      {scan?.status === 'completed' && (
        <View style={s.card}>
          <Text style={s.sTitle}>SEVERITY BREAKDOWN</Text>
          <View style={s.sevRow}>
            {['critical','high','medium','low','info'].map(sv => (
              <View key={sv} style={[s.sevCard, { backgroundColor:theme[sv+'Bg']||theme.card, borderColor:theme[sv+'Border']||theme.border, borderTopColor:sevColor(sv) }]}>
                <Text style={[s.sevNum, { color:sevColor(sv) }]}>{sc[sv]||0}</Text>
                <Text style={[s.sevLabel, { color:sevColor(sv) }]}>{sv.toUpperCase()}</Text>
              </View>
            ))}
          </View>
          <View style={{ flexDirection:'row', justifyContent:'space-between', marginTop:4 }}>
            <Text style={{ color:theme.textSecondary, fontSize:12 }}>Risk Score</Text>
            <Text style={{ color:theme.high, fontWeight:'bold', fontSize:14 }}>
              {scan?.total_risk_score?.toFixed(1)||'0.0'} / 10
            </Text>
          </View>
        </View>
      )}

      {/* Vulnerabilities */}
      {vulns.length > 0 && (
        <View style={{ margin:12, marginTop:0 }}>
          <Text style={[s.sTitle, { marginTop:12, marginBottom:8 }]}>VULNERABILITIES ({vulns.length})</Text>
          {vulns.map((v, i) => (
            <TouchableOpacity key={i}
              style={[s.vulnItem, { backgroundColor:theme.card, borderColor:theme.border, borderLeftColor:sevColor(v.severity) }]}
              onPress={() => setExpandedIdx(expandedIdx===i ? null : i)}>
              <View style={s.vulnHeader}>
                <View style={[s.badge, { backgroundColor:sevColor(v.severity)+'20', borderWidth:1, borderColor:sevColor(v.severity)+'40' }]}>
                  <Text style={[s.badgeText, { color:sevColor(v.severity) }]}>{v.severity?.toUpperCase()||'INFO'}</Text>
                </View>
                <Text style={[s.vulnType, { marginLeft:8 }]} numberOfLines={1}>{v.vuln_type}</Text>
                <Text style={{ color:theme.textMuted, fontSize:12 }}>{expandedIdx===i ? '▲':'▼'}</Text>
              </View>
              {expandedIdx === i && (
                <View style={s.vulnDetail}>
                  {v.url && <View style={s.detailRow}><Text style={s.detailLabel}>URL</Text><Text style={s.detailVal} numberOfLines={2}>{v.url}</Text></View>}
                  {v.param && v.param!=='N/A' && <View style={s.detailRow}><Text style={s.detailLabel}>PARAM</Text><Text style={s.detailVal}>{v.param}</Text></View>}
                  {v.payload && <View style={s.detailRow}><Text style={s.detailLabel}>PAYLOAD</Text><View style={s.codeBox}><Text style={s.codeText}>{v.payload}</Text></View></View>}
                  {v.evidence && <View style={s.detailRow}><Text style={s.detailLabel}>EVIDENCE</Text><Text style={s.detailVal}>{v.evidence}</Text></View>}
                  {v.cve_id && <View style={s.detailRow}><Text style={s.detailLabel}>CVE</Text><Text style={[s.detailVal, { color:theme.accent }]}>{v.cve_id}</Text></View>}
                  {v.risk_score && <View style={s.detailRow}><Text style={s.detailLabel}>RISK SCORE</Text><Text style={[s.detailVal, { color:theme.high }]}>{v.risk_score}/10</Text></View>}
                </View>
              )}
            </TouchableOpacity>
          ))}
        </View>
      )}

      {scan?.status === 'completed' && vulns.length === 0 && (
        <View style={{ backgroundColor:theme.lowBg, borderRadius:14, margin:12, padding:30, alignItems:'center', borderWidth:1, borderColor:theme.lowBorder }}>
          <Text style={{ fontSize:18, fontWeight:'bold', color:theme.success }}>✓ No vulnerabilities found!</Text>
          <Text style={{ color:theme.textSecondary, marginTop:6, textAlign:'center' }}>Target passed all security checks.</Text>
        </View>
      )}

      <View style={{ height:40 }}/>

      {/* Delete modal */}
      <Modal visible={showDel} transparent animationType="fade">
        <View style={s.modalOverlay}>
          <View style={s.modal}>
            <Text style={s.modalTitle}>CONFIRM DELETE</Text>
            <Text style={s.modalDesc}>Enter your password to permanently delete this scan.</Text>
            {!!delErr && <View style={s.modalErr}><Text style={{ color:theme.danger, fontSize:12 }}>⚠ {delErr}</Text></View>}
            <TextInput style={s.modalInput} placeholder="Your password" placeholderTextColor={theme.textMuted}
              value={delPass} onChangeText={t=>{setDelPass(t);setDelErr('');}} secureTextEntry/>
            <View style={s.modalBtns}>
              <TouchableOpacity style={[s.modalBtn, { backgroundColor:theme.bg, borderWidth:1, borderColor:theme.border }]}
                onPress={() => { setShowDel(false); setDelPass(''); setDelErr(''); }}>
                <Text style={[s.modalBtnText, { color:theme.text }]}>CANCEL</Text>
              </TouchableOpacity>
              <TouchableOpacity style={[s.modalBtn, { backgroundColor:theme.danger }, deleting&&{opacity:0.5}]}
                onPress={handleDelete} disabled={deleting}>
                {deleting ? <ActivityIndicator color="#fff" size="small"/> : <Text style={s.modalBtnText}>DELETE</Text>}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </ScrollView>
  );
}