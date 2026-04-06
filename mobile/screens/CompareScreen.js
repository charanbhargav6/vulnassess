// PATH: vulnassess-app/screens/CompareScreen.js
import React, { useState, useEffect } from 'react';
import { View, Text, TouchableOpacity, StyleSheet, ScrollView, ActivityIndicator, Alert } from 'react-native';
import { api } from '../services/api';
import { useTheme } from '../context/ThemeContext';

export default function CompareScreen({ route, navigation }) {
  const { theme } = useTheme();
  const { scan1Id, scan2Id } = route.params;
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [tab,     setTab]     = useState('overview');

  useEffect(() => { load(); }, []);

  const load = async () => {
    try {
      const res = await api.compareScans(scan1Id, scan2Id);
      if (res.detail) { Alert.alert('Error', res.detail); navigation.goBack(); return; }
      setData(res);
    } catch { Alert.alert('Error', 'Failed to load comparison'); navigation.goBack(); }
    setLoading(false);
  };

  const sevColor = sev => ({
    critical:theme.critical, high:theme.high,
    medium:theme.medium, low:theme.low, info:theme.blue,
    Critical:theme.critical, High:theme.high,
    Medium:theme.medium, Low:theme.low, Info:theme.blue,
  })[sev] || theme.textMuted;

  if (loading) return (
    <View style={{ flex:1, justifyContent:'center', alignItems:'center', backgroundColor:theme.bg }}>
      <ActivityIndicator size="large" color={theme.accent}/>
      <Text style={{ color:theme.textSecondary, marginTop:12 }}>Comparing scans…</Text>
    </View>
  );

  const { scan1, scan2, summary } = data;
  const scoreDiff = summary.score_diff;
  const improved  = summary.improved;

  const TABS = [
    { key:'overview', label:'Overview'                          },
    { key:'findings', label:'All'                               },
    { key:'fixed',    label:`Fixed (${summary.fixed_findings_count})`  },
    { key:'new',      label:`New (${summary.new_findings_count})`      },
  ];

  const s = StyleSheet.create({
    container:  { flex:1, backgroundColor:theme.bg },
    tabRow:     { flexDirection:'row', backgroundColor:theme.card, borderBottomWidth:1, borderBottomColor:theme.border },
    tab:        { flex:1, paddingVertical:12, alignItems:'center' },
    tabText:    { fontSize:12, fontWeight:'500' },
    card:       { backgroundColor:theme.card, borderRadius:14, marginHorizontal:12, marginTop:14,
                  padding:16, borderWidth:1, borderColor:theme.border },
    cardTitle:  { fontSize:13, fontWeight:'bold', color:theme.text, letterSpacing:1, marginBottom:12 },
    cardSub:    { fontSize:12, color:theme.textSecondary, marginBottom:12 },
    scoreRow:   { flexDirection:'row', alignItems:'center', justifyContent:'space-between', marginTop:4 },
    scoreBox:   { flex:1, alignItems:'center' },
    scoreLabel: { fontSize:11, fontWeight:'bold', color:theme.textSecondary, letterSpacing:1, marginBottom:2 },
    scoreDate:  { fontSize:10, color:theme.textMuted, marginBottom:8 },
    scoreBig:   { fontSize:36, fontWeight:'bold' },
    scoreSev:   { fontSize:11, fontWeight:'bold', marginTop:4 },
    diffBox:    { alignItems:'center', paddingHorizontal:8 },
    diffArrow:  { fontSize:20, color:theme.textMuted },
    diffVal:    { fontSize:16, fontWeight:'bold', marginTop:4 },
    diffLabel:  { fontSize:10, color:theme.textMuted, marginTop:2 },
    summaryRow: { flexDirection:'row', marginHorizontal:12, marginTop:12, gap:8 },
    sumCard:    { flex:1, borderRadius:12, padding:14, alignItems:'center', borderWidth:1 },
    sumNum:     { fontSize:26, fontWeight:'bold' },
    sumLabel:   { fontSize:11, marginTop:2, color:theme.textSecondary },
    sevRow:     { flexDirection:'row', alignItems:'center', paddingVertical:8,
                  borderBottomWidth:1, borderBottomColor:theme.border },
    sevName:    { width:70, fontSize:13, fontWeight:'bold' },
    sevCount:   { width:28, fontSize:15, fontWeight:'bold', textAlign:'center', color:theme.text },
    sevArrow:   { width:24, textAlign:'center', color:theme.textMuted },
    sevDiff:    { flex:1, fontSize:13, fontWeight:'bold', textAlign:'right' },
    detailRow:  { flexDirection:'row', paddingVertical:6, borderBottomWidth:1, borderBottomColor:theme.border },
    detailLabel:{ width:110, fontSize:12, fontWeight:'bold', color:theme.textSecondary },
    detailVal:  { flex:1, fontSize:12, color:theme.text },
    findRow:    { flexDirection:'row', justifyContent:'space-between', alignItems:'center',
                  paddingVertical:10, borderBottomWidth:1, borderBottomColor:theme.border },
    findLeft:   { flex:1, marginRight:8 },
    findName:   { fontSize:13, fontWeight:'bold', color:theme.text },
    findMod:    { fontSize:11, color:theme.textSecondary, marginTop:2 },
    sevBadge:   { paddingHorizontal:8, paddingVertical:3, borderRadius:10 },
    sevBadgeText:{ color:'#fff', fontSize:10, fontWeight:'bold' },
    emptyText:  { textAlign:'center', fontSize:14, color:theme.textMuted, paddingVertical:20 },
  });

  const renderFindingRow = (f, i, bg) => (
    <View key={i} style={[s.findRow, bg && { backgroundColor:bg, borderRadius:6, paddingHorizontal:6 }]}>
      <View style={s.findLeft}>
        <Text style={s.findName}>{f.name}</Text>
        <Text style={s.findMod}>{f.module}</Text>
      </View>
      <View style={[s.sevBadge, { backgroundColor: sevColor(f.severity) }]}>
        <Text style={s.sevBadgeText}>{f.severity?.toUpperCase()}</Text>
      </View>
    </View>
  );

  return (
    <View style={s.container}>
      {/* Tabs */}
      <View style={s.tabRow}>
        {TABS.map(t => (
          <TouchableOpacity key={t.key} style={[s.tab, tab===t.key && { borderBottomWidth:3, borderBottomColor:theme.accent }]}
            onPress={() => setTab(t.key)}>
            <Text style={[s.tabText, { color: tab===t.key ? theme.accent : theme.textSecondary },
              tab===t.key && { fontWeight:'bold' }]}>
              {t.label}
            </Text>
          </TouchableOpacity>
        ))}
      </View>

      <ScrollView>
        {/* OVERVIEW */}
        {tab==='overview' && (
          <>
            <View style={s.card}>
              <Text style={s.cardTitle}>RISK SCORE COMPARISON</Text>
              <View style={s.scoreRow}>
                {[scan1, scan2].map((sc, i) => (
                  <View key={i} style={s.scoreBox}>
                    <Text style={s.scoreLabel}>SCAN {i+1}</Text>
                    <Text style={s.scoreDate}>{sc.created_at ? new Date(sc.created_at).toLocaleDateString() : ''}</Text>
                    <Text style={[s.scoreBig, { color: sc.severity_color || sevColor(sc.severity_label?.toLowerCase()) }]}>
                      {sc.total_risk_score?.toFixed(1)}
                    </Text>
                    <Text style={[s.scoreSev, { color: sc.severity_color || theme.textMuted }]}>{sc.severity_label}</Text>
                  </View>
                ))}
                <View style={s.diffBox}>
                  <Text style={s.diffArrow}>{improved ? '↓' : scoreDiff===0 ? '=' : '↑'}</Text>
                  <Text style={[s.diffVal, { color: improved ? theme.success : scoreDiff===0 ? theme.textMuted : theme.danger }]}>
                    {scoreDiff===0 ? 'Same' : `${improved?'':'+'}${scoreDiff?.toFixed(1)}`}
                  </Text>
                  <Text style={s.diffLabel}>{improved ? 'Improved' : scoreDiff===0 ? 'No change' : 'Worsened'}</Text>
                </View>
              </View>
            </View>

            <View style={s.summaryRow}>
              {[
                { num:summary.fixed_findings_count, label:'Fixed',     bg:theme.successBg, border:theme.successBorder, color:theme.success },
                { num:summary.new_findings_count,   label:'New Issues', bg:theme.dangerBg,  border:theme.dangerBorder,  color:theme.danger  },
                { num:scan2.total_findings,          label:'Total Now',  bg:theme.mediumBg,  border:theme.mediumBorder,  color:theme.medium  },
              ].map((b, i) => (
                <View key={i} style={[s.sumCard, { backgroundColor:b.bg, borderColor:b.border }]}>
                  <Text style={[s.sumNum, { color:b.color }]}>{b.num}</Text>
                  <Text style={s.sumLabel}>{b.label}</Text>
                </View>
              ))}
            </View>

            <View style={s.card}>
              <Text style={s.cardTitle}>SEVERITY BREAKDOWN</Text>
              {['Critical','High','Medium','Low'].map(sev => {
                const c1   = scan1.severity_counts?.[sev] || 0;
                const c2   = scan2.severity_counts?.[sev] || 0;
                const diff = c2 - c1;
                return (
                  <View key={sev} style={s.sevRow}>
                    <Text style={[s.sevName, { color:sevColor(sev) }]}>{sev}</Text>
                    <Text style={s.sevCount}>{c1}</Text>
                    <Text style={s.sevArrow}>→</Text>
                    <Text style={s.sevCount}>{c2}</Text>
                    <Text style={[s.sevDiff, { color: diff<0 ? theme.success : diff>0 ? theme.danger : theme.textMuted }]}>
                      {diff>0 ? `+${diff}` : diff===0 ? '—' : diff}
                    </Text>
                  </View>
                );
              })}
            </View>

            <View style={s.card}>
              <Text style={s.cardTitle}>SCAN DETAILS</Text>
              {[['Scan 1 Target', scan1.target_url], ['Scan 2 Target', scan2.target_url],
                ['Scan 1 Date', scan1.created_at ? new Date(scan1.created_at).toLocaleString() : '—'],
                ['Scan 2 Date', scan2.created_at ? new Date(scan2.created_at).toLocaleString() : '—'],
              ].map(([lbl, val], i) => (
                <View key={i} style={s.detailRow}>
                  <Text style={s.detailLabel}>{lbl}</Text>
                  <Text style={s.detailVal} numberOfLines={1}>{val}</Text>
                </View>
              ))}
            </View>
          </>
        )}

        {/* ALL FINDINGS */}
        {tab==='findings' && (
          <View style={s.card}>
            <Text style={s.cardTitle}>ALL FINDINGS — SCAN 2 ({scan2.total_findings})</Text>
            {scan2.findings?.length===0
              ? <Text style={s.emptyText}>No findings in scan 2</Text>
              : scan2.findings?.map((f, i) => renderFindingRow(f, i))}
          </View>
        )}

        {/* FIXED */}
        {tab==='fixed' && (
          <View style={s.card}>
            <Text style={s.cardTitle}>FIXED ISSUES ({summary.fixed_findings_count})</Text>
            <Text style={s.cardSub}>Were in Scan 1 but not in Scan 2</Text>
            {summary.fixed_findings?.length===0
              ? <Text style={s.emptyText}>No issues were fixed</Text>
              : summary.fixed_findings?.map((f, i) => renderFindingRow(f, i, theme.successBg))}
          </View>
        )}

        {/* NEW */}
        {tab==='new' && (
          <View style={s.card}>
            <Text style={s.cardTitle}>NEW ISSUES ({summary.new_findings_count})</Text>
            <Text style={s.cardSub}>Appeared in Scan 2 but not in Scan 1</Text>
            {summary.new_findings?.length===0
              ? <Text style={s.emptyText}>No new issues found</Text>
              : summary.new_findings?.map((f, i) => renderFindingRow(f, i, theme.dangerBg))}
          </View>
        )}

        <View style={{ height:40 }}/>
      </ScrollView>
    </View>
  );
}