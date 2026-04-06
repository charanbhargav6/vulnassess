// PATH: vulnassess-app/screens/ScheduleScreen.js
import React, { useState, useEffect } from 'react';
import { View, Text, ScrollView, TouchableOpacity, StyleSheet, Alert, ActivityIndicator, TextInput, Modal } from 'react-native';
import { api } from '../services/api';
import { useTheme } from '../context/ThemeContext';

const TIMEFRAMES = [
  { key:'1hour',   label:'Every Hour',     icon:'1H'  },
  { key:'6hours',  label:'Every 6 Hours',  icon:'6H'  },
  { key:'12hours', label:'Every 12 Hours', icon:'12H' },
  { key:'daily',   label:'Daily',          icon:'1D'  },
  { key:'weekly',  label:'Weekly',         icon:'7D'  },
  { key:'monthly', label:'Monthly',        icon:'30D' },
];

export default function ScheduleScreen({ navigation }) {
  const { theme } = useTheme();
  const [schedules, setSchedules] = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [targetUrl, setTargetUrl] = useState('');
  const [timeframe, setTimeframe] = useState('daily');
  const [creating,  setCreating]  = useState(false);
  const [formErr,   setFormErr]   = useState('');

  const getId = item => item._id || item.id;

  useEffect(() => {
    load();
    const unsub = navigation.addListener('focus', load);
    return unsub;
  }, [navigation]);

  const load = async () => {
    setLoading(true);
    try { const d = await api.getSchedules(); if (Array.isArray(d)) setSchedules(d); }
    catch { Alert.alert('Error', 'Failed to load schedules'); }
    setLoading(false);
  };

  const handleCreate = async () => {
    setFormErr('');
    if (!targetUrl) { setFormErr('Target URL is required'); return; }
    let url = targetUrl.trim();
    if (!url.startsWith('http')) url = 'https://' + url;
    setCreating(true);
    try {
      const data = await api.createSchedule(url, timeframe, '', '');
      if (data.id || data._id) {
        setShowModal(false); setTargetUrl(''); setTimeframe('daily');
        await load();
      } else { setFormErr(data.detail || 'Failed to create schedule'); }
    } catch { setFormErr('Cannot connect to server'); }
    setCreating(false);
  };

  const handleToggle = async (sched) => {
    try {
      await api.toggleSchedule(getId(sched), !sched.is_active);
      setSchedules(prev => prev.map(s => getId(s)===getId(sched) ? {...s, is_active:!s.is_active} : s));
    } catch { Alert.alert('Error', 'Failed to update schedule'); }
  };

  const handleDelete = sched => {
    Alert.alert('Delete Schedule', `Delete schedule for "${sched.target_url}"?`,
      [{ text:'Cancel', style:'cancel' },
       { text:'Delete', style:'destructive', onPress: async () => {
           try { await api.deleteSchedule(getId(sched)); setSchedules(prev => prev.filter(s => getId(s)!==getId(sched))); }
           catch { Alert.alert('Error', 'Failed to delete'); }
         }
       }]
    );
  };

  const formatNext = nextRun => {
    if (!nextRun) return 'Not scheduled';
    const diff = new Date(nextRun) - new Date();
    if (diff < 0) return 'Running soon';
    const mins = Math.floor(diff/60000);
    if (mins < 60) return `In ${mins}m`;
    const hrs = Math.floor(mins/60);
    if (hrs < 24) return `In ${hrs}h`;
    return `In ${Math.floor(hrs/24)}d`;
  };

  const s = StyleSheet.create({
    container:   { flex:1, backgroundColor:theme.bg },
    center:      { flex:1, justifyContent:'center', alignItems:'center', backgroundColor:theme.bg },
    infoBox:     { margin:14, borderRadius:12, padding:14, borderWidth:1, borderLeftWidth:4, backgroundColor:theme.mediumBg, borderColor:theme.mediumBorder },
    infoTitle:   { fontWeight:'bold', fontSize:14, color:theme.medium, marginBottom:4 },
    infoText:    { fontSize:13, color:theme.text, lineHeight:20 },
    card:        { backgroundColor:theme.card, borderRadius:14, marginHorizontal:12, marginBottom:10, padding:14, borderWidth:1 },
    cardActive:  { borderColor:theme.accent },
    cardInactive:{ borderColor:theme.border, opacity:0.7 },
    cardTop:     { flexDirection:'row', alignItems:'center', marginBottom:8 },
    tfBadge:     { borderRadius:6, paddingHorizontal:8, paddingVertical:4, marginRight:10, backgroundColor:theme.accentMuted },
    tfBadgeText: { fontWeight:'bold', fontSize:11, color:theme.accent },
    cardUrl:     { flex:1, fontSize:13, fontWeight:'bold', color:theme.text },
    dot:         { width:10, height:10, borderRadius:5, marginLeft:8 },
    cardStats:   { flexDirection:'row', justifyContent:'space-between', marginBottom:6 },
    cardStat:    { fontSize:11, color:theme.textSecondary },
    cardBtns:    { flexDirection:'row', gap:8, marginTop:4 },
    actionBtn:   { paddingHorizontal:14, paddingVertical:7, borderRadius:8, borderWidth:1 },
    empty:       { alignItems:'center', padding:60 },
    emptyText:   { fontSize:17, fontWeight:'bold', color:theme.textSecondary },
    emptySubtext:{ fontSize:13, color:theme.textMuted, textAlign:'center', marginTop:6 },
    fab:         { position:'absolute', bottom:20, left:14, right:14, backgroundColor:theme.accent,
                   padding:16, borderRadius:12, alignItems:'center' },
    fabText:     { color:theme.card, fontSize:15, fontWeight:'bold', letterSpacing:1 },
    overlay:     { flex:1, backgroundColor:'rgba(0,0,0,0.6)', justifyContent:'flex-end' },
    modal:       { backgroundColor:theme.card, borderTopLeftRadius:20, borderTopRightRadius:20,
                   padding:24, maxHeight:'90%', borderWidth:1, borderColor:theme.border },
    modalTitle:  { fontSize:17, fontWeight:'bold', color:theme.text, letterSpacing:1, marginBottom:14 },
    label:       { fontSize:10, fontWeight:'bold', color:theme.textSecondary, letterSpacing:2, marginBottom:6, marginTop:8 },
    input:       { backgroundColor:theme.input, borderWidth:1, borderColor:theme.inputBorder,
                   borderRadius:8, padding:12, fontSize:14, color:theme.text, marginBottom:4 },
    tfGrid:      { flexDirection:'row', flexWrap:'wrap', gap:8, marginBottom:8 },
    tfBtn:       { width:'31%', borderRadius:10, padding:10, alignItems:'center', borderWidth:1 },
    tfBtnIcon:   { fontSize:15, fontWeight:'bold', marginBottom:2 },
    tfBtnLabel:  { fontSize:10, textAlign:'center' },
    errBox:      { backgroundColor:theme.dangerBg, borderWidth:1, borderColor:theme.dangerBorder,
                   borderRadius:8, padding:10, marginBottom:10 },
    errText:     { color:theme.danger, fontSize:12 },
    modalBtns:   { flexDirection:'row', gap:10, marginTop:10 },
    modalBtn:    { flex:1, padding:13, borderRadius:10, alignItems:'center' },
    modalBtnText:{ fontWeight:'bold', fontSize:14 },
  });

  if (loading) return <View style={s.center}><ActivityIndicator size="large" color={theme.accent}/></View>;

  return (
    <View style={s.container}>
      <ScrollView contentContainerStyle={{ paddingBottom:100 }}>
        <View style={s.infoBox}>
          <Text style={s.infoTitle}>⏱ Automatic Scanning</Text>
          <Text style={s.infoText}>Schedule scans to run automatically. Results appear in your scan list when complete.</Text>
        </View>

        {schedules.length === 0 ? (
          <View style={s.empty}>
            <Text style={s.emptyText}>No schedules yet</Text>
            <Text style={s.emptySubtext}>Tap the button below to create your first automated scan</Text>
          </View>
        ) : schedules.map(sched => (
          <View key={getId(sched)} style={[s.card, sched.is_active ? s.cardActive : s.cardInactive]}>
            <View style={s.cardTop}>
              <View style={s.tfBadge}>
                <Text style={s.tfBadgeText}>{TIMEFRAMES.find(t=>t.key===sched.timeframe)?.icon || sched.timeframe}</Text>
              </View>
              <Text style={s.cardUrl} numberOfLines={1}>{sched.target_url}</Text>
              <View style={[s.dot, { backgroundColor: sched.is_active ? theme.success : theme.muted }]}/>
            </View>
            <View style={s.cardStats}>
              <Text style={s.cardStat}>{sched.timeframe_label || sched.timeframe}</Text>
              <Text style={s.cardStat}>Runs: {sched.run_count||0}</Text>
              <Text style={[s.cardStat, { color: sched.is_active ? theme.accent : theme.muted }]}>
                Next: {sched.is_active ? formatNext(sched.next_run) : 'Paused'}
              </Text>
            </View>
            {sched.last_run && <Text style={{ fontSize:11, color:theme.textMuted, marginBottom:6 }}>Last: {new Date(sched.last_run).toLocaleString()}</Text>}
            <View style={s.cardBtns}>
              <TouchableOpacity style={[s.actionBtn, { backgroundColor: sched.is_active ? theme.warningBg : theme.successBg,
                borderColor: sched.is_active ? theme.high : theme.lowBorder }]}
                onPress={() => handleToggle(sched)}>
                <Text style={{ color: sched.is_active ? theme.high : theme.success, fontWeight:'bold', fontSize:12 }}>
                  {sched.is_active ? 'PAUSE' : 'RESUME'}
                </Text>
              </TouchableOpacity>
              <TouchableOpacity style={[s.actionBtn, { backgroundColor:theme.dangerBg, borderColor:theme.dangerBorder }]}
                onPress={() => handleDelete(sched)}>
                <Text style={{ color:theme.danger, fontWeight:'bold', fontSize:12 }}>DELETE</Text>
              </TouchableOpacity>
            </View>
          </View>
        ))}
      </ScrollView>

      <TouchableOpacity style={s.fab} onPress={() => { setFormErr(''); setTargetUrl(''); setTimeframe('daily'); setShowModal(true); }}>
        <Text style={s.fabText}>⊕ NEW SCHEDULE</Text>
      </TouchableOpacity>

      <Modal visible={showModal} transparent animationType="slide">
        <View style={s.overlay}>
          <View style={s.modal}>
            <Text style={s.modalTitle}>NEW SCHEDULED SCAN</Text>

            {!!formErr && <View style={s.errBox}><Text style={s.errText}>⚠ {formErr}</Text></View>}

            <Text style={s.label}>TARGET URL</Text>
            <TextInput style={s.input} placeholder="https://example.com" placeholderTextColor={theme.textMuted}
              value={targetUrl} onChangeText={t=>{setTargetUrl(t);setFormErr('');}} autoCapitalize="none"/>

            <Text style={s.label}>SCAN INTERVAL</Text>
            <View style={s.tfGrid}>
              {TIMEFRAMES.map(tf => (
                <TouchableOpacity key={tf.key} style={[s.tfBtn,
                  { backgroundColor: timeframe===tf.key ? theme.accent : theme.input,
                    borderColor: timeframe===tf.key ? theme.accent : theme.border }]}
                  onPress={() => setTimeframe(tf.key)}>
                  <Text style={[s.tfBtnIcon, { color: timeframe===tf.key ? theme.card : theme.text }]}>{tf.icon}</Text>
                  <Text style={[s.tfBtnLabel, { color: timeframe===tf.key ? theme.card : theme.textSecondary }]}>{tf.label}</Text>
                </TouchableOpacity>
              ))}
            </View>

            <View style={s.modalBtns}>
              <TouchableOpacity style={[s.modalBtn, { backgroundColor:theme.bg, borderWidth:1, borderColor:theme.border }]}
                onPress={() => setShowModal(false)}>
                <Text style={[s.modalBtnText, { color:theme.text }]}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity style={[s.modalBtn, { backgroundColor:theme.accent }, creating&&{opacity:0.5}]}
                onPress={handleCreate} disabled={creating}>
                {creating ? <ActivityIndicator color={theme.card} size="small"/>
                  : <Text style={[s.modalBtnText, { color:theme.card }]}>CREATE</Text>}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}