// PATH: vulnassess-app/screens/DashboardScreen.js
import React, { useState, useEffect } from 'react';
import {
  View, Text, FlatList, TouchableOpacity, StyleSheet,
  ActivityIndicator, RefreshControl, Modal, TextInput, Alert
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { api } from '../services/api';
import { useTheme } from '../context/ThemeContext';
import { useNotifications } from '../context/NotificationContext';

export default function DashboardScreen({ navigation }) {
  const { theme, isDark, toggleTheme } = useTheme();
  const { notifications, unreadCount, markAllRead, clearAll } = useNotifications();
  const [scans,       setScans]       = useState([]);
  const [loading,     setLoading]     = useState(true);
  const [refreshing,  setRefreshing]  = useState(false);
  const [email,       setEmail]       = useState('');
  const [role,        setRole]        = useState('');
  const [showNotifs,  setShowNotifs]  = useState(false);
  const [selectMode,  setSelectMode]  = useState(false);
  const [selectedIds, setSelectedIds] = useState([]);
  const [showDelModal,setShowDelModal]= useState(false);
  const [delPass,     setDelPass]     = useState('');
  const [delErr,      setDelErr]      = useState('');
  const [deleting,    setDeleting]    = useState(false);

  const pollState = React.useRef({ timer: null, delay: 2000 });

  useEffect(() => {
    loadData();
    const unsub = navigation.addListener('focus', loadData);
    return unsub;
  }, [navigation]);

  // Poll while scans are running
  useEffect(() => {
    const clearPoll = () => {
      if (pollState.current.timer) {
        clearTimeout(pollState.current.timer);
        pollState.current.timer = null;
      }
    };

    const hasRunning = scans.some(s => s.status === 'running' || s.status === 'pending');
    if (!hasRunning) {
      pollState.current.delay = 2000;
      clearPoll();
      return clearPoll;
    }

    let cancelled = false;
    const maxDelay = 30000;

    const scheduleNext = () => {
      pollState.current.timer = setTimeout(async () => {
        if (cancelled) return;
        await fetchScans();
        pollState.current.delay = Math.min(pollState.current.delay + 1000, maxDelay);
        scheduleNext();
      }, pollState.current.delay);
    };

    clearPoll();
    scheduleNext();

    return () => {
      cancelled = true;
      clearPoll();
    };
  }, [scans]);

  const loadData = async () => {
    setEmail(await AsyncStorage.getItem('email') || '');
    setRole(await AsyncStorage.getItem('role') || '');
    await fetchScans();
  };

  const fetchScans = async () => {
    try {
      const data = await api.getScans();
      if (Array.isArray(data)) setScans(data);
    } catch {}
    setLoading(false);
    setRefreshing(false);
  };

  const handleLogout = async () => {
    await api.logout();
    navigation.replace('Login');
  };

  const toggleSelect = id =>
    setSelectedIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);

  const handleBulkDelete = async () => {
    setDelErr('');
    if (!delPass) { setDelErr('Enter your password'); return; }
    setDeleting(true);
    for (const id of selectedIds) {
      const res = await api.deleteScanVerified(id, delPass).catch(() => null);
      if (res && !res.message && !res.success) {
        setDelErr(res.detail || 'Wrong password');
        setDeleting(false);
        return;
      }
    }
    setDeleting(false);
    setShowDelModal(false);
    setDelPass(''); setDelErr('');
    setSelectMode(false); setSelectedIds([]);
    fetchScans();
  };

  const getId = item => item._id || item.id;

  const statusColor = st => ({
    completed: theme.success, running: theme.medium,
    failed: theme.danger, cancelled: theme.warning, pending: theme.muted,
  })[st] || theme.muted;

  const riskColor = score => {
    if (score >= 8) return theme.critical;
    if (score >= 6) return theme.high;
    if (score >= 4) return theme.warning;
    if (score > 0)  return theme.low;
    return theme.textMuted;
  };

  // Stats from new field names
  const total     = scans.length;
  const completed = scans.filter(s => s.status === 'completed').length;
  const running   = scans.filter(s => s.status === 'running').length;
  const highRisk  = scans.filter(s => (s.total_risk_score || 0) >= 7).length;
  const totalVulns= scans.filter(s => s.status === 'completed')
                         .reduce((a, s) => a + (s.total_vulnerabilities || 0), 0);
  const critical  = scans.filter(s => s.status === 'completed')
                         .reduce((a, s) => a + (s.severity_counts?.critical || 0), 0);

  const s = StyleSheet.create({
    container:      { flex:1, backgroundColor:theme.bg },
    center:         { flex:1, justifyContent:'center', alignItems:'center', backgroundColor:theme.bg },
    header:         { backgroundColor:theme.header, paddingTop:50, paddingBottom:16, paddingHorizontal:16 },
    headerTop:      { flexDirection:'row', justifyContent:'space-between', alignItems:'flex-start' },
    welcomeText:    { color:'rgba(253,255,245,0.6)', fontSize:12, letterSpacing:1 },
    emailText:      { color:'#FDFFF5', fontSize:15, fontWeight:'bold', marginTop:2 },
    roleText:       { color:'rgba(253,255,245,0.45)', fontSize:10, letterSpacing:1, marginTop:1 },
    headerBtns:     { flexDirection:'row', flexWrap:'wrap', justifyContent:'flex-end', gap:6 },
    hBtn:           { backgroundColor:'rgba(253,255,245,0.12)', borderRadius:7, paddingHorizontal:10, paddingVertical:6 },
    hBtnText:       { color:'#FDFFF5', fontSize:11, fontWeight:'bold', letterSpacing:0.5 },
    adminBtn:       { backgroundColor:'#FDFFF5', borderRadius:7, paddingHorizontal:10, paddingVertical:6 },
    adminBtnText:   { color:'#191970', fontSize:11, fontWeight:'bold' },
    statsRow:       { flexDirection:'row', padding:12, gap:8 },
    statCard:       { flex:1, backgroundColor:theme.card, borderRadius:10, padding:12,
                      alignItems:'center', borderWidth:1, borderColor:theme.border, borderTopWidth:3 },
    statNum:        { fontSize:22, fontWeight:'bold', marginBottom:2 },
    statLabel:      { fontSize:9, color:theme.textMuted, letterSpacing:1, textAlign:'center' },
    quickRow:       { flexDirection:'row', paddingHorizontal:12, gap:8, marginBottom:8 },
    qBtn:           { flex:1, borderRadius:10, padding:10, alignItems:'center',
                      backgroundColor:theme.card, borderWidth:1, borderColor:theme.border },
    qBtnText:       { fontSize:11, fontWeight:'bold' },
    toolbar:        { flexDirection:'row', alignItems:'center', backgroundColor:theme.card,
                      paddingHorizontal:14, paddingVertical:10, borderBottomWidth:1, borderBottomColor:theme.border },
    toolbarText:    { flex:1, color:theme.text, fontWeight:'bold', fontSize:13 },
    toolbarBtn:     { paddingHorizontal:12, paddingVertical:6, borderRadius:7, marginLeft:8 },
    listTitle:      { fontSize:12, fontWeight:'bold', color:theme.textSecondary,
                      letterSpacing:1.5, paddingHorizontal:14, paddingVertical:8 },
    scanCard:       { backgroundColor:theme.card, borderRadius:12, padding:14,
                      marginHorizontal:12, marginBottom:10, borderWidth:1, borderColor:theme.border,
                      borderLeftWidth:3 },
    scanCardSelected:{ borderColor:theme.accent, borderWidth:2 },
    scanRow:        { flexDirection:'row', justifyContent:'space-between', alignItems:'center', marginBottom:6 },
    selectCircle:   { width:20, height:20, borderRadius:10, borderWidth:2,
                      borderColor:theme.border, marginRight:8, alignItems:'center', justifyContent:'center' },
    selectCircleOn: { backgroundColor:theme.accent, borderColor:theme.accent },
    selectCheck:    { color:'#fff', fontSize:9, fontWeight:'bold' },
    scanUrl:        { fontSize:13, fontWeight:'bold', color:theme.text, flex:1 },
    badge:          { paddingHorizontal:7, paddingVertical:3, borderRadius:5 },
    badgeText:      { fontSize:10, fontWeight:'bold' },
    scanMeta:       { flexDirection:'row', justifyContent:'space-between', marginTop:4 },
    scanDate:       { fontSize:11, color:theme.textMuted },
    scanRisk:       { fontSize:11, fontWeight:'bold' },
    scanVulns:      { fontSize:10, color:theme.textMuted, marginTop:2 },
    progressBar:    { height:2, backgroundColor:theme.border, borderRadius:1, marginTop:6, overflow:'hidden' },
    progressFill:   { height:'100%', borderRadius:1 },
    empty:          { alignItems:'center', padding:60 },
    emptyText:      { fontSize:16, fontWeight:'bold', color:theme.textSecondary },
    emptySubtext:   { fontSize:13, color:theme.textMuted, textAlign:'center', marginTop:6 },
    fab:            { backgroundColor:theme.accent, margin:12, padding:16, borderRadius:12, alignItems:'center' },
    fabText:        { color:theme.card, fontSize:15, fontWeight:'bold', letterSpacing:1 },
    overlay:        { position:'absolute', top:0, left:0, right:0, bottom:0,
                      backgroundColor:'rgba(0,0,0,0.5)', justifyContent:'flex-end', zIndex:999 },
    notifPanel:     { backgroundColor:theme.card, borderTopLeftRadius:20, borderTopRightRadius:20,
                      padding:20, maxHeight:'70%', borderWidth:1, borderColor:theme.border },
    notifHeader:    { flexDirection:'row', justifyContent:'space-between', alignItems:'center', marginBottom:14 },
    notifTitle:     { fontSize:16, fontWeight:'bold', color:theme.text },
    notifItem:      { borderLeftWidth:3, borderRadius:8, padding:12, marginBottom:8, backgroundColor:theme.bg2 },
    notifItemTitle: { fontSize:13, fontWeight:'bold', color:theme.text, marginBottom:2 },
    notifItemMsg:   { fontSize:12, color:theme.textSecondary },
    notifItemTime:  { fontSize:10, color:theme.textMuted, marginTop:3 },
    modalOverlay:   { flex:1, backgroundColor:'rgba(0,0,0,0.6)', justifyContent:'center', alignItems:'center', padding:24 },
    modal:          { backgroundColor:theme.card, borderRadius:16, padding:24, width:'100%', maxWidth:380,
                      borderWidth:1, borderColor:theme.dangerBorder },
    modalTitle:     { fontSize:16, fontWeight:'bold', color:theme.danger, marginBottom:8 },
    modalDesc:      { fontSize:13, color:theme.textSecondary, marginBottom:14, lineHeight:20 },
    modalBtns:      { flexDirection:'row', gap:10, marginTop:4 },
    modalBtn:       { flex:1, padding:13, borderRadius:10, alignItems:'center' },
    modalBtnText:   { color:'#fff', fontWeight:'bold', fontSize:14 },
    modalInput:     { borderWidth:1, borderColor:theme.inputBorder, borderRadius:8, padding:12,
                      fontSize:14, color:theme.text, backgroundColor:theme.input, marginBottom:12 },
    modalErr:       { backgroundColor:theme.dangerBg, borderWidth:1, borderColor:theme.dangerBorder,
                      borderRadius:8, padding:10, marginBottom:12 },
    modalErrText:   { color:theme.danger, fontSize:12 },
  });

  const renderScan = ({ item }) => {
    const id       = getId(item);
    const selected = selectedIds.includes(id);
    const sc       = item.severity_counts || {};
    return (
      <TouchableOpacity
        style={[s.scanCard, { borderLeftColor: statusColor(item.status) }, selected && s.scanCardSelected]}
        onPress={() => selectMode ? toggleSelect(id) : navigation.navigate('ScanProgress', { scanId: id })}
        onLongPress={() => { if (!selectMode) { setSelectMode(true); setSelectedIds([id]); } }}
      >
        <View style={s.scanRow}>
          {selectMode && (
            <View style={[s.selectCircle, selected && s.selectCircleOn]}>
              {selected && <Text style={s.selectCheck}>✓</Text>}
            </View>
          )}
          <Text style={s.scanUrl} numberOfLines={1}>{item.target_url || item.target}</Text>
          <View style={[s.badge, { backgroundColor: statusColor(item.status) + '25' }]}>
            <Text style={[s.badgeText, { color: statusColor(item.status) }]}>
              {item.status?.toUpperCase()}
            </Text>
          </View>
        </View>

        {item.status === 'running' && (
          <View style={s.progressBar}>
            <View style={[s.progressFill, { width:`${item.progress||0}%`, backgroundColor:theme.accent }]}/>
          </View>
        )}

        {item.status === 'completed' && (
          <View style={{ flexDirection:'row', gap:6, flexWrap:'wrap', marginTop:4 }}>
            {['critical','high','medium','low'].map(sv => (sc[sv] > 0) && (
              <View key={sv} style={[s.badge, { backgroundColor: theme[sv+'Bg'] }]}>
                <Text style={[s.badgeText, { color: theme[sv] }]}>{sc[sv]} {sv}</Text>
              </View>
            ))}
          </View>
        )}

        <View style={s.scanMeta}>
          <Text style={s.scanDate}>{item.created_at ? new Date(item.created_at).toLocaleDateString() : ''}</Text>
          <Text style={[s.scanRisk, { color: riskColor(item.total_risk_score) }]}>
            Risk: {item.total_risk_score?.toFixed(1) || '0.0'}/10
          </Text>
        </View>
      </TouchableOpacity>
    );
  };

  if (loading) return <View style={s.center}><ActivityIndicator size="large" color={theme.accent}/></View>;

  return (
    <View style={s.container}>
      {/* Header */}
      <View style={s.header}>
        <View style={s.headerTop}>
          <View>
            <Text style={s.welcomeText}>WELCOME BACK</Text>
            <Text style={s.emailText}>{email}</Text>
            <Text style={s.roleText}>{role === 'admin' ? '★ ADMIN' : '◆ USER'}</Text>
          </View>
          <View style={s.headerBtns}>
            <TouchableOpacity style={s.hBtn} onPress={() => { setShowNotifs(true); markAllRead(); }}>
              <Text style={s.hBtnText}>🔔{unreadCount > 0 ? ` ${unreadCount}` : ''}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={s.hBtn} onPress={toggleTheme}>
              <Text style={s.hBtnText}>{isDark ? '☀' : '☾'}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={s.hBtn} onPress={() => navigation.navigate('Profile')}>
              <Text style={s.hBtnText}>Profile</Text>
            </TouchableOpacity>
            {role === 'admin' && (
              <TouchableOpacity style={s.adminBtn} onPress={() => navigation.navigate('Admin')}>
                <Text style={s.adminBtnText}>Admin</Text>
              </TouchableOpacity>
            )}
            <TouchableOpacity style={s.hBtn} onPress={handleLogout}>
              <Text style={s.hBtnText}>Logout</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>

      {/* Stats */}
      <View style={s.statsRow}>
        {[
          { label:'SCANS',     value:total,     color:theme.accent    },
          { label:'DONE',      value:completed, color:theme.success   },
          { label:'RUNNING',   value:running,   color:theme.warning   },
          { label:'VULNS',     value:totalVulns,color:theme.high      },
          { label:'CRITICAL',  value:critical,  color:theme.critical  },
        ].map(st => (
          <View key={st.label} style={[s.statCard, { borderTopColor: st.color }]}>
            <Text style={[s.statNum, { color: st.color }]}>{st.value}</Text>
            <Text style={s.statLabel}>{st.label}</Text>
          </View>
        ))}
      </View>

      {/* Quick actions */}
      <View style={s.quickRow}>
        {[
          { label:'Compare', color:theme.success, screen:'Compare' },
          { label:'Schedule',color:theme.warning, screen:'Schedule' },
          { label:'Profile', color:theme.high,    screen:'Profile'  },
        ].map(a => (
          <TouchableOpacity key={a.label} style={[s.qBtn, { borderColor: a.color+'50' }]}
            onPress={() => navigation.navigate(a.screen)}>
            <Text style={[s.qBtnText, { color: a.color }]}>{a.label}</Text>
          </TouchableOpacity>
        ))}
      </View>

      {/* Select toolbar */}
      {selectMode && (
        <View style={s.toolbar}>
          <Text style={s.toolbarText}>{selectedIds.length} selected</Text>
          <TouchableOpacity style={[s.toolbarBtn, { backgroundColor:theme.accentMuted }]}
            onPress={() => setSelectedIds(scans.map(getId))}>
            <Text style={{ color:theme.accent, fontWeight:'bold', fontSize:12 }}>All</Text>
          </TouchableOpacity>
          <TouchableOpacity style={[s.toolbarBtn, { backgroundColor:theme.dangerBg }]}
            onPress={() => { if (!selectedIds.length) return; setDelErr(''); setDelPass(''); setShowDelModal(true); }}>
            <Text style={{ color:theme.danger, fontWeight:'bold', fontSize:12 }}>Delete ({selectedIds.length})</Text>
          </TouchableOpacity>
          <TouchableOpacity style={[s.toolbarBtn, { backgroundColor:theme.bg }]}
            onPress={() => { setSelectMode(false); setSelectedIds([]); }}>
            <Text style={{ color:theme.textSecondary, fontWeight:'bold', fontSize:12 }}>Cancel</Text>
          </TouchableOpacity>
        </View>
      )}

      <FlatList
        data={scans}
        keyExtractor={item => getId(item)}
        renderItem={renderScan}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => { setRefreshing(true); fetchScans(); }} tintColor={theme.accent}/>}
        ListHeaderComponent={<Text style={s.listTitle}>RECENT OPERATIONS</Text>}
        ListEmptyComponent={
          <View style={s.empty}>
            <Text style={s.emptyText}>No scans yet</Text>
            <Text style={s.emptySubtext}>Tap the button below to start your first scan</Text>
          </View>
        }
      />

      <TouchableOpacity style={s.fab} onPress={() => navigation.navigate('NewScan')}>
        <Text style={s.fabText}>⊕ LAUNCH SCAN</Text>
      </TouchableOpacity>

      {/* Notifications panel */}
      {showNotifs && (
        <View style={s.overlay}>
          <View style={s.notifPanel}>
            <View style={s.notifHeader}>
              <Text style={s.notifTitle}>Notifications</Text>
              <View style={{ flexDirection:'row', gap:16 }}>
                <TouchableOpacity onPress={clearAll}><Text style={{ color:theme.danger, fontSize:13 }}>Clear All</Text></TouchableOpacity>
                <TouchableOpacity onPress={() => setShowNotifs(false)}><Text style={{ color:theme.accent, fontSize:13 }}>Close</Text></TouchableOpacity>
              </View>
            </View>
            {notifications.length === 0
              ? <Text style={{ textAlign:'center', padding:30, color:theme.textMuted }}>No notifications yet</Text>
              : notifications.map(n => (
                  <TouchableOpacity key={n.id}
                    style={[s.notifItem, { borderLeftColor: n.type==='success' ? theme.success : n.type==='error' ? theme.danger : theme.accent }]}
                    onPress={() => { setShowNotifs(false); if (n.scanId) navigation.navigate('Report', { scanId: n.scanId }); }}>
                    <Text style={s.notifItemTitle}>{n.title}</Text>
                    <Text style={s.notifItemMsg}>{n.message}</Text>
                    <Text style={s.notifItemTime}>{new Date(n.timestamp).toLocaleTimeString()}</Text>
                  </TouchableOpacity>
                ))
            }
          </View>
        </View>
      )}

      {/* Bulk delete modal */}
      <Modal visible={showDelModal} transparent animationType="fade">
        <View style={s.modalOverlay}>
          <View style={s.modal}>
            <Text style={s.modalTitle}>CONFIRM DELETE</Text>
            <Text style={s.modalDesc}>
              Enter your password to delete {selectedIds.length} scan{selectedIds.length > 1 ? 's' : ''}.
            </Text>
            {!!delErr && <View style={s.modalErr}><Text style={s.modalErrText}>⚠ {delErr}</Text></View>}
            <TextInput
              style={s.modalInput} placeholder="Your password"
              placeholderTextColor={theme.textMuted} value={delPass}
              onChangeText={t => { setDelPass(t); setDelErr(''); }} secureTextEntry
            />
            <View style={s.modalBtns}>
              <TouchableOpacity style={[s.modalBtn, { backgroundColor:theme.bg, borderWidth:1, borderColor:theme.border }]}
                onPress={() => { setShowDelModal(false); setDelPass(''); setDelErr(''); }}>
                <Text style={[s.modalBtnText, { color:theme.text }]}>CANCEL</Text>
              </TouchableOpacity>
              <TouchableOpacity style={[s.modalBtn, { backgroundColor:theme.danger }, deleting && { opacity:0.5 }]}
                onPress={handleBulkDelete} disabled={deleting}>
                {deleting ? <ActivityIndicator color="#fff" size="small"/> : <Text style={s.modalBtnText}>DELETE</Text>}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}