// PATH: vulnassess-app/screens/AdminScreen.js
import React, { useState, useEffect } from 'react';
import { View, Text, ScrollView, TouchableOpacity, StyleSheet, Alert, ActivityIndicator, Switch, TextInput } from 'react-native';
import { api } from '../services/api';
import { useTheme } from '../context/ThemeContext';

export default function AdminScreen() {
  const { theme } = useTheme();
  const [users,        setUsers]        = useState([]);
  const [modules,      setModules]      = useState([]);
  const [allScans,     setAllScans]     = useState([]);
  const [stats,        setStats]        = useState(null);
  const [logs,         setLogs]         = useState([]);
  const [payments,     setPayments]     = useState([]);
  const [tab,          setTab]          = useState('stats');
  const [loading,      setLoading]      = useState(true);
  const [editingLimit, setEditingLimit] = useState(null);
  const [limitValue,   setLimitValue]   = useState('');

  const getId = item => item._id || item.id;

  useEffect(() => { loadAll(); }, []);

  const loadAll = async () => {
    try {
      const [u, m, s, st, l, p] = await Promise.all([
        api.getUsers(), api.getModules(), api.getAllScans(),
        api.getStats(), api.getLogs(), api.getPayments(),
      ]);
      if (Array.isArray(u)) setUsers(u);
      if (Array.isArray(m)) setModules(m);
      if (Array.isArray(s)) setAllScans(s);
      if (st && !st.detail) setStats(st);
      if (Array.isArray(l)) setLogs(l);
      if (Array.isArray(p)) setPayments(p);
    } catch { Alert.alert('Error', 'Failed to load admin data'); }
    setLoading(false);
  };

  const handleDeleteUser = (userId, email) => {
    Alert.alert('Delete User', `Delete ${email}?`,
      [{ text:'Cancel', style:'cancel' },
       { text:'Delete', style:'destructive', onPress: async () => {
           await api.deleteUser(userId);
           setUsers(u => u.filter(x => getId(x) !== userId));
         }
       }]
    );
  };

  const handleRoleToggle = async (userId, currentRole) => {
    const newRole = currentRole === 'admin' ? 'user' : 'admin';
    await api.updateRole(userId, newRole);
    setUsers(u => u.map(x => getId(x)===userId ? {...x, role:newRole} : x));
  };

  const handleToggleUser = async (userId) => {
    await api.toggleUser(userId);
    setUsers(u => u.map(x => getId(x)===userId ? {...x, is_active:!x.is_active} : x));
  };

  const handleScanLimit = async (userId) => {
    const limit = parseInt(limitValue);
    if (isNaN(limit) || limit < 1) { Alert.alert('Error', 'Enter a valid number'); return; }
    await api.updateScanLimit(userId, limit);
    setUsers(u => u.map(x => getId(x)===userId ? {...x, scan_limit:limit} : x));
    setEditingLimit(null); setLimitValue('');
  };

  const handleModuleToggle = async (moduleKey, currentEnabled, isFixed) => {
    if (isFixed) { Alert.alert('Cannot Disable', 'Authentication module is required and cannot be disabled.'); return; }
    await api.updateModule(moduleKey, !currentEnabled);
    setModules(m => m.map(x => x.module_key===moduleKey ? {...x, enabled:!currentEnabled} : x));
  };

  const handleMoveModule = async (index, dir) => {
    const mod = modules[index];
    if (mod.fixed) return;
    const swapIdx = dir==='up' ? index-1 : index+1;
    if (swapIdx < 0 || swapIdx >= modules.length || modules[swapIdx].fixed) return;
    const newMods = [...modules];
    [newMods[index], newMods[swapIdx]] = [newMods[swapIdx], newMods[index]];
    setModules(newMods);
    await api.updateModuleOrder(mod.module_key, newMods[swapIdx].order);
  };

  const handleRestoreDefaults = () => {
    Alert.alert('Restore Defaults', 'Reset all modules to default order and enable all?',
      [{ text:'Cancel', style:'cancel' },
       { text:'Restore', onPress: async () => {
           await api.restoreModuleDefaults(); await loadAll();
           Alert.alert('Done', 'Modules restored to defaults!');
         }
       }]
    );
  };

  const handleDeleteScan = (scanId) => {
    Alert.alert('Delete Scan', 'Delete this scan?',
      [{ text:'Cancel', style:'cancel' },
       { text:'Delete', style:'destructive', onPress: async () => {
           await api.adminDeleteScan(scanId);
           setAllScans(s => s.filter(x => getId(x)!==scanId));
         }
       }]
    );
  };

  const handleAutoVerify = async (paymentId) => {
    await api.autoVerifyPayment(paymentId);
    await loadAll();
  };

  const handleSetPaymentStatus = async (paymentId, status) => {
    await api.updatePaymentStatus(paymentId, status, status === 'verified' ? 'Approved by admin' : 'Rejected by admin');
    await loadAll();
  };

  const s = StyleSheet.create({
    container:    { flex:1, backgroundColor:theme.bg },
    center:       { flex:1, justifyContent:'center', alignItems:'center', backgroundColor:theme.bg },
    tabBar:       { maxHeight:48, borderBottomWidth:1, borderBottomColor:theme.border, backgroundColor:theme.card },
    tab:          { paddingHorizontal:18, paddingVertical:14 },
    tabText:      { fontSize:13, fontWeight:'500' },
    tabActive:    { borderBottomWidth:3 },
    content:      { flex:1, padding:14 },
    sTitle:       { fontSize:13, fontWeight:'bold', color:theme.textSecondary, letterSpacing:2, marginBottom:12 },
    statsGrid:    { flexDirection:'row', flexWrap:'wrap', gap:8, marginBottom:16 },
    statCard:     { width:'31%', borderRadius:10, padding:12, alignItems:'center', borderWidth:1, borderColor:theme.border },
    statVal:      { fontSize:26, fontWeight:'bold', marginBottom:2 },
    statLabel:    { fontSize:10, color:theme.textSecondary, textAlign:'center', letterSpacing:0.5 },
    chartCard:    { backgroundColor:theme.card, borderRadius:12, padding:14, flexDirection:'row',
                    justifyContent:'space-around', alignItems:'flex-end', height:130, marginBottom:16,
                    borderWidth:1, borderColor:theme.border },
    chartCol:     { alignItems:'center', flex:1 },
    chartCount:   { fontSize:10, color:theme.textSecondary, marginBottom:4 },
    bar:          { width:22, borderRadius:4, minHeight:4 },
    chartDate:    { fontSize:9, color:theme.textMuted, marginTop:4 },
    card:         { backgroundColor:theme.card, borderRadius:12, padding:14, marginBottom:10, borderWidth:1, borderColor:theme.border },
    cardRow:      { flexDirection:'row', justifyContent:'space-between', alignItems:'center' },
    cardInfo:     { flex:1, marginRight:8 },
    cardTitle:    { fontSize:14, fontWeight:'bold', color:theme.text },
    cardSub:      { fontSize:12, color:theme.textSecondary, marginTop:2 },
    roleBadge:    { paddingHorizontal:10, paddingVertical:4, borderRadius:8 },
    roleText:     { fontSize:11, fontWeight:'bold' },
    cardBtns:     { flexDirection:'row', flexWrap:'wrap', gap:6, marginTop:10 },
    aBtn:         { paddingHorizontal:10, paddingVertical:5, borderRadius:7 },
    aBtnText:     { fontSize:11, fontWeight:'bold' },
    limitRow:     { flexDirection:'row', gap:8, marginTop:8, alignItems:'center' },
    limitInput:   { flex:1, backgroundColor:theme.input, borderWidth:1, borderColor:theme.border,
                    borderRadius:8, padding:8, fontSize:13, color:theme.text },
    limitSave:    { backgroundColor:theme.success, padding:8, borderRadius:8, paddingHorizontal:12 },
    limitSaveText:{ color:'#fff', fontWeight:'bold', fontSize:12 },
    limitCancel:  { backgroundColor:theme.dangerBg, padding:8, borderRadius:8, paddingHorizontal:10 },
    limitCancelT: { color:theme.danger, fontWeight:'bold', fontSize:12 },
    modsHeader:   { flexDirection:'row', justifyContent:'space-between', alignItems:'center', marginBottom:8 },
    restoreBtn:   { paddingHorizontal:12, paddingVertical:6, borderRadius:8, backgroundColor:theme.accentMuted },
    restoreBtnText:{ fontSize:12, fontWeight:'bold', color:theme.accent },
    hintText:     { fontSize:11, color:theme.textSecondary, marginBottom:10 },
    modRow:       { flexDirection:'row', alignItems:'center', gap:8 },
    orderBtns:    { alignItems:'center', width:28 },
    orderBtn:     { fontSize:10, fontWeight:'bold', color:theme.accent, padding:2 },
    orderNum:     { fontSize:11, color:theme.textMuted },
    modInfo:      { flex:1 },
    fixedLabel:   { fontSize:10, color:theme.accent, marginTop:2, letterSpacing:1 },
    scanCard:     { backgroundColor:theme.card, borderRadius:12, padding:14, marginBottom:8, borderWidth:1, borderColor:theme.border, borderLeftWidth:3 },
    delScanBtn:   { alignSelf:'flex-end', paddingHorizontal:12, paddingVertical:4, borderRadius:6, marginTop:8, backgroundColor:theme.dangerBg },
    delScanText:  { color:theme.danger, fontSize:11, fontWeight:'bold' },
    logCard:      { backgroundColor:theme.card, borderRadius:10, padding:12, marginBottom:8, borderLeftWidth:3, borderWidth:1, borderColor:theme.border },
    logHeader:    { flexDirection:'row', justifyContent:'space-between', marginBottom:4 },
    logAction:    { fontSize:11, fontWeight:'bold', letterSpacing:1 },
    logTime:      { fontSize:10, color:theme.textMuted },
    logDetail:    { fontSize:11, color:theme.textSecondary },
    empty:        { padding:40, alignItems:'center' },
    emptyText:    { fontSize:14, color:theme.textMuted },
  });

  if (loading) return <View style={s.center}><ActivityIndicator size="large" color={theme.accent}/></View>;

  const TABS = ['stats','users','modules','scans','payments','logs'];

  return (
    <View style={s.container}>
      {/* Tabs */}
      <ScrollView horizontal showsHorizontalScrollIndicator={false} style={s.tabBar}>
        {TABS.map(t => (
          <TouchableOpacity key={t} style={[s.tab, tab===t && { ...s.tabActive, borderBottomColor:theme.accent }]} onPress={() => setTab(t)}>
            <Text style={[s.tabText, { color: tab===t ? theme.accent : theme.textSecondary }, tab===t && { fontWeight:'bold' }]}>
              {t.charAt(0).toUpperCase()+t.slice(1)}
            </Text>
          </TouchableOpacity>
        ))}
      </ScrollView>

      <ScrollView style={s.content}>

        {/* STATS */}
        {tab==='stats' && stats && (
          <>
            <Text style={s.sTitle}>PLATFORM OVERVIEW</Text>
            <View style={s.statsGrid}>
              {[
                { label:'TOTAL USERS',  value:stats.total_users,     color:theme.accent    },
                { label:'TOTAL SCANS',  value:stats.total_scans,     color:'#7C3AED'       },
                { label:'COMPLETED',    value:stats.completed_scans, color:theme.success   },
                { label:'FAILED',       value:stats.failed_scans,    color:theme.danger    },
                { label:'HIGH RISK',    value:stats.high_risk_scans, color:theme.high      },
                { label:'THIS WEEK',    value:stats.recent_scans,    color:theme.medium    },
              ].map((item, i) => (
                <View key={i} style={[s.statCard, { borderTopWidth:3, borderTopColor:item.color }]}>
                  <Text style={[s.statVal, { color:item.color }]}>{item.value}</Text>
                  <Text style={s.statLabel}>{item.label}</Text>
                </View>
              ))}
            </View>

            {stats.scans_per_day?.length > 0 && (
              <>
                <Text style={s.sTitle}>SCANS LAST 7 DAYS</Text>
                <View style={s.chartCard}>
                  {stats.scans_per_day.map((day, i) => (
                    <View key={i} style={s.chartCol}>
                      <Text style={s.chartCount}>{day.count}</Text>
                      <View style={[s.bar, { height: Math.max(day.count*18,4), backgroundColor: day.count>0 ? theme.accent : theme.border }]}/>
                      <Text style={s.chartDate}>{day.date}</Text>
                    </View>
                  ))}
                </View>
              </>
            )}
          </>
        )}

        {/* USERS */}
        {tab==='users' && (
          <>
            <Text style={s.sTitle}>USERS ({users.length})</Text>
            {users.map(user => {
              const uid = getId(user);
              return (
                <View key={uid} style={[s.card, !user.is_active && { opacity:0.6 }]}>
                  <View style={s.cardRow}>
                    <View style={s.cardInfo}>
                      <Text style={s.cardTitle}>{user.email}</Text>
                      <Text style={s.cardSub}>Scans: {user.scan_count||0} / {user.scan_limit||100}</Text>
                      <Text style={[s.cardSub, { color: user.is_active ? theme.success : theme.danger }]}>
                        {user.is_active ? '● Active' : '○ Deactivated'}
                      </Text>
                    </View>
                    <View style={[s.roleBadge, { backgroundColor: user.role==='admin' ? theme.accentMuted : theme.bg }]}>
                      <Text style={[s.roleText, { color: user.role==='admin' ? theme.accent : theme.textMuted }]}>
                        {user.role==='admin' ? '★ Admin' : '◆ User'}
                      </Text>
                    </View>
                  </View>

                  {editingLimit===uid && (
                    <View style={s.limitRow}>
                      <TextInput style={s.limitInput} value={limitValue} onChangeText={setLimitValue}
                        keyboardType="number-pad" placeholder="Scan limit" placeholderTextColor={theme.textMuted}/>
                      <TouchableOpacity style={s.limitSave} onPress={() => handleScanLimit(uid)}>
                        <Text style={s.limitSaveText}>Save</Text>
                      </TouchableOpacity>
                      <TouchableOpacity style={s.limitCancel} onPress={() => setEditingLimit(null)}>
                        <Text style={s.limitCancelT}>Cancel</Text>
                      </TouchableOpacity>
                    </View>
                  )}

                  <View style={s.cardBtns}>
                    {[
                      { label: user.role==='admin' ? 'Make User' : 'Make Admin', bg:theme.accentMuted, color:theme.accent, fn:() => handleRoleToggle(uid, user.role) },
                      { label:'Set Limit', bg:theme.highBg, color:theme.high, fn:() => { setEditingLimit(uid); setLimitValue(String(user.scan_limit||100)); } },
                      { label: user.is_active ? 'Deactivate' : 'Activate', bg: user.is_active ? theme.dangerBg : theme.successBg, color: user.is_active ? theme.danger : theme.success, fn:() => handleToggleUser(uid) },
                      { label:'Delete', bg:theme.dangerBg, color:theme.danger, fn:() => handleDeleteUser(uid, user.email) },
                    ].map((btn, i) => (
                      <TouchableOpacity key={i} style={[s.aBtn, { backgroundColor:btn.bg }]} onPress={btn.fn}>
                        <Text style={[s.aBtnText, { color:btn.color }]}>{btn.label}</Text>
                      </TouchableOpacity>
                    ))}
                  </View>
                </View>
              );
            })}
          </>
        )}

        {/* MODULES */}
        {tab==='modules' && (
          <>
            <View style={s.modsHeader}>
              <Text style={s.sTitle}>MODULES ({modules.length})</Text>
              <TouchableOpacity style={s.restoreBtn} onPress={handleRestoreDefaults}>
                <Text style={s.restoreBtnText}>Restore Defaults</Text>
              </TouchableOpacity>
            </View>
            <Text style={s.hintText}>↑↓ to reorder · Auth module is fixed · Toggle to enable/disable</Text>
            {modules.map((mod, idx) => (
              <View key={mod.module_key} style={[s.card, mod.fixed && { borderColor:theme.accent }]}>
                <View style={s.modRow}>
                  <View style={s.orderBtns}>
                    <TouchableOpacity onPress={() => handleMoveModule(idx,'up')} disabled={idx===0||mod.fixed}>
                      <Text style={[s.orderBtn, (idx===0||mod.fixed) && { color:theme.border }]}>▲</Text>
                    </TouchableOpacity>
                    <Text style={s.orderNum}>{idx+1}</Text>
                    <TouchableOpacity onPress={() => handleMoveModule(idx,'down')} disabled={idx===modules.length-1||mod.fixed}>
                      <Text style={[s.orderBtn, (idx===modules.length-1||mod.fixed) && { color:theme.border }]}>▼</Text>
                    </TouchableOpacity>
                  </View>
                  <View style={s.modInfo}>
                    <Text style={s.cardTitle}>{mod.name}</Text>
                    {mod.fixed && <Text style={s.fixedLabel}>FIXED · CANNOT DISABLE</Text>}
                  </View>
                  <Switch value={mod.enabled}
                    onValueChange={() => handleModuleToggle(mod.module_key, mod.enabled, mod.fixed)}
                    trackColor={{ false:theme.border, true:theme.mediumBorder }}
                    thumbColor={mod.enabled ? theme.accent : theme.textMuted}
                    disabled={mod.fixed}
                  />
                </View>
              </View>
            ))}
          </>
        )}

        {/* SCANS */}
        {tab==='scans' && (
          <>
            <Text style={s.sTitle}>ALL SCANS ({allScans.length})</Text>
            {allScans.map(scan => {
              const sid = getId(scan);
              return (
                <View key={sid} style={[s.scanCard, { borderLeftColor: (scan.total_risk_score||0)>=7 ? theme.danger : theme.success }]}>
                  <Text style={s.cardTitle} numberOfLines={1}>{scan.target_url || scan.target}</Text>
                  <Text style={s.cardSub}>User: {(scan.user_id||'').slice(0,14)}…</Text>
                  <View style={s.cardRow}>
                    <Text style={s.cardSub}>{scan.created_at ? new Date(scan.created_at).toLocaleDateString() : '—'}</Text>
                    <Text style={[s.cardSub, { fontWeight:'bold', color: (scan.total_risk_score||0)>=7 ? theme.danger : theme.success }]}>
                      Risk: {scan.total_risk_score?.toFixed(1)||'0.0'}/10
                    </Text>
                  </View>
                  <TouchableOpacity style={s.delScanBtn} onPress={() => handleDeleteScan(sid)}>
                    <Text style={s.delScanText}>DELETE</Text>
                  </TouchableOpacity>
                </View>
              );
            })}
          </>
        )}

        {/* LOGS */}
        {tab==='payments' && (
          <>
            <Text style={s.sTitle}>PAYMENTS ({payments.length})</Text>
            {payments.map((p, i) => (
              <View key={p.id || i} style={[s.card, { borderLeftWidth:3, borderLeftColor: p.status==='verified' ? theme.success : p.status==='rejected' ? theme.danger : theme.warning }]}>
                <Text style={s.cardTitle}>Txn: {p.transaction_id}</Text>
                <Text style={s.cardSub}>User: {(p.user_id || '').slice(0, 14)}...</Text>
                <Text style={s.cardSub}>Plan: {(p.plan || '').toUpperCase()} · {p.amount} {p.currency || 'USD'}</Text>
                <Text style={[s.cardSub, { color: p.status==='verified' ? theme.success : p.status==='rejected' ? theme.danger : theme.warning }]}>Status: {(p.status || 'pending').toUpperCase()}</Text>
                <View style={s.cardBtns}>
                  <TouchableOpacity style={[s.aBtn, { backgroundColor:theme.accentMuted }]} onPress={() => handleAutoVerify(p.id)}>
                    <Text style={[s.aBtnText, { color:theme.accent }]}>Auto Verify</Text>
                  </TouchableOpacity>
                  <TouchableOpacity style={[s.aBtn, { backgroundColor:theme.successBg }]} onPress={() => handleSetPaymentStatus(p.id, 'verified')}>
                    <Text style={[s.aBtnText, { color:theme.success }]}>Verify</Text>
                  </TouchableOpacity>
                  <TouchableOpacity style={[s.aBtn, { backgroundColor:theme.dangerBg }]} onPress={() => handleSetPaymentStatus(p.id, 'rejected')}>
                    <Text style={[s.aBtnText, { color:theme.danger }]}>Reject</Text>
                  </TouchableOpacity>
                </View>
              </View>
            ))}
          </>
        )}

        {/* LOGS */}
        {tab==='logs' && (
          <>
            <Text style={s.sTitle}>ACTIVITY LOGS ({logs.length})</Text>
            {logs.length === 0
              ? <View style={s.empty}><Text style={s.emptyText}>No activity logs yet</Text></View>
              : logs.map((log, i) => (
                  <View key={i} style={[s.logCard, { borderLeftColor:theme.accent }]}>
                    <View style={s.logHeader}>
                      <Text style={[s.logAction, { color:theme.accent }]}>{log.action?.replace(/_/g,' ').toUpperCase()}</Text>
                      <Text style={s.logTime}>{log.timestamp ? new Date(log.timestamp).toLocaleString() : ''}</Text>
                    </View>
                    {log.target_id && <Text style={s.logDetail}>Target: {log.target_id.slice(0,14)}…</Text>}
                    {log.new_role   && <Text style={s.logDetail}>New role: {log.new_role}</Text>}
                  </View>
                ))
            }
          </>
        )}

        <View style={{ height:40 }}/>
      </ScrollView>
    </View>
  );
}