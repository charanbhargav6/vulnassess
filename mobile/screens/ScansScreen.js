// PATH: vulnassess-app/screens/ScansScreen.js
import React, { useState, useEffect, useCallback } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView, ActivityIndicator, RefreshControl } from 'react-native';
import { api } from '../services/api';
import { useTheme } from '../context/ThemeContext';

const STATUS_FILTERS = ['all','completed','running','pending','failed'];
const RISK_FILTERS   = [
  { label:'All Risk', value:'all' },
  { label:'Critical 9+', value:'critical' },
  { label:'High 7+', value:'high' },
  { label:'Medium 4+', value:'medium' },
  { label:'Low <4', value:'low' },
];

export default function ScansScreen({ navigation }) {
  const { theme } = useTheme();
  const [scans,        setScans]        = useState([]);
  const [loading,      setLoading]      = useState(true);
  const [refreshing,   setRefreshing]   = useState(false);
  const [search,       setSearch]       = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter,   setRiskFilter]   = useState('all');
  const [selectedIds,  setSelectedIds]  = useState([]);

  const getId = item => item._id || item.id;

  const loadScans = useCallback(async () => {
    try {
      const data = await api.getScans({ status: statusFilter, risk_level: riskFilter, search });
      setScans(Array.isArray(data) ? data : []);
    } catch { setScans([]); }
    setLoading(false);
    setRefreshing(false);
  }, [statusFilter, riskFilter, search]);

  useEffect(() => { setLoading(true); loadScans(); }, [loadScans]);

  const toggleSelect = id =>
    setSelectedIds(prev => {
      if (prev.includes(id)) return prev.filter(x => x !== id);
      if (prev.length >= 2) return prev;
      return [...prev, id];
    });

  const statusColor = st => ({
    completed: theme.success, running: theme.medium,
    failed: theme.danger, cancelled: theme.warning, pending: theme.muted,
  })[st] || theme.muted;

  const riskColor = score => {
    if (score >= 9) return theme.critical;
    if (score >= 7) return theme.high;
    if (score >= 4) return theme.warning;
    return theme.success;
  };

  const hasFilters = search || statusFilter !== 'all' || riskFilter !== 'all';

  const s = StyleSheet.create({
    container:    { flex:1, backgroundColor:theme.bg },
    searchRow:    { flexDirection:'row', padding:12, paddingBottom:0, gap:8 },
    searchInput:  { flex:1, backgroundColor:theme.card, borderWidth:1, borderColor:theme.border,
                    borderRadius:10, padding:10, fontSize:14, color:theme.text },
    clearBtn:     { backgroundColor:theme.dangerBg, borderWidth:1, borderColor:theme.dangerBorder,
                    borderRadius:8, paddingHorizontal:12, paddingVertical:10 },
    clearBtnText: { color:theme.danger, fontWeight:'bold', fontSize:13 },
    pillRow:      { paddingHorizontal:12, paddingVertical:8, gap:6 },
    pill:         { paddingHorizontal:12, paddingVertical:6, borderRadius:20, borderWidth:1 },
    pillText:     { fontSize:12, fontWeight:'500' },
    compareBar:   { backgroundColor:theme.accent, padding:12, flexDirection:'row', justifyContent:'space-between', alignItems:'center' },
    compareBarText:{ color:theme.card, fontSize:13, flex:1 },
    compareBarBtns:{ flexDirection:'row', gap:8 },
    cmpBtn:       { backgroundColor:'rgba(255,255,255,0.2)', borderRadius:8, paddingHorizontal:12, paddingVertical:6 },
    cmpBtnText:   { color:theme.card, fontSize:12, fontWeight:'bold' },
    cmpGoBtn:     { backgroundColor:theme.card, borderRadius:8, paddingHorizontal:12, paddingVertical:6 },
    cmpGoBtnText: { color:theme.accent, fontSize:12, fontWeight:'bold' },
    resultRow:    { flexDirection:'row', justifyContent:'space-between', alignItems:'center', paddingHorizontal:14, paddingVertical:6 },
    resultText:   { fontSize:12, color:theme.textSecondary },
    hintText:     { fontSize:10, color:theme.textMuted },
    scanCard:     { backgroundColor:theme.card, borderRadius:12, marginHorizontal:12, marginBottom:10,
                    padding:14, borderWidth:1, borderLeftWidth:3 },
    scanCardSel:  { borderColor:theme.accent },
    selBadge:     { position:'absolute', top:-8, right:-8, width:22, height:22, borderRadius:11,
                    alignItems:'center', justifyContent:'center', zIndex:1 },
    selBadgeText: { color:theme.card, fontSize:11, fontWeight:'bold' },
    scanRow:      { flexDirection:'row', justifyContent:'space-between', alignItems:'center', marginBottom:6 },
    scanUrl:      { flex:1, fontSize:13, fontWeight:'bold', color:theme.text, marginRight:8 },
    riskBadge:    { paddingHorizontal:9, paddingVertical:4, borderRadius:20 },
    riskBadgeText:{ color:'#fff', fontSize:12, fontWeight:'bold' },
    scanBottom:   { flexDirection:'row', alignItems:'center', gap:6 },
    statusDot:    { width:7, height:7, borderRadius:4 },
    statusText:   { fontSize:12, fontWeight:'600' },
    sep:          { color:theme.border, fontSize:12 },
    dateText:     { fontSize:12, color:theme.textMuted },
    sevRow:       { flexDirection:'row', gap:6, flexWrap:'wrap', marginTop:6 },
    sevBadge:     { paddingHorizontal:7, paddingVertical:2, borderRadius:5, borderWidth:1 },
    sevBadgeText: { fontSize:9, fontWeight:'bold', letterSpacing:0.5 },
    empty:        { alignItems:'center', paddingTop:60 },
    emptyText:    { fontSize:16, fontWeight:'bold', color:theme.textSecondary },
    emptySubtext: { fontSize:13, color:theme.textMuted, textAlign:'center', marginTop:6 },
    center:       { flex:1, justifyContent:'center', alignItems:'center', paddingTop:60 },
  });

  return (
    <View style={s.container}>
      {/* Search */}
      <View style={s.searchRow}>
        <TextInput style={s.searchInput} placeholder="Search by URL…" placeholderTextColor={theme.textMuted}
          value={search} onChangeText={setSearch} autoCapitalize="none"/>
        {hasFilters && (
          <TouchableOpacity style={s.clearBtn} onPress={() => { setSearch(''); setStatusFilter('all'); setRiskFilter('all'); }}>
            <Text style={s.clearBtnText}>Clear</Text>
          </TouchableOpacity>
        )}
      </View>

      {/* Status pills */}
      <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={s.pillRow}>
        {STATUS_FILTERS.map(f => (
          <TouchableOpacity key={f} style={[s.pill,
            { backgroundColor: statusFilter===f ? statusColor(f) : theme.card, borderColor: statusFilter===f ? statusColor(f) : theme.border }]}
            onPress={() => setStatusFilter(f)}>
            <Text style={[s.pillText, { color: statusFilter===f ? theme.card : theme.textSecondary }]}>
              {f.toUpperCase()}
            </Text>
          </TouchableOpacity>
        ))}
      </ScrollView>

      {/* Risk pills */}
      <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={[s.pillRow, { paddingTop:0 }]}>
        {RISK_FILTERS.map(f => (
          <TouchableOpacity key={f.value} style={[s.pill,
            { backgroundColor: riskFilter===f.value ? theme.accent : theme.card, borderColor: riskFilter===f.value ? theme.accent : theme.border }]}
            onPress={() => setRiskFilter(f.value)}>
            <Text style={[s.pillText, { color: riskFilter===f.value ? theme.card : theme.textSecondary }]}>
              {f.label}
            </Text>
          </TouchableOpacity>
        ))}
      </ScrollView>

      {/* Compare bar */}
      {selectedIds.length > 0 && (
        <View style={s.compareBar}>
          <Text style={s.compareBarText}>
            {selectedIds.length === 1 ? '1 selected — tap another to compare' : '2 selected — ready!'}
          </Text>
          <View style={s.compareBarBtns}>
            <TouchableOpacity style={s.cmpBtn} onPress={() => setSelectedIds([])}>
              <Text style={s.cmpBtnText}>Clear</Text>
            </TouchableOpacity>
            {selectedIds.length === 2 && (
              <TouchableOpacity style={s.cmpGoBtn}
                onPress={() => { navigation.navigate('Compare', { scan1Id: selectedIds[0], scan2Id: selectedIds[1] }); setSelectedIds([]); }}>
                <Text style={s.cmpGoBtnText}>Compare →</Text>
              </TouchableOpacity>
            )}
          </View>
        </View>
      )}

      <View style={s.resultRow}>
        <Text style={s.resultText}>{loading ? 'Loading…' : `${scans.length} scan${scans.length!==1?'s':''} found`}</Text>
        <Text style={s.hintText}>Tap → open · Long press → select</Text>
      </View>

      {loading ? (
        <View style={s.center}><ActivityIndicator size="large" color={theme.accent}/></View>
      ) : (
        <ScrollView refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => { setRefreshing(true); loadScans(); }} tintColor={theme.accent}/>}>
          {scans.length === 0 ? (
            <View style={s.empty}>
              <Text style={s.emptyText}>No scans found</Text>
              <Text style={s.emptySubtext}>{hasFilters ? 'Try changing your filters' : 'Start a new scan to see results here'}</Text>
            </View>
          ) : scans.map(scan => {
            const id       = getId(scan);
            const selected = selectedIds.includes(id);
            const disabled = selectedIds.length === 2 && !selected;
            const sc       = scan.severity_counts || {};
            return (
              <TouchableOpacity key={id}
                style={[s.scanCard, { borderColor: theme.border, borderLeftColor: statusColor(scan.status) },
                  selected && s.scanCardSel, disabled && { opacity:0.4 }]}
                onPress={() => selectedIds.length > 0 ? toggleSelect(id) : navigation.navigate('ScanProgress', { scanId: id })}
                onLongPress={() => toggleSelect(id)}>
                {selected && (
                  <View style={[s.selBadge, { backgroundColor: theme.accent }]}>
                    <Text style={s.selBadgeText}>{selectedIds.indexOf(id)+1}</Text>
                  </View>
                )}
                <View style={s.scanRow}>
                  <Text style={s.scanUrl} numberOfLines={1}>{scan.target_url || scan.target}</Text>
                  <View style={[s.riskBadge, { backgroundColor: riskColor(scan.total_risk_score) }]}>
                    <Text style={s.riskBadgeText}>{scan.total_risk_score?.toFixed(1)||'0.0'}</Text>
                  </View>
                </View>
                <View style={s.scanBottom}>
                  <View style={[s.statusDot, { backgroundColor: statusColor(scan.status) }]}/>
                  <Text style={[s.statusText, { color: statusColor(scan.status) }]}>{scan.status?.toUpperCase()}</Text>
                  <Text style={s.sep}>·</Text>
                  <Text style={s.dateText}>{scan.created_at ? new Date(scan.created_at).toLocaleDateString() : ''}</Text>
                </View>
                {scan.status === 'completed' && (
                  <View style={s.sevRow}>
                    {['critical','high','medium','low'].map(sv => (sc[sv]>0) && (
                      <View key={sv} style={[s.sevBadge, { backgroundColor:theme[sv+'Bg'], borderColor:theme[sv+'Border'] }]}>
                        <Text style={[s.sevBadgeText, { color:theme[sv] }]}>{sc[sv]} {sv}</Text>
                      </View>
                    ))}
                  </View>
                )}
              </TouchableOpacity>
            );
          })}
          <View style={{ height:20 }}/>
        </ScrollView>
      )}
    </View>
  );
}