// PATH: vulnassess-app/screens/DashboardScreen.js
import React, { useState, useEffect } from 'react';
import {
  View, Text, FlatList, TouchableOpacity, StyleSheet,
  ActivityIndicator, RefreshControl, Modal, TextInput, Alert, Dimensions, ScrollView
} from 'react-native';
import { BarChart as GraphChart } from 'react-native-chart-kit';
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
  const [proxyEnabled, setProxyEnabled] = useState(false);
  const [proxyUrl, setProxyUrl] = useState('');
  const [proxyType, setProxyType] = useState('http');
  const [proxyMsg, setProxyMsg] = useState('');

  useEffect(() => {
    loadData();
    const unsub = navigation.addListener('focus', loadData);
    return unsub;
  }, [navigation]);

  // Poll while scans are running
  useEffect(() => {
    const hasRunning = scans.some(s => s.status === 'running' || s.status === 'pending');
    if (!hasRunning) return;
    const t = setInterval(fetchScans, 5000);
    return (
    <View style={s.container}>
      {/* Header */}
      <View style={s.header}>
        <View style={s.headerTop}>
          <View>
            <Text style={s.welcomeText}>WELCOME BACK</Text>
            <Text style={s.emailText}>{email}</Text>
            <Text style={s.roleText}>{role === \'admin\' ? \'★ ADMIN\' : \'◆ USER\'}</Text>
          </View>
          <View style={s.headerBtns}>
            <TouchableOpacity style={s.hBtn} onPress={() => { setShowNotifs(true); markAllRead(); }}>
              <Text style={s.hBtnText}>🔔{unreadCount > 0 ? \ \\ : \'\'}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={s.hBtn} onPress={toggleTheme}>
              <Text style={s.hBtnText}>{isDark ? \'☀\' : \'☾\'}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={s.hBtn} onPress={handleLogout}>
              <Text style={s.hBtnText}>Logout</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>

      <ScrollView contentContainerStyle={{ paddingBottom: 100 }}>
        <View style={{ flexDirection: \'row\', flexWrap: \'wrap\', padding: 12, gap: 8 }}>
          {[
            { label:\'TOTAL SCANS\', value:total,     color:theme.accent    },
            { label:\'COMPLETED\',   value:completed, color:theme.success   },
            { label:\'RUNNING\',     value:running,   color:theme.warning   },
            { label:\'TOTAL VULNS\', value:totalVulns,color:theme.high      },
            { label:\'CRITICAL\',    value:critical,  color:theme.critical  },
            { label:\'FAILED\',      value:failed,    color:theme.danger    },
          ].map(st => (
            <View key={st.label} style={[{ width: \'31%\', backgroundColor:theme.card, borderRadius:10, padding:12, alignItems:\'center\', borderWidth:1, borderColor:theme.border, borderTopWidth:3, borderTopColor: st.color }]}>
              <Text style={[s.statNum, { color: st.color, fontSize: 20 }]}>{st.value}</Text>
              <Text style={{ fontSize: 8, color:theme.textMuted, letterSpacing:1, textAlign:\'center\' }}>{st.label}</Text>
            </View>
          ))}
        </View>

        <View style={{ padding: 12 }}>
          <Text style={{ fontSize: 13, fontWeight: \'bold\', color: theme.textSecondary, marginBottom: 12, letterSpacing: 1 }}>SCANS & VULNERABILITIES THIS YEAR</Text>
          <View style={{ backgroundColor: theme.card, padding: 12, borderRadius: 12, borderWidth: 1, borderColor: theme.border, alignItems: \'center\' }}>
            <ScrollView horizontal showsHorizontalScrollIndicator={false}>
              <GraphChart
                data={{
                  labels: chartLabels,
                  datasets: [
                    { data: chartDatasetScans, color: (opacity = 1) => theme.accent },
                    { data: chartDatasetVulns, color: (opacity = 1) => theme.high }
                  ],
                  legend: [\'Scans\', \'Vulnerabilities\']
                }}
                width={Math.max(Dimensions.get(\'window\').width - 48, chartLabels.length * 60)}
                height={220}
                chartConfig={chartConfig}
                verticalLabelRotation={30}
                style={{ borderRadius: 8 }}
              />
            </ScrollView>
          </View>
        </View>
      </ScrollView>

      {/* Notifications panel */}
      {showNotifs && (
        <View style={s.overlay}>
          <View style={[s.notifPanel, { alignSelf: \'stretch\', width: \'100%\' }]}>
            <View style={s.notifHeader}>
              <Text style={s.notifTitle}>Notifications</Text>
              <View style={{ flexDirection:\'row\', gap:16 }}>
                <TouchableOpacity onPress={clearAll}><Text style={{ color:theme.danger, fontSize:13 }}>Clear All</Text></TouchableOpacity>
                <TouchableOpacity onPress={() => setShowNotifs(false)}><Text style={{ color:theme.accent, fontSize:13 }}>Close</Text></TouchableOpacity>        
              </View>
            </View>
            <ScrollView>
            {notifications.length === 0
              ? <Text style={{ textAlign:\'center\', padding:30, color:theme.textMuted }}>No notifications yet</Text>
              : notifications.map(n => (
                  <TouchableOpacity key={n.id}
                    style={[s.notifItem, { borderLeftColor: n.type===\'success\' ? theme.success : n.type===\'error\' ? theme.danger : theme.accent }]}
                    onPress={() => { setShowNotifs(false); if (n.scanId) navigation.navigate(\'Report\', { scanId: n.scanId }); }}>
                    <Text style={s.notifItemTitle}>{n.title}</Text>
                    <Text style={s.notifItemMsg}>{n.message}</Text>
                    <Text style={s.notifItemTime}>{new Date(n.timestamp).toLocaleTimeString()}</Text>
                  </TouchableOpacity>
                ))
            }
            </ScrollView>
          </View>
        </View>
      )}

    </View>
  );
}
