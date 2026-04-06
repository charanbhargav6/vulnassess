// PATH: vulnassess-app/screens/ProfileScreen.js
import React, { useState, useEffect } from 'react';
import { View, Text, TextInput, TouchableOpacity, ScrollView, ActivityIndicator, Alert, Modal } from 'react-native';
import { api } from '../services/api';
import { useTheme } from '../context/ThemeContext';

const PLAN_CONFIG = {
  monthly: {
    label: 'Monthly',
    price: 5.0,
    suffix: '/month',
    description: 'Best for active monthly scanning',
    bullets: ['AI fixes for completed scans', 'Priority remediation formatting'],
  },
  yearly: {
    label: 'Yearly',
    price: 50.0,
    suffix: '/year',
    description: 'Best value for continuous security programs',
    bullets: ['Discounted annual billing', 'Long-term subscription validity'],
  },
};

const FX_RATES = {
  USD: 1,
  INR: 83,
};

const detectRegionalCurrency = () => {
  try {
    const locale = (Intl.DateTimeFormat().resolvedOptions().locale || '').toUpperCase();
    return /(?:-|_)IN\b/.test(locale) ? 'INR' : 'USD';
  } catch (_) {
    return 'USD';
  }
};

const convertUsdToCurrency = (usdAmount, currency) => {
  const rate = FX_RATES[currency] || 1;
  return Number((Number(usdAmount || 0) * rate).toFixed(2));
};

const formatMoney = (amount, currency) => {
  const value = Number(amount || 0).toFixed(2);
  return currency === 'INR' ? `₹${value}` : `$${value}`;
};

export default function ProfileScreen({ navigation }) {
  const { theme, isDark, toggleTheme } = useTheme();
  const [profile,         setProfile]         = useState(null);
  const [loading,         setLoading]          = useState(true);
  const [fullName,        setFullName]         = useState('');
  const [savingName,      setSavingName]       = useState(false);
  const [currPass,        setCurrPass]         = useState('');
  const [newPass,         setNewPass]          = useState('');
  const [confirmPass,     setConfirmPass]      = useState('');
  const [changingPass,    setChangingPass]     = useState(false);
  const [passErr,         setPassErr]          = useState('');
  const [passOk,          setPassOk]           = useState('');
  const [showDelModal,    setShowDelModal]     = useState(false);
  const [delPass,         setDelPass]          = useState('');
  const [delErr,          setDelErr]           = useState('');
  const [deleting,        setDeleting]         = useState(false);
  const [subscription,    setSubscription]     = useState(null);
  const [plan,            setPlan]             = useState('monthly');
  const [paymentMethod,   setPaymentMethod]    = useState('upi');
  const [upiId,           setUpiId]            = useState('');
  const [cardLast4,       setCardLast4]        = useState('');
  const [cryptoNetwork,   setCryptoNetwork]    = useState('');
  const [cryptoWallet,    setCryptoWallet]     = useState('');
  const [displayCurrency, setDisplayCurrency]  = useState('USD');
  const [txId,            setTxId]             = useState('');
  const [receiptUrl,      setReceiptUrl]       = useState('');
  const [subMsg,          setSubMsg]           = useState('');

  useEffect(() => {
    setDisplayCurrency(detectRegionalCurrency());
    loadProfile();
  }, []);

  useEffect(() => {
    if (displayCurrency !== 'INR' && paymentMethod === 'upi') {
      setPaymentMethod('debit_card');
    }
  }, [displayCurrency, paymentMethod]);

  const loadProfile = async () => {
    setLoading(true);
    try { const d = await api.getProfile(); setProfile(d); setFullName(d.full_name || ''); }
    catch { Alert.alert('Error', 'Failed to load profile'); }
    const sub = await api.getSubscription().catch(() => null);
    if (sub) setSubscription(sub);
    setLoading(false);
  };

  const handleSubscription = async () => {
    setSubMsg('');
    const selectedPlan = PLAN_CONFIG[plan] || PLAN_CONFIG.monthly;
    const payableAmount = convertUsdToCurrency(selectedPlan.price, displayCurrency);
    if (!txId.trim() || txId.trim().length < 8) {
      setSubMsg('Transaction ID must be at least 8 characters');
      return;
    }
    if (!receiptUrl.trim()) {
      setSubMsg('Receipt URL is required');
      return;
    }

    if (paymentMethod === 'upi' && !upiId.trim()) {
      setSubMsg('UPI ID is required for UPI payments');
      return;
    }
    if (paymentMethod === 'debit_card' && (cardLast4 || '').replace(/\D/g, '').length < 4) {
      setSubMsg('Enter valid debit card last 4 digits');
      return;
    }
    if (paymentMethod === 'crypto' && (!cryptoNetwork.trim() || !cryptoWallet.trim())) {
      setSubMsg('Crypto network and wallet are required');
      return;
    }

    const payload = {
      plan,
      amount: payableAmount,
      transaction_id: txId.trim(),
      receipt_url: receiptUrl.trim(),
      currency: displayCurrency,
      payment_method: paymentMethod,
      upi_id: paymentMethod === 'upi' ? upiId.trim() : null,
      card_last4: paymentMethod === 'debit_card' ? (cardLast4 || '').replace(/\D/g, '').slice(-4) : null,
      crypto_network: paymentMethod === 'crypto' ? cryptoNetwork.trim() : null,
      crypto_wallet: paymentMethod === 'crypto' ? cryptoWallet.trim() : null,
    };
    const res = await api.requestSubscription(payload).catch(() => null);
    if (res?.id) {
      setSubMsg(res.message || 'Payment submitted');
      setTxId('');
      setReceiptUrl('');
      setUpiId('');
      setCardLast4('');
      setCryptoNetwork('');
      setCryptoWallet('');
      const sub = await api.getSubscription().catch(() => null);
      if (sub) setSubscription(sub);
    } else {
      setSubMsg(res?.detail || 'Failed to submit payment');
    }
  };

  const handleSaveName = async () => {
    setSavingName(true);
    try {
      await api.updateProfile(fullName);
      Alert.alert('Success', 'Name updated!');
    } catch { Alert.alert('Error', 'Failed to update name'); }
    setSavingName(false);
  };

  const handleChangePass = async () => {
    setPassErr(''); setPassOk('');
    if (!currPass || !newPass || !confirmPass) { setPassErr('All fields are required'); return; }
    if (newPass !== confirmPass) { setPassErr('New passwords do not match'); return; }
    if (newPass.length < 8) { setPassErr('Password must be at least 8 characters'); return; }
    if (newPass === currPass) { setPassErr('New password must differ from current'); return; }
    setChangingPass(true);
    try {
      const data = await api.changePassword(currPass, newPass);
      if (data.message && data.message.toLowerCase().includes('changed')) {
        setPassOk('✓ Password changed successfully!');
        setCurrPass(''); setNewPass(''); setConfirmPass('');
      } else { setPassErr(data.detail || data.message || 'Failed to change password'); }
    } catch { setPassErr('Cannot connect to server'); }
    setChangingPass(false);
  };

  const handleDeleteAccount = async () => {
    setDelErr('');
    if (!delPass) { setDelErr('Enter your password'); return; }
    setDeleting(true);
    try {
      const data = await api.deleteAccount(delPass);
      if (data.message) {
        setShowDelModal(false);
        await api.storage.clear();
        Alert.alert('Account Deleted', 'Your account and all data have been permanently deleted.',
          [{ text:'OK', onPress:() => navigation.replace('Login') }]);
      } else { setDelErr(data.detail || 'Incorrect password'); }
    } catch { setDelErr('Cannot connect to server'); }
    setDeleting(false);
  };

  const s = {
    container:    { flex:1, backgroundColor:theme.bg },
    center:       { flex:1, justifyContent:'center', alignItems:'center', backgroundColor:theme.bg },
    headerCard:   { backgroundColor:theme.header, padding:28, alignItems:'center', marginBottom:14 },
    avatar:       { width:72, height:72, borderRadius:36, backgroundColor:'rgba(253,255,245,0.2)',
                    justifyContent:'center', alignItems:'center', marginBottom:10 },
    avatarText:   { fontSize:32, fontWeight:'bold', color:'#FDFFF5' },
    email:        { fontSize:16, color:'#FDFFF5', fontWeight:'600', marginBottom:8 },
    badgeRow:     { flexDirection:'row', gap:8, marginBottom:6 },
    roleBadge:    { paddingHorizontal:12, paddingVertical:4, borderRadius:20, backgroundColor:'rgba(253,255,245,0.15)' },
    roleBadgeText:{ color:'#FDFFF5', fontSize:12, fontWeight:'bold' },
    adminBadge:   { paddingHorizontal:12, paddingVertical:4, borderRadius:20, backgroundColor:'#7C3AED' },
    joinedText:   { color:'rgba(253,255,245,0.5)', fontSize:11 },
    section:      { backgroundColor:theme.card, borderRadius:14, marginHorizontal:12, marginBottom:12,
                    padding:16, borderWidth:1, borderColor:theme.border },
    sTitle:       { fontSize:12, fontWeight:'bold', color:theme.textSecondary, letterSpacing:2, marginBottom:14 },
    planGrid:     { flexDirection:'row', gap:10, marginBottom:12 },
    planCard:     { flex:1, borderRadius:12, borderWidth:1, padding:12 },
    planTitle:    { fontSize:14, fontWeight:'bold', marginBottom:4 },
    planPrice:    { fontSize:24, fontWeight:'800', marginBottom:3 },
    planDesc:     { fontSize:11, color:theme.textMuted, marginBottom:8, lineHeight:16 },
    planBullet:   { fontSize:11, color:theme.textSecondary, marginBottom:4 },
    payMethodRow: { flexDirection:'row', gap:8, marginBottom:10, flexWrap:'wrap' },
    payMethodChip:{ paddingHorizontal:12, paddingVertical:8, borderRadius:10, borderWidth:1 },
    payMethodText:{ fontSize:11, fontWeight:'700', letterSpacing:0.5 },
    tinyHint:     { fontSize:11, color:theme.textMuted, marginBottom:8 },
    statsGrid:    { flexDirection:'row', flexWrap:'wrap', gap:8 },
    statCard:     { flex:1, minWidth:'45%', backgroundColor:theme.bg, borderRadius:10, padding:14,
                    alignItems:'center', borderWidth:1, borderColor:theme.border, borderTopWidth:3 },
    statNum:      { fontSize:26, fontWeight:'bold', marginBottom:4 },
    statLabel:    { fontSize:11, color:theme.textSecondary, letterSpacing:1 },
    themeRow:     { flexDirection:'row', justifyContent:'space-between', alignItems:'center' },
    themeLabel:   { fontSize:14, fontWeight:'bold', color:theme.text },
    themeSub:     { fontSize:12, color:theme.textSecondary, marginTop:2 },
    themeBtn:     { paddingHorizontal:20, paddingVertical:10, borderRadius:10 },
    themeBtnText: { color:'#FDFFF5', fontWeight:'bold', fontSize:13 },
    label:        { fontSize:10, fontWeight:'bold', color:theme.textSecondary, letterSpacing:2, marginBottom:6, marginTop:4 },
    input:        { backgroundColor:theme.input, borderWidth:1, borderColor:theme.inputBorder,
                    borderRadius:8, padding:12, fontSize:14, color:theme.text, marginBottom:8 },
    btn:          { borderRadius:8, padding:13, alignItems:'center', marginTop:4 },
    btnPrimary:   { backgroundColor:theme.accent },
    btnDanger:    { backgroundColor:theme.danger },
    btnDisabled:  { opacity:0.5 },
    btnText:      { color:theme.card, fontWeight:'bold', fontSize:14, letterSpacing:0.5 },
    errBox:       { backgroundColor:theme.dangerBg, borderWidth:1, borderColor:theme.dangerBorder, borderRadius:8, padding:10, marginBottom:10 },
    errText:      { color:theme.danger, fontSize:12 },
    okBox:        { backgroundColor:theme.successBg, borderWidth:1, borderColor:theme.successBorder, borderRadius:8, padding:10, marginBottom:10 },
    okText:       { color:theme.success, fontSize:12 },
    dangerSection:{ backgroundColor:theme.card, borderRadius:14, marginHorizontal:12, marginBottom:12,
                    padding:16, borderWidth:2, borderColor:theme.danger },
    dangerTitle:  { fontSize:12, fontWeight:'bold', color:theme.danger, letterSpacing:2, marginBottom:8 },
    dangerDesc:   { fontSize:13, color:theme.textSecondary, lineHeight:20, marginBottom:14 },
    overlay:      { flex:1, backgroundColor:'rgba(0,0,0,0.6)', justifyContent:'center', alignItems:'center', padding:24 },
    modal:        { backgroundColor:theme.card, borderRadius:16, padding:24, width:'100%', maxWidth:380,
                    borderWidth:1, borderColor:theme.dangerBorder },
    modalTitle:   { fontSize:16, fontWeight:'bold', color:theme.danger, marginBottom:8 },
    modalDesc:    { fontSize:13, color:theme.textSecondary, marginBottom:14, lineHeight:20 },
    modalBtns:    { flexDirection:'row', gap:10, marginTop:6 },
    modalBtn:     { flex:1, padding:13, borderRadius:10, alignItems:'center' },
    modalBtnText: { fontWeight:'bold', fontSize:14 },
  };

  if (loading) return (
    <View style={s.center}>
      <ActivityIndicator size="large" color={theme.accent}/>
    </View>
  );

  const selectedPlan = PLAN_CONFIG[plan] || PLAN_CONFIG.monthly;
  const selectedDisplayAmount = convertUsdToCurrency(selectedPlan.price, displayCurrency);
  const paymentMethodOptions = displayCurrency === 'INR'
    ? [
        { key:'upi', label:'UPI' },
        { key:'debit_card', label:'DEBIT CARD' },
        { key:'crypto', label:'CRYPTO' },
      ]
    : [
        { key:'debit_card', label:'DEBIT CARD' },
        { key:'crypto', label:'CRYPTO' },
      ];

  return (
    <ScrollView style={s.container}>
      {/* Header */}
      <View style={s.headerCard}>
        <View style={s.avatar}>
          <Text style={s.avatarText}>{profile?.email?.[0]?.toUpperCase()}</Text>
        </View>
        <Text style={s.email}>{profile?.email}</Text>
        <View style={s.badgeRow}>
          <View style={profile?.role==='admin' ? s.adminBadge : s.roleBadge}>
            <Text style={s.roleBadgeText}>{profile?.role==='admin' ? '★ ADMIN' : '◆ USER'}</Text>
          </View>
          <View style={s.roleBadge}>
            <Text style={s.roleBadgeText}>{profile?.is_active ? '● ACTIVE' : '○ INACTIVE'}</Text>
          </View>
        </View>
        <Text style={s.joinedText}>Joined: {profile?.created_at ? new Date(profile.created_at).toLocaleDateString() : '—'}</Text>
      </View>

      {/* Stats */}
      <View style={s.section}>
        <Text style={s.sTitle}>SCAN STATISTICS</Text>
        <View style={s.statsGrid}>
          {[
            { value: profile?.stats?.total_scans||0,     label:'TOTAL SCANS', color:theme.accent   },
            { value: profile?.stats?.completed_scans||0, label:'COMPLETED',   color:theme.success  },
            { value: profile?.stats?.high_risk_scans||0, label:'HIGH RISK',   color:theme.critical },
            { value: profile?.scan_limit||100,            label:'SCAN LIMIT',  color:theme.high     },
          ].map((st, i) => (
            <View key={i} style={[s.statCard, { borderTopColor: st.color }]}>
              <Text style={[s.statNum, { color:st.color }]}>{st.value}</Text>
              <Text style={s.statLabel}>{st.label}</Text>
            </View>
          ))}
        </View>
      </View>

      {/* Appearance */}
      <View style={s.section}>
        <Text style={s.sTitle}>APPEARANCE</Text>
        <View style={s.themeRow}>
          <View>
            <Text style={s.themeLabel}>{isDark ? '☾ Dark Mode' : '☀ Light Mode'}</Text>
            <Text style={s.themeSub}>{isDark ? 'Currently using dark theme' : 'Currently using light theme'}</Text>
          </View>
          <TouchableOpacity style={[s.themeBtn, { backgroundColor: isDark ? theme.warning : theme.accent }]} onPress={toggleTheme}>
            <Text style={s.themeBtnText}>{isDark ? 'LIGHT' : 'DARK'}</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Display Name */}
      <View style={s.section}>
        <Text style={s.sTitle}>DISPLAY NAME</Text>
        <Text style={s.label}>FULL NAME</Text>
        <TextInput style={s.input} placeholder="Your name" placeholderTextColor={theme.textMuted}
          value={fullName} onChangeText={setFullName}/>
        <TouchableOpacity style={[s.btn, s.btnPrimary, savingName && s.btnDisabled]} onPress={handleSaveName} disabled={savingName}>
          {savingName ? <ActivityIndicator color={theme.card} size="small"/> : <Text style={s.btnText}>→ SAVE NAME</Text>}
        </TouchableOpacity>
      </View>

      <View style={s.section}>
        <Text style={s.sTitle}>AI FIX SUBSCRIPTION</Text>
        <Text style={{ color:theme.textSecondary, fontSize:12, marginBottom:8 }}>
          Status: {subscription?.subscription_status || profile?.subscription?.subscription_status || 'inactive'}
        </Text>
        {subscription?.subscription_expires_at && (
          <Text style={{ color:theme.textMuted, fontSize:11, marginBottom:10 }}>
            Expires: {new Date(subscription.subscription_expires_at).toLocaleDateString()}
          </Text>
        )}

        <Text style={s.label}>CHOOSE PLAN</Text>
        <View style={s.planGrid}>
          {Object.entries(PLAN_CONFIG).map(([key, cfg]) => {
            const active = plan === key;
            return (
              <TouchableOpacity
                key={key}
                style={[
                  s.planCard,
                  {
                    backgroundColor: active ? theme.accentMuted : theme.bg,
                    borderColor: active ? theme.accent : theme.border,
                  },
                ]}
                onPress={() => setPlan(key)}
                activeOpacity={0.9}
              >
                <Text style={[s.planTitle, { color: active ? theme.accent : theme.text }]}>{cfg.label}</Text>
                <Text style={[s.planPrice, { color: active ? theme.accent : theme.text }]}>{formatMoney(convertUsdToCurrency(cfg.price, displayCurrency), displayCurrency)}</Text>
                <Text style={s.planDesc}>{cfg.suffix} · {cfg.description}</Text>
                {cfg.bullets.map(b => <Text key={b} style={s.planBullet}>• {b}</Text>)}
              </TouchableOpacity>
            );
          })}
        </View>

        <Text style={{ color:theme.textSecondary, fontSize:12, marginBottom:8 }}>
          Selected: {selectedPlan.label} · {formatMoney(selectedDisplayAmount, displayCurrency)}{selectedPlan.suffix}
        </Text>
        <Text style={{ color:theme.textMuted, fontSize:11, marginBottom:8 }}>
          Billing currency based on your region: {displayCurrency}
          {displayCurrency === 'INR' ? ` (Base ${selectedPlan.price.toFixed(2)} USD)` : ''}
        </Text>

        <Text style={s.label}>PAYMENT METHOD</Text>
        <View style={s.payMethodRow}>
          {paymentMethodOptions.map(m => {
            const active = paymentMethod === m.key;
            return (
              <TouchableOpacity
                key={m.key}
                onPress={() => setPaymentMethod(m.key)}
                style={[
                  s.payMethodChip,
                  {
                    backgroundColor: active ? theme.accentMuted : theme.bg,
                    borderColor: active ? theme.accent : theme.border,
                  },
                ]}
              >
                <Text style={[s.payMethodText, { color: active ? theme.accent : theme.textSecondary }]}>{m.label}</Text>
              </TouchableOpacity>
            );
          })}
        </View>

        {paymentMethod === 'upi' && (
          <>
            <Text style={s.label}>UPI ID</Text>
            <TextInput style={s.input} value={upiId} onChangeText={setUpiId} placeholder="name@bank" placeholderTextColor={theme.textMuted} autoCapitalize="none" />
            <Text style={s.tinyHint}>Example: username@oksbi or username@ybl</Text>
          </>
        )}

        {paymentMethod === 'debit_card' && (
          <>
            <Text style={s.label}>DEBIT CARD LAST 4 DIGITS</Text>
            <TextInput
              style={s.input}
              value={cardLast4}
              onChangeText={(t) => setCardLast4((t || '').replace(/\D/g, '').slice(-4))}
              placeholder="1234"
              placeholderTextColor={theme.textMuted}
              keyboardType="number-pad"
              maxLength={4}
            />
            <Text style={s.tinyHint}>Card is represented by masked digits for audit trail.</Text>
          </>
        )}

        {paymentMethod === 'crypto' && (
          <>
            <Text style={s.label}>CRYPTO NETWORK</Text>
            <TextInput style={s.input} value={cryptoNetwork} onChangeText={setCryptoNetwork} placeholder="USDT-TRC20 / BTC / ETH" placeholderTextColor={theme.textMuted} autoCapitalize="none" />
            <Text style={s.label}>WALLET ADDRESS</Text>
            <TextInput style={s.input} value={cryptoWallet} onChangeText={setCryptoWallet} placeholder="Wallet address" placeholderTextColor={theme.textMuted} autoCapitalize="none" />
          </>
        )}

        <Text style={s.label}>TRANSACTION ID</Text>
        <TextInput style={s.input} value={txId} onChangeText={setTxId} placeholder="TXN123456" placeholderTextColor={theme.textMuted} />
        <Text style={s.label}>RECEIPT URL</Text>
        <TextInput style={s.input} value={receiptUrl} onChangeText={setReceiptUrl} placeholder="https://..." placeholderTextColor={theme.textMuted} autoCapitalize="none" />
        {!!subMsg && <View style={subMsg.toLowerCase().includes('failed') ? s.errBox : s.okBox}><Text style={subMsg.toLowerCase().includes('failed') ? s.errText : s.okText}>{subMsg}</Text></View>}
        <TouchableOpacity style={[s.btn, s.btnPrimary]} onPress={handleSubscription}>
          <Text style={s.btnText}>SUBMIT PAYMENT</Text>
        </TouchableOpacity>
      </View>

      {/* Change Password */}
      <View style={s.section}>
        <Text style={s.sTitle}>CHANGE PASSWORD</Text>
        {!!passErr && <View style={s.errBox}><Text style={s.errText}>⚠ {passErr}</Text></View>}
        {!!passOk  && <View style={s.okBox}><Text style={s.okText}>{passOk}</Text></View>}
        {[['CURRENT PASSWORD', currPass, setCurrPass], ['NEW PASSWORD', newPass, setNewPass], ['CONFIRM NEW PASSWORD', confirmPass, setConfirmPass]].map(([lbl, val, setter]) => (
          <View key={lbl}>
            <Text style={s.label}>{lbl}</Text>
            <TextInput style={s.input} placeholder="••••••••" placeholderTextColor={theme.textMuted}
              value={val} onChangeText={t => { setter(t); setPassErr(''); setPassOk(''); }} secureTextEntry/>
          </View>
        ))}
        <TouchableOpacity style={[s.btn, s.btnDanger, changingPass && s.btnDisabled]} onPress={handleChangePass} disabled={changingPass}>
          {changingPass ? <ActivityIndicator color="#fff" size="small"/> : <Text style={s.btnText}>→ CHANGE PASSWORD</Text>}
        </TouchableOpacity>
      </View>

      {/* Danger Zone */}
      <View style={s.dangerSection}>
        <Text style={s.dangerTitle}>⚠ DANGER ZONE</Text>
        <Text style={s.dangerDesc}>Permanently delete your account and all scan data. This action cannot be undone.</Text>
        <TouchableOpacity style={[s.btn, s.btnDanger]}
          onPress={() => Alert.alert('Delete Account', `Delete "${profile?.email}"? All data will be permanently removed.`,
            [{ text:'Cancel', style:'cancel' },
             { text:'Yes, Delete', style:'destructive', onPress:() => { setDelErr(''); setDelPass(''); setShowDelModal(true); } }])}>
          <Text style={s.btnText}>DELETE MY ACCOUNT</Text>
        </TouchableOpacity>
      </View>

      <View style={{ height:40 }}/>

      <Modal visible={showDelModal} transparent animationType="fade">
        <View style={s.overlay}>
          <View style={s.modal}>
            <Text style={s.modalTitle}>CONFIRM DELETION</Text>
            <Text style={s.modalDesc}>Enter your password to permanently delete your account and all data.</Text>
            {!!delErr && <View style={s.errBox}><Text style={s.errText}>⚠ {delErr}</Text></View>}
            <TextInput style={s.input} placeholder="Your password" placeholderTextColor={theme.textMuted}
              value={delPass} onChangeText={t=>{setDelPass(t);setDelErr('');}} secureTextEntry/>
            <View style={s.modalBtns}>
              <TouchableOpacity style={[s.modalBtn, { backgroundColor:theme.bg, borderWidth:1, borderColor:theme.border }]}
                onPress={() => { setShowDelModal(false); setDelPass(''); setDelErr(''); }}>
                <Text style={[s.modalBtnText, { color:theme.text }]}>CANCEL</Text>
              </TouchableOpacity>
              <TouchableOpacity style={[s.modalBtn, { backgroundColor:theme.danger }, deleting&&{opacity:0.5}]}
                onPress={handleDeleteAccount} disabled={deleting}>
                {deleting ? <ActivityIndicator color="#fff" size="small"/> : <Text style={[s.modalBtnText, { color:'#fff' }]}>DELETE</Text>}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </ScrollView>
  );
}