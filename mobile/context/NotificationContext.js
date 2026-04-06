import React, { createContext, useContext, useState, useCallback } from 'react';
import { Animated, View, Text, TouchableOpacity, StyleSheet } from 'react-native';

const NotificationContext = createContext();

export function NotificationProvider({ children }) {
  const [notifications, setNotifications] = useState([]);
  const [toastVisible, setToastVisible] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const [toastType, setToastType] = useState('success');
  const [toastScanId, setToastScanId] = useState(null);
  const [fadeAnim] = useState(new Animated.Value(0));
  const [navigationRef, setNavigationRef] = useState(null);

  const showToast = useCallback((message, type = 'success', scanId = null) => {
    setToastMessage(message);
    setToastType(type);
    setToastScanId(scanId);
    setToastVisible(true);
    Animated.sequence([
      Animated.timing(fadeAnim, { toValue: 1, duration: 300, useNativeDriver: false }),
      Animated.delay(3500),
      Animated.timing(fadeAnim, { toValue: 0, duration: 300, useNativeDriver: false }),
    ]).start(() => setToastVisible(false));
  }, [fadeAnim]);

  const addNotification = useCallback((title, message, type = 'success', scanId = null) => {
    const notif = {
      id: Date.now().toString(),
      title,
      message,
      type,
      scanId,
      read: false,
      timestamp: new Date(),
    };
    setNotifications(prev => [notif, ...prev]);
    showToast(message, type, scanId);
  }, [showToast]);

  const markAllRead = useCallback(() => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  }, []);

  const clearAll = useCallback(() => {
    setNotifications([]);
  }, []);

  const unreadCount = notifications.filter(n => !n.read).length;

  return (
    <NotificationContext.Provider value={{
      notifications, addNotification, markAllRead,
      clearAll, unreadCount, setNavigationRef
    }}>
      {children}
      {toastVisible && (
        <Animated.View style={[
          styles.toast,
          { opacity: fadeAnim },
          toastType === 'success' ? styles.toastSuccess :
          toastType === 'error' ? styles.toastError : styles.toastInfo,
        ]}>
          <View style={styles.toastContent}>
            <Text style={styles.toastIcon}>
              {toastType === 'success' ? 'DONE' : toastType === 'error' ? 'FAIL' : 'INFO'}
            </Text>
            <Text style={styles.toastText} numberOfLines={2}>{toastMessage}</Text>
          </View>
        </Animated.View>
      )}
    </NotificationContext.Provider>
  );
}

export function useNotifications() {
  return useContext(NotificationContext);
}

const styles = StyleSheet.create({
  toast: {
    position: 'absolute',
    top: 60,
    left: 16,
    right: 16,
    borderRadius: 12,
    padding: 14,
    elevation: 10,
    zIndex: 9999,
  },
  toastSuccess: { backgroundColor: '#065F46', borderLeftWidth: 4, borderLeftColor: '#10B981' },
  toastError: { backgroundColor: '#7F1D1D', borderLeftWidth: 4, borderLeftColor: '#EF4444' },
  toastInfo: { backgroundColor: '#1E3A5F', borderLeftWidth: 4, borderLeftColor: '#3B82F6' },
  toastContent: { flexDirection: 'row', alignItems: 'center' },
  toastIcon: { color: '#fff', fontWeight: 'bold', fontSize: 11, marginRight: 10, opacity: 0.8 },
  toastText: { color: '#fff', fontSize: 14, fontWeight: '500', flex: 1 },
});