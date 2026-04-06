import React, { useState, useEffect } from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { ActivityIndicator, View, LogBox } from 'react-native';
import { ThemeProvider, useTheme } from './context/ThemeContext';
import { NotificationProvider } from './context/NotificationContext';
import { api } from './services/api';

import LoginScreen from './screens/LoginScreen';
import RegisterScreen from './screens/RegisterScreen';
import DashboardScreen from './screens/DashboardScreen';
import NewScanScreen from './screens/NewScanScreen';
import ScanProgressScreen from './screens/ScanProgressScreen';
import ReportScreen from './screens/ReportScreen';
import AdminScreen from './screens/AdminScreen';
import ProfileScreen from './screens/ProfileScreen';
import ScansScreen from './screens/ScansScreen';
import CompareScreen from './screens/CompareScreen';
import ScheduleScreen from './screens/ScheduleScreen';
import AIRemediationScreen from './screens/AIRemediationScreen';

const Stack = createNativeStackNavigator();

LogBox.ignoreLogs([
  'props.pointerEvents is deprecated. Use style.pointerEvents',
]);

function withAuthGuard(ScreenComponent, adminOnly = false) {
  return function GuardedScreen(props) {
    const { theme } = useTheme();
    const [allowed, setAllowed] = useState(false);

    useEffect(() => {
      let mounted = true;
      const validate = async () => {
        const token = await api.storage.get('token');
        const role = await api.storage.get('role');
        const ok = !!token && (!adminOnly || role === 'admin');

        if (!ok) {
          if (mounted) setAllowed(false);
          props.navigation.replace('Login');
          return;
        }

        if (mounted) setAllowed(true);
      };

      validate();
      const unsubscribe = props.navigation.addListener('focus', validate);
      return () => {
        mounted = false;
        unsubscribe();
      };
    }, [props.navigation]);

    if (!allowed) {
      return (
        <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center', backgroundColor: theme.bg }}>
          <ActivityIndicator size="large" color={theme.accent} />
        </View>
      );
    }

    return <ScreenComponent {...props} />;
  };
}

function AppNavigator() {
  const [ready, setReady] = useState(false);
  const [initialRoute, setInitialRoute] = useState('Login');
  const { theme } = useTheme();

  const ProtectedDashboard = withAuthGuard(DashboardScreen);
  const ProtectedNewScan = withAuthGuard(NewScanScreen);
  const ProtectedScanProgress = withAuthGuard(ScanProgressScreen);
  const ProtectedReport = withAuthGuard(ReportScreen);
  const ProtectedAdmin = withAuthGuard(AdminScreen, true);
  const ProtectedProfile = withAuthGuard(ProfileScreen);
  const ProtectedScans = withAuthGuard(ScansScreen);
  const ProtectedCompare = withAuthGuard(CompareScreen);
  const ProtectedSchedule = withAuthGuard(ScheduleScreen);
  const ProtectedAIRemediation = withAuthGuard(AIRemediationScreen);

  useEffect(() => {
    const checkToken = async () => {
      const token = await api.storage.get('token');
      if (!token) {
        setInitialRoute('Login');
        setReady(true);
        return;
      }

      try {
        const me = await api.getMe();
        if (!me?.email) {
          await api.storage.clear();
          setInitialRoute('Login');
        } else {
          setInitialRoute('Dashboard');
        }
      } catch (_) {
        await api.storage.clear();
        setInitialRoute('Login');
      }

      setReady(true);
    };
    checkToken();
  }, []);

  if (!ready) {
    return (
      <View style={{ flex: 1, justifyContent: 'center',
        alignItems: 'center', backgroundColor: theme.bg }}>
        <ActivityIndicator size="large" color={theme.blue} />
      </View>
    );
  }

  return (
    <NavigationContainer>
      <Stack.Navigator
        initialRouteName={initialRoute}
        screenOptions={{
          headerStyle: { backgroundColor: theme.header },
          headerTintColor: theme.headerText,
          headerTitleStyle: { fontWeight: 'bold' },
          contentStyle: { backgroundColor: theme.bg },
        }}
      >
        <Stack.Screen name="Login" component={LoginScreen}
          options={{ headerShown: false }} />
        <Stack.Screen name="Register" component={RegisterScreen}
          options={{ title: 'Create Account' }} />
        <Stack.Screen name="Dashboard" component={ProtectedDashboard}
          options={{ headerShown: false }} />
        <Stack.Screen name="NewScan" component={ProtectedNewScan}
          options={{ title: 'New Scan' }} />
        <Stack.Screen name="ScanProgress" component={ProtectedScanProgress}
          options={{ title: 'Scan Progress' }} />
        <Stack.Screen name="Report" component={ProtectedReport}
          options={{ title: 'Report' }} />
        <Stack.Screen name="Admin" component={ProtectedAdmin}
          options={{ title: 'Admin Panel' }} />
        <Stack.Screen name="Profile" component={ProtectedProfile}
          options={{ title: 'My Profile' }} />
        <Stack.Screen name="Scans" component={ProtectedScans}
          options={{ title: 'My Scans' }} />
        <Stack.Screen name="Compare" component={ProtectedCompare}
          options={{ title: 'Scan Comparison' }} />
        <Stack.Screen name="Schedule" component={ProtectedSchedule}
          options={{ title: 'Scheduled Scans' }} />
        <Stack.Screen name="AIRemediation" component={ProtectedAIRemediation}
          options={{ title: 'AI Remediation', headerStyle: { backgroundColor: '#1E1B4B' }, headerTintColor: '#A5B4FC' }} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <NotificationProvider>
        <AppNavigator />
      </NotificationProvider>
    </ThemeProvider>
  );
}