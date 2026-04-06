// PATH: vulnassess-web/src/App.js
import React, { useState, useEffect } from 'react';
import './index.css';
import { ThemeProvider } from './context/ThemeContext';
import Login from './screens/Login';
import Register from './screens/Register';
import Layout from './screens/Layout';
import Dashboard from './screens/Dashboard';
import NewScan from './screens/NewScan';
import Scans from './screens/Scans';
import AIRemediation from './screens/AIRemediation';
import { Schedule, Compare, Profile, Admin } from './screens/OtherScreens';
import { AppBootSkeleton } from './screens/Skeletons';
import { api } from './api';

const PUBLIC_PATHS = new Set(['/login', '/register']);

const pathToScreen = (path, role = 'user') => {
  switch (path) {
    case '/dashboard': return 'dashboard';
    case '/new-scan': return 'new-scan';
    case '/scans': return 'scans';
    case '/schedule': return 'schedule';
    case '/compare': return 'compare';
    case '/profile': return 'profile';
    case '/admin': return role === 'admin' ? 'admin' : null;
    default: return 'dashboard';
  }
};

const screenToPath = (screen) => {
  if ((screen || '').startsWith('ai-remediation:')) return '/scans';
  switch (screen) {
    case 'dashboard': return '/dashboard';
    case 'new-scan': return '/new-scan';
    case 'scans': return '/scans';
    case 'schedule': return '/schedule';
    case 'compare': return '/compare';
    case 'profile': return '/profile';
    case 'admin': return '/admin';
    default: return '/dashboard';
  }
};

const normalizePath = (path) => {
  if (!path) return '/';
  const p = path.endsWith('/') && path.length > 1 ? path.slice(0, -1) : path;
  return p.toLowerCase();
};

export default function App() {
  const [auth, setAuth]             = useState(null);
  const [authScreen, setAuthScreen] = useState('login');
  const [screen, setScreen]         = useState('dashboard');

  useEffect(() => {
    const initialPath = normalizePath(window.location.pathname);
    api.getMe()
      .then(user => {
        if (user?.email) {
          const role = user.role || 'user';

          const targetScreen = pathToScreen(initialPath, role);
          if (!targetScreen) {
            setAuth(user);
            setScreen('dashboard');
            window.history.replaceState({}, '', '/dashboard');
            return;
          }

          setAuth(user);
          if (PUBLIC_PATHS.has(initialPath)) {
            window.history.replaceState({}, '', '/dashboard');
            setScreen('dashboard');
          } else {
            setScreen(targetScreen);
          }
        } else {
          setAuth(false);
          setAuthScreen('login');
          window.history.replaceState({}, '', '/login');
        }
      })
      .catch(() => {
        setAuth(false);
        setAuthScreen(initialPath === '/register' ? 'register' : 'login');
        if (!PUBLIC_PATHS.has(initialPath)) {
          window.history.replaceState({}, '', '/login');
        }
      });
  }, []);

  const handleLogin  = (user) => { setAuth(user); setScreen('dashboard'); };
  const handleLogout = async () => {
    await api.logout();
    setAuth(false);
    setAuthScreen('login');
    window.history.replaceState({}, '', '/login');
  };

  useEffect(() => {
    if (!auth) {
      const nextPath = authScreen === 'register' ? '/register' : '/login';
      if (normalizePath(window.location.pathname) !== nextPath) {
        window.history.replaceState({}, '', nextPath);
      }
      return;
    }
    const nextPath = screenToPath(screen);
    if (normalizePath(window.location.pathname) !== nextPath) {
      window.history.replaceState({}, '', nextPath);
    }
  }, [auth, authScreen, screen]);

  useEffect(() => {
    if (!auth || auth === null) return;
    if (screen === 'admin' && auth.role !== 'admin') {
      setScreen('dashboard');
      window.history.replaceState({}, '', '/dashboard');
    }
  }, [auth, screen]);

  if (auth === null) return (
    <ThemeProvider>
      <AppBootSkeleton />
    </ThemeProvider>
  );

  if (!auth) return (
    <ThemeProvider>
      {authScreen === 'register'
        ? <Register goLogin={() => setAuthScreen('login')} />
        : <Login onLogin={handleLogin} goRegister={() => setAuthScreen('register')} />}
    </ThemeProvider>
  );

  const renderScreen = () => {
    if (screen.startsWith('ai-remediation:')) {
      const scanId = screen.split(':')[1];
      return <AIRemediation scanId={scanId} onBack={() => setScreen('scans')} />;
    }
    switch (screen) {
      case 'dashboard': return <Dashboard setScreen={setScreen} />;
      case 'new-scan':  return <NewScan setScreen={setScreen} />;
      case 'scans':     return <Scans setScreen={setScreen} />;
      case 'schedule':  return <Schedule />;
      case 'compare':   return <Compare />;
      case 'profile':   return <Profile />;
      case 'admin':     return auth?.role === 'admin'
                               ? <Admin /> : <Dashboard setScreen={setScreen} />;
      default:          return <Dashboard setScreen={setScreen} />;
    }
  };

  return (
    <ThemeProvider>
      <Layout screen={screen} setScreen={setScreen} user={auth} onLogout={handleLogout}>
        {renderScreen()}
      </Layout>
    </ThemeProvider>
  );
}