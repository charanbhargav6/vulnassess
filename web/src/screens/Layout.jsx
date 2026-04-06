// PATH: vulnassess-web/src/screens/Layout.jsx
import React, { useEffect, useState } from 'react';
import { useTheme } from '../context/ThemeContext';

const NAV = [
  { key:'dashboard', icon:'⊞', label:'DASHBOARD' },
  { key:'new-scan',  icon:'⊕', label:'NEW SCAN'  },
  { key:'scans',     icon:'◎', label:'MY SCANS'  },
  { key:'schedule',  icon:'◷', label:'SCHEDULES' },
  { key:'compare',   icon:'⇄', label:'COMPARE'   },
  { key:'profile',   icon:'◉', label:'PROFILE'   },
];

export default function Layout({ children, screen, setScreen, user, onLogout }) {
  const [collapsed, setCollapsed] = useState(false);
  const [isMobile, setIsMobile] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const { isDark, toggleTheme } = useTheme();
  const role = user?.role || 'user';
  const nav  = role === 'admin' ? [...NAV, { key:'admin', icon:'⚙', label:'ADMIN' }] : NAV;
  const currentNav = nav.find(n => n.key === screen) || nav[0];

  useEffect(() => {
    const media = window.matchMedia('(max-width: 980px)');
    const sync = () => {
      const mobile = media.matches;
      setIsMobile(mobile);
      if (!mobile) {
        setMobileNavOpen(false);
      }
    };

    sync();
    if (media.addEventListener) {
      media.addEventListener('change', sync);
      return () => media.removeEventListener('change', sync);
    }

    media.addListener(sync);
    return () => media.removeListener(sync);
  }, []);

  const handleSelectScreen = (nextScreen) => {
    setScreen(nextScreen);
    if (isMobile) setMobileNavOpen(false);
  };

  const sidebarStyle = isMobile
    ? { width: 260 }
    : { width: collapsed ? 64 : 220 };

  return (
    <div className="va-shell">
      {isMobile && mobileNavOpen && (
        <button
          type="button"
          className="va-mobile-nav-overlay"
          onClick={() => setMobileNavOpen(false)}
          aria-label="Close navigation menu"
        />
      )}

      {/* ── SIDEBAR ── */}
      <aside className={`va-sidebar${isMobile ? ' mobile' : ''}${mobileNavOpen ? ' open' : ''}`} style={sidebarStyle}>

        <div className="va-logo-row" onClick={() => { if (!isMobile) setCollapsed(c => !c); }}>
          <span className="va-logo-icon">⬡</span>
          {!collapsed && (
            <div>
              <div className="va-logo-text">VULNASSESS</div>
              <div className="va-logo-sub">SECURITY SCANNER</div>
            </div>
          )}
        </div>

        <nav className="va-nav">
          {nav.map(item => (
            <button
              key={item.key}
              className={`va-nav-item${screen === item.key ? ' active' : ''}`}
              onClick={() => handleSelectScreen(item.key)}
              title={collapsed ? item.label : ''}
            >
              <span className="va-nav-icon">{item.icon}</span>
              {!collapsed && <span>{item.label}</span>}
              {screen === item.key && <div className="va-nav-bar" />}
            </button>
          ))}
        </nav>

        <div className="va-sidebar-bottom">
          {!collapsed && (
            <div className="va-user-row">
              <div className="va-avatar">{(user?.email || 'U')[0].toUpperCase()}</div>
              <div style={{ overflow:'hidden' }}>
                <div className="va-user-email">{user?.email || 'Unknown User'}</div>
                <div className="va-user-role">{role === 'admin' ? '★ ADMIN' : '◆ USER'}</div>
              </div>
            </div>
          )}
          <button onClick={onLogout} className="va-logout" title="Logout">
            <span className="va-nav-icon">⏻</span>
            {!collapsed && <span>LOGOUT</span>}
          </button>
        </div>
      </aside>

      {/* ── MAIN ── */}
      <main className="va-main">
        <div className="va-topbar">
          <div style={{ display:'flex', alignItems:'center', gap:10, minWidth:0 }}>
            {isMobile && (
              <button
                type="button"
                className="va-mobile-menu-btn"
                onClick={() => setMobileNavOpen(true)}
                aria-label="Open navigation menu"
              >
                ☰
              </button>
            )}
            <span className="va-breadcrumb">
              {currentNav.icon} {currentNav.label}
            </span>
          </div>
          <div style={{ display:'flex', alignItems:'center', gap:10 }}>
            <div className="va-live-badge">
              <span className="va-live-dot" />
              LIVE
            </div>
            <button className="va-theme-toggle" onClick={toggleTheme}>
              {isDark ? '☀ LIGHT' : '☾ DARK'}
            </button>
          </div>
        </div>
        <div className="va-content">{children}</div>
      </main>
    </div>
  );
}