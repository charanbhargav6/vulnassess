import React from 'react';

export function SkeletonBlock({ height = 14, width = '100%', style = {} }) {
  return <div className="va-skeleton" style={{ height, width, ...style }} />;
}

export function DashboardSkeleton() {
  return (
    <div className="va-page fade-in">
      <div className="va-page-header">
        <div style={{ width: '60%' }}>
          <SkeletonBlock height={28} width="52%" style={{ marginBottom: 8 }} />
          <SkeletonBlock height={14} width="78%" />
        </div>
        <SkeletonBlock height={40} width={150} style={{ borderRadius: 8 }} />
      </div>

      <div className="va-stats-grid" style={{ marginBottom: 20 }}>
        {Array.from({ length: 6 }).map((_, i) => (
          <div className="va-stat-card" key={i}>
            <SkeletonBlock height={34} width={34} style={{ borderRadius: 8 }} />
            <div style={{ width: '100%' }}>
              <SkeletonBlock height={20} width="45%" style={{ marginBottom: 6 }} />
              <SkeletonBlock height={10} width="70%" />
            </div>
          </div>
        ))}
      </div>

      <div className="va-card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'grid', gap: 10 }}>
          {Array.from({ length: 5 }).map((_, i) => (
            <SkeletonBlock key={i} height={44} style={{ borderRadius: 8 }} />
          ))}
        </div>
      </div>

      <div className="va-quick-grid">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="va-card" style={{ marginBottom: 0 }}>
            <SkeletonBlock height={18} width="48%" style={{ marginBottom: 10 }} />
            <SkeletonBlock height={12} width="80%" />
          </div>
        ))}
      </div>
    </div>
  );
}

export function ProfileSkeleton() {
  return (
    <div className="va-page fade-in">
      <div className="va-page-header" style={{ marginBottom: 16 }}>
        <div style={{ width: '60%' }}>
          <SkeletonBlock height={28} width="45%" style={{ marginBottom: 8 }} />
          <SkeletonBlock height={14} width="75%" />
        </div>
      </div>
      <div className="va-two-col-grid">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="va-card" style={{ marginBottom: 0 }}>
            <SkeletonBlock height={14} width="35%" style={{ marginBottom: 14 }} />
            {Array.from({ length: 5 }).map((__, j) => (
              <SkeletonBlock key={j} height={12} width={j % 2 === 0 ? '100%' : '82%'} style={{ marginBottom: 10 }} />
            ))}
            <SkeletonBlock height={38} width="100%" style={{ borderRadius: 8, marginTop: 8 }} />
          </div>
        ))}
      </div>
    </div>
  );
}

export function TableSkeleton({ rows = 6 }) {
  return (
    <div className="va-card fade-in">
      <div style={{ display: 'grid', gap: 10 }}>
        {Array.from({ length: rows }).map((_, i) => (
          <SkeletonBlock key={i} height={42} style={{ borderRadius: 8 }} />
        ))}
      </div>
    </div>
  );
}

export function ScanCardsSkeleton({ cards = 6 }) {
  return (
    <div className="va-scan-cards fade-in">
      {Array.from({ length: cards }).map((_, i) => (
        <div key={i} className="va-scan-card">
          <SkeletonBlock height={12} width="68%" style={{ marginBottom: 10 }} />
          <SkeletonBlock height={10} width="42%" style={{ marginBottom: 12 }} />
          <SkeletonBlock height={10} width="80%" />
        </div>
      ))}
    </div>
  );
}

export function ScanDetailSkeleton() {
  return (
    <div className="va-card fade-in" style={{ marginTop: 16 }}>
      <SkeletonBlock height={22} width="55%" style={{ marginBottom: 10 }} />
      <SkeletonBlock height={12} width="38%" style={{ marginBottom: 16 }} />
      <SkeletonBlock height={6} width="100%" style={{ marginBottom: 16, borderRadius: 999 }} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: 8, marginBottom: 16 }}>
        {Array.from({ length: 5 }).map((_, i) => (
          <SkeletonBlock key={i} height={54} style={{ borderRadius: 8 }} />
        ))}
      </div>
      {Array.from({ length: 4 }).map((_, i) => (
        <SkeletonBlock key={i} height={52} style={{ marginBottom: 8, borderRadius: 8 }} />
      ))}
    </div>
  );
}

export function AppBootSkeleton() {
  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg)', padding: 20 }} className="fade-in">
      <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 16, minHeight: 'calc(100vh - 40px)' }}>
        <div className="va-card" style={{ marginBottom: 0 }}>
          <SkeletonBlock height={24} width="60%" style={{ marginBottom: 18 }} />
          {Array.from({ length: 7 }).map((_, i) => (
            <SkeletonBlock key={i} height={34} style={{ marginBottom: 8, borderRadius: 8 }} />
          ))}
        </div>
        <div>
          <div className="va-card" style={{ marginBottom: 12, padding: 14 }}>
            <SkeletonBlock height={16} width="30%" />
          </div>
          <div className="va-card" style={{ marginBottom: 0 }}>
            <SkeletonBlock height={28} width="40%" style={{ marginBottom: 8 }} />
            <SkeletonBlock height={14} width="62%" style={{ marginBottom: 18 }} />
            <div className="va-stats-grid">
              {Array.from({ length: 6 }).map((_, i) => (
                <SkeletonBlock key={i} height={64} style={{ borderRadius: 8 }} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
