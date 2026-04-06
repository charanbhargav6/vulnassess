/**
 * VulnAssess — Shared API Core
 * PATH: vulnassess-web/src/apiCore.js
 */

export const BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api';

export function createApi(storage) {

  const getHeaders = async () => {
    const token = await storage.get('token');
    return {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  };

  const req = async (method, path, body) => {
    const res = await fetch(`${BASE_URL}${path}`, {
      method,
      credentials: 'include',
      headers: await getHeaders(),
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return res.json();
  };

  const get  = (path)       => req('GET',    path);
  const post = (path, body) => req('POST',   path, body);
  const put  = (path, body) => req('PUT',    path, body);
  const del  = (path, body) => req('DELETE', path, body);

  return {

    // ── Auth ──────────────────────────────────────────────────────────────────
    login: async (email, password) => {
      const normalizedEmail = (email || '').trim().toLowerCase();
      const res = await fetch(`${BASE_URL}/auth/login`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: JSON.stringify({ email: normalizedEmail, password }),
      });
      const data = await res.json();
      if (data.access_token) {
        await storage.set('role',  data.role  || 'user');
        await storage.set('email', data.email || normalizedEmail);
        if (data.scan_count != null) await storage.set('scan_count', String(data.scan_count));
        if (data.scan_limit != null) await storage.set('scan_limit', String(data.scan_limit));
      }
      return data;
    },

    register: async (email, password) => {
      const res = await fetch(`${BASE_URL}/auth/register`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: JSON.stringify({ email, password }),
      });
      return res.json();
    },

    logout: async () => {
      try { await post('/auth/logout'); } catch (_) {}
      await storage.clear();
    },

    getMe:          ()         => get('/auth/me'),
    verifyPassword: (password) => post('/auth/verify-password', { password }),
    deleteAccount:  (password) => del('/auth/delete-account',   { password }),

    // ── Scans ─────────────────────────────────────────────────────────────────
    getScans: async (filters = {}) => {
      const params = new URLSearchParams();
      if (filters.status)     params.set('status',     filters.status);
      if (filters.risk_level) params.set('risk_level', filters.risk_level);
      if (filters.date_from)  params.set('date_from',  filters.date_from);
      if (filters.date_to)    params.set('date_to',    filters.date_to);
      if (filters.search)     params.set('search',     filters.search);
      params.set('fields', filters.fields || 'target_url,status,total_risk_score,created_at,progress,current_step,total_vulnerabilities,severity_counts');
      const qs = params.toString() ? `?${params}` : '';
      return get(`/scans${qs}`);
    },

    startScan: (data) => post('/scans', {
      target_url:    data.target_url || data.target || '',
      username:      data.username      || null,
      password:      data.password      || null,
      proxy_enabled: data.proxy_enabled || false,
      proxy_url:     data.proxy_url     || null,
      proxy_type:    data.proxy_type    || 'http',
      verify_token:  data.verify_token  || null,
    }),

    verifyTarget: (target_url) => post('/scans/verify-target', { target_url }),

    // alias for mobile screens that call createScan
    createScan: (target_url, username, password, proxy_enabled, proxy_url, proxy_type) =>
      post('/scans', { target_url, username: username || null, password: password || null,
                       proxy_enabled: proxy_enabled || false, proxy_url: proxy_url || null,
                       proxy_type: proxy_type || 'http' }),

    getScan:    (id)  => get(`/scans/${id}`),
    cancelScan: (id)  => post(`/scans/${id}/cancel`),
    deleteScan: (id)  => del(`/scans/${id}`),

    deleteScanVerified: (id, password) =>
      del(`/scans/${id}/verify-delete`, { password }),

    deleteScansVerified: async (ids, password) => {
      const headers = await getHeaders();
      return Promise.all(ids.map(id =>
        fetch(`${BASE_URL}/scans/${id}/verify-delete`, {
          method: 'DELETE', credentials: 'include', headers, body: JSON.stringify({ password }),
        })
      ));
    },

    // ── Reports ───────────────────────────────────────────────────────────────
    downloadPDF: async (id) => {
      const res = await fetch(`${BASE_URL}/reports/${id}/pdf`, { credentials: 'include', headers: await getHeaders() });
      if (!res.ok) return null;
      return res.blob();
    },

    getAIRemediation: (scanId) => get(`/reports/${scanId}/ai-remediation`),

    downloadAIPDF: async (scanId) => {
      const res = await fetch(`${BASE_URL}/reports/${scanId}/ai-remediation/pdf`, { credentials: 'include', headers: await getHeaders() });
      if (!res.ok) return null;
      return res.blob();
    },

    // ── Compare ───────────────────────────────────────────────────────────────
    compareScans: (id1, id2) => get(`/compare?scan1_id=${id1}&scan2_id=${id2}`),

    // ── Modules ───────────────────────────────────────────────────────────────
    getModules:           ()             => get('/modules'),
    updateModule:         (key, enabled) => put(`/modules/${key}`,          { enabled }),
    updateModuleOrder:    (key, order)   => put(`/modules/${key}/order`,     { order }),
    restoreModuleDefaults: ()            => post('/modules/restore-defaults'),

    // ── Profile ───────────────────────────────────────────────────────────────
    getProfile:     ()                             => get('/profile'),
    updateProfile:  (full_name)                    => put('/profile', { full_name }),
    updateProxySettings: (proxy_enabled, proxy_url, proxy_type) =>
      put('/profile/proxy', { proxy_enabled, proxy_url, proxy_type }),
    changePassword: (current_password, new_password) =>
      put('/profile/change-password', { current_password, new_password }),
    getSubscription: () => get('/profile/subscription'),
    requestSubscription: (payload) => post('/profile/subscription/request', {
      plan: payload?.plan,
      amount: payload?.amount,
      currency: payload?.currency || 'USD',
      transaction_id: payload?.transaction_id,
      receipt_url: payload?.receipt_url,
      payment_method: payload?.payment_method || 'upi',
      upi_id: payload?.upi_id || null,
      card_last4: payload?.card_last4 || null,
      crypto_network: payload?.crypto_network || null,
      crypto_wallet: payload?.crypto_wallet || null,
    }),

    // ── Admin ─────────────────────────────────────────────────────────────────
    getUsers:         ()              => get('/admin/users'),
    deleteUser:       (userId)        => del(`/admin/users/${userId}`),
    updateRole:       (userId, role)  => put(`/admin/users/${userId}/role`,  { role }),
    updateUserRole:   (userId, role)  => put(`/admin/users/${userId}/role`,  { role }),
    updateScanLimit:  (userId, limit) => put(`/admin/users/${userId}/limit`, { scan_limit: limit }),
    toggleUser:       (userId)        => put(`/admin/users/${userId}/toggle`),
    getAllScans:       ()              => get('/admin/scans'),
    adminDeleteScan:  (scanId)        => del(`/admin/scans/${scanId}`),
    getAdminOverview: ()              => get('/admin/overview'),
    getAdminStats:    ()              => get('/admin/stats'),
    getStats:         ()              => get('/admin/stats'),
    getLogs:          ()              => get('/admin/logs'),
    getPayments:      ()              => get('/admin/payments'),
    autoVerifyPayment:(paymentId)     => post(`/admin/payments/${paymentId}/auto-verify`),
    updatePaymentStatus: (paymentId, status, admin_note) =>
      put(`/admin/payments/${paymentId}/status`, { status, admin_note }),

    // ── Schedules ─────────────────────────────────────────────────────────────
    getSchedules:   ()                       => get('/schedules'),
    createSchedule: (targetOrPayload, timeframe, username, password) => {
      const payload = (targetOrPayload && typeof targetOrPayload === 'object')
        ? {
            target_url: targetOrPayload.target_url || targetOrPayload.target || '',
            timeframe: targetOrPayload.timeframe || timeframe,
            username: targetOrPayload.username || null,
            password: targetOrPayload.password || null,
          }
        : {
            target_url: targetOrPayload || '',
            timeframe,
            username: username || null,
            password: password || null,
          };
      return post('/schedules', payload);
    },
    toggleSchedule: (id, is_active)          => put(`/schedules/${id}`, { is_active }),
    deleteSchedule: (id)                     => del(`/schedules/${id}`),

    // ── Storage passthrough ───────────────────────────────────────────────────
    storage,
  };
}