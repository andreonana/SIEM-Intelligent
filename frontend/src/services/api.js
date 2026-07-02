// ─── Token management ─────────────────────────────────────────────────────────
export const getToken = () => localStorage.getItem('token');
const setToken = (t) => localStorage.setItem('token', t);
export const clearToken = () => { localStorage.removeItem('token'); localStorage.removeItem('role'); };

// ─── Base fetch wrapper ───────────────────────────────────────────────────────

/**
 * Erreur distincte pour une session expirée/invalide (HTTP 401), à ne jamais
 * confondre avec une panne backend réelle. App.jsx écoute l'événement
 * 'session-expired' pour ramener l'utilisateur à l'écran de connexion avec un
 * message honnête, plutôt que d'afficher "Backend indisponible" partout.
 */
export class SessionExpiredError extends Error {}

async function req(path, opts = {}) {
  const token = getToken();
  const res = await fetch(path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    if (res.status === 401) {
      clearToken();
      window.dispatchEvent(new CustomEvent('session-expired'));
      throw new SessionExpiredError(err.detail || 'Session expirée. Veuillez vous reconnecter.');
    }
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
export async function login(username, password) {
  const data = await req('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  if (data.access_token) {
    setToken(data.access_token);
  }
  return data; // { access_token } ou { mfa_required, mfa_token }
}

export async function verifyMfa(mfaToken, code) {
  const data = await req('/api/auth/mfa/verify', {
    method: 'POST',
    body: JSON.stringify({ mfa_token: mfaToken, code }),
  });
  if (data.access_token) setToken(data.access_token);
  return data;
}

export async function logout() {
  try { await req('/api/auth/logout', { method: 'POST' }); } catch (_) {}
  clearToken();
}

// ─── Alerts ───────────────────────────────────────────────────────────────────
export async function getAlerts(params = {}) {
  const qs = new URLSearchParams({ page_size: 100, ...params }).toString();
  const data = await req(`/api/alerts?${qs}`);
  return data.alerts || [];
}

export async function acknowledgeAlert(id) {
  return req(`/api/alerts/${id}/acknowledge`, { method: 'POST' });
}

export async function resolveAlert(id, note = '') {
  return req(`/api/alerts/${id}/resolve`, {
    method: 'POST',
    body: JSON.stringify({ note }),
  });
}

export async function exportAlertsCsv(params = {}) {
  const qs = new URLSearchParams(params).toString();
  await downloadBlob(`/api/alerts/export.csv?${qs}`, { method: 'GET' }, 'smart-siem-alerts-export.csv');
}

export async function exportAlertsXlsx(params = {}) {
  const qs = new URLSearchParams(params).toString();
  await downloadBlob(`/api/alerts/export.xlsx?${qs}`, { method: 'GET' }, 'smart-siem-alerts-export.xlsx');
}

async function downloadBlob(path, opts, filename) {
  const token = getToken();
  const res = await fetch(path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(opts?.headers || {}),
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    if (res.status === 401) {
      clearToken();
      window.dispatchEvent(new CustomEvent('session-expired'));
      throw new SessionExpiredError(err.detail || 'Session expirée. Veuillez vous reconnecter.');
    }
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Logs ─────────────────────────────────────────────────────────────────────
export async function getLogs(params = {}) {
  const qs = new URLSearchParams({ page_size: 200, ...params }).toString();
  const data = await req(`/api/v1/logs?${qs}`);
  return data.logs || [];
}

export async function searchLogs(criteria = {}) {
  const data = await req('/api/search', {
    method: 'POST',
    body: JSON.stringify(criteria),
  });
  return data.logs || data.results || [];
}

export async function exportLogsCsv(criteria = {}) {
  await downloadBlob(
    '/api/search/export.csv',
    { method: 'POST', body: JSON.stringify(criteria) },
    'smart-siem-logs-export.csv',
  );
}

export async function exportLogsXlsx(criteria = {}) {
  await downloadBlob(
    '/api/search/export.xlsx',
    { method: 'POST', body: JSON.stringify(criteria) },
    'smart-siem-logs-export.xlsx',
  );
}

// ─── Rules ────────────────────────────────────────────────────────────────────
export async function getRules() {
  const data = await req('/api/rules');
  return data.rules || [];
}

export async function toggleRule(ruleId, enabled) {
  return req(`/api/rules/${ruleId}`, {
    method: 'PUT',
    body: JSON.stringify({ enabled }),
  });
}

export async function runCorrelation() {
  return req('/api/correlation/run', { method: 'POST' });
}

// ─── Playbooks ────────────────────────────────────────────────────────────────
export async function getPlaybooks() {
  const data = await req('/api/soar/playbooks');
  return data.playbooks || [];
}

export async function runPlaybook(id, params = {}) {
  return req(`/api/soar/playbooks/${id}/run`, {
    method: 'POST',
    body: JSON.stringify({ params }),
  });
}

// ─── Audit ────────────────────────────────────────────────────────────────────
export async function getAuditLogs(params = {}) {
  const qs = new URLSearchParams({ page_size: 50, ...params }).toString();
  const data = await req(`/api/audit?${qs}`);
  return data.entries || [];
}

// ─── Users ────────────────────────────────────────────────────────────────────
export async function getUsers() {
  const data = await req('/api/users');
  return data.users || [];
}

export async function createUser(payload) {
  return req('/api/users', { method: 'POST', body: JSON.stringify(payload) });
}

export async function updateUserRole(userId, role) {
  return req(`/api/users/${userId}`, {
    method: 'PUT',
    body: JSON.stringify({ role }),
  });
}

export async function updateUserActive(userId, isActive) {
  return req(`/api/users/${userId}`, {
    method: 'PUT',
    body: JSON.stringify({ is_active: isActive }),
  });
}

export async function deleteUser(userId) {
  return req(`/api/users/${userId}`, { method: 'DELETE' });
}

// ─── Health / System ──────────────────────────────────────────────────────────
export async function getHealth() {
  return req('/health');
}

export async function getSystemHealth() {
  return req('/api/system/health');
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
export async function getDashboardData() {
  return req('/api/dashboard');
}

// ─── UEBA ─────────────────────────────────────────────────────────────────────
export async function getUebaRiskScores(params = {}) {
  const qs = new URLSearchParams({ page_size: 50, ...params }).toString();
  const data = await req(`/api/ueba/risk-scores?${qs}`);
  return data.risk_scores || [];
}

export async function getUebaAnomalies(params = {}) {
  const qs = new URLSearchParams({ page_size: 50, ...params }).toString();
  const data = await req(`/api/ueba/anomalies?${qs}`);
  return data.anomalies || [];
}

export async function getEntityRisk(entityType, entityId) {
  return req(`/api/ueba/entities/${entityType}/${entityId}/risk`);
}

export async function runUebaAnalysis() {
  return req('/api/ueba/analyze', { method: 'POST' });
}

// ─── Reports ──────────────────────────────────────────────────────────────────
export async function getReportSummary(days = 7) {
  return req(`/api/reports/weekly/summary?days=${days}`);
}

export async function downloadPdfReport(days = 7) {
  await downloadBlob(
    `/api/reports/weekly?days=${days}`,
    { method: 'GET' },
    `smart-siem-report-${new Date().toISOString().slice(0, 10)}.pdf`,
  );
}

// ─── Integrity ────────────────────────────────────────────────────────────────
export async function getIntegrityBatches() {
  const data = await req('/api/integrity/batches');
  return data;
}

// ─── Data mappers (API → format mock attendu par les vues) ───────────────────

// Alerte API → format log mock utilisé par AlertTriage / PlaybooksSOAR
export function mapAlert(a) {
  // status backend réel : "open" | "in_progress" | "resolved" (voir alert_service.py).
  // "escalated" (utilisé par la Salle de crise) doit dériver de ce même champ,
  // mis à jour par acknowledgeAlert() lors du clic sur "Escalader" — surtout
  // pas de soar_status, qui ne reflète que l'exécution d'un playbook SOAR et
  // n'est jamais modifié par une escalade manuelle (c'était le bug : l'alerte
  // redevenait non-escaladée dès le rafraîchissement suivant).
  const statusMap = { open: 'ACTIF', in_progress: 'EN_COURS', resolved: 'TRAITÉ' };
  return {
    id: `ALT-${a.id}`,
    _realId: a.id,
    timestamp: a.detected_at ? a.detected_at.replace('T', ' ').slice(0, 19) : '',
    severity: a.severity,
    source: a.source_ip || 'N/A',
    destination: a.host || 'N/A',
    service: a.rule_name || 'SIEM Engine',
    event: a.description || a.title || a.rule_name,
    status: statusMap[a.status] || a.status?.toUpperCase() || 'ACTIF',
    escalated: a.status === 'in_progress',
    payload: JSON.stringify({
      rule_id: a.rule_id,
      mitre_tactic: a.mitre_tactic,
      mitre_technique: a.mitre_technique,
      confidence_score: a.confidence_score,
      soar_status: a.soar_status,
      dedupe_key: a.dedupe_key,
    }, null, 2),
    confidence_score: a.confidence_score,
    soar_status: a.soar_status,
  };
}

// Log Elasticsearch → format mock attendu par LogExplorer
export function mapLog(l) {
  return {
    id: l.id || l._id || `LOG-${Math.random().toString(36).slice(2)}`,
    timestamp: l.timestamp || l.received_at || '',
    source: l.source_ip || l.host || 'N/A',
    destination: l.host || 'N/A',
    service: l.log_type || l.source || 'system',
    event: l.message || l.raw_message || '',
    severity: (l.severity || 'INFO').toUpperCase(),
    status: 'INFO',
    payload: l.raw_message || '',
  };
}

// Règle API → format mock attendu par RuleManagement
export function mapRule(r) {
  return {
    id: r.rule_id || `RULE-${r.id}`,
    _realId: r.rule_id,
    name: r.name,
    description: r.description,
    category: r.mitre_tactic || r.rule_type || 'Detection',
    severity: r.severity,
    active: r.enabled,
    confidence_score: r.confidence_score,
    soar_mode: r.soar_mode,
    soar_action: r.soar_action,
    window_minutes: r.window_minutes,
    threshold: r.threshold,
  };
}
