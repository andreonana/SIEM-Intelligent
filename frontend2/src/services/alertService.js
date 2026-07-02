// ============================================================
// alertService.js — Alerts CRUD + MITRE data
// ============================================================

import { apiCall } from "./api";

// ── Get all alerts ────────────────────────────────────────
// Optional filters: { severity, status, rule_name, limit }
// Each alert includes mitre_tactic_id and mitre_technique_id
export async function getAlerts(filters = {}) {
  const params = new URLSearchParams(filters).toString();
  return apiCall(`/api/alerts${params ? `?${params}` : ""}`);
}

// ── Get one alert by ID ───────────────────────────────────
export async function getAlert(alertId) {
  return apiCall(`/api/alerts/${alertId}`);
}

// ── Acknowledge an alert (analyst + admin only) ───────────
export async function acknowledgeAlert(alertId) {
  return apiCall(`/api/alerts/${alertId}/acknowledge`, {
    method: "POST",
  });
}

// ── Change alert status ───────────────────────────────────
// status: "ouvert" | "en_cours" | "resolu"
export async function updateAlertStatus(alertId, status) {
  return apiCall(`/api/alerts/${alertId}/status`, {
    method: "PUT",
    body: JSON.stringify({ status }),
  });
}

// ── Get MITRE coverage summary ────────────────────────────
// Returns how many alerts per MITRE tactic
// Used on the dashboard MITRE coverage widget
export async function getMitreSummary() {
  return apiCall("/api/alerts/mitre-summary");
}

// ── Run a SOAR playbook on an alert (analyst + admin) ─────
// playbook: "block_ip" | "disable_account" | "escalate_admin"
export async function runPlaybook(alertId, playbook) {
  return apiCall(`/api/soar/playbooks/${playbook}/run`, {
    method: "POST",
    body: JSON.stringify({ alert_id: alertId }),
  });
}
