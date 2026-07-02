// ============================================================
// logService.js — Logs + forensic search
// ============================================================

import { apiCall } from "./api";

// ── Get recent logs ───────────────────────────────────────
// filters: { log_type, severity, source_ip, host, limit }
export async function getLogs(filters = {}) {
  const params = new URLSearchParams(filters).toString();
  return apiCall(`/api/logs${params ? `?${params}` : ""}`);
}

// ── Search logs (analyst + admin only) ───────────────────
// Forensic investigation search with time range
export async function searchLogs(query) {
  // query = {
  //   source_ip, username, log_type,
  //   severity, from_time, to_time
  // }
  return apiCall("/api/search", {
    method: "POST",
    body: JSON.stringify(query),
  });
}

// ── Get dashboard stats ───────────────────────────────────
// Returns counts for the 4 stat cards on the dashboard
export async function getDashboardStats() {
  return apiCall("/api/dashboard/stats");
}

// ── Get log volume per hour ───────────────────────────────
// Used for the volume chart on the dashboard
export async function getLogVolume() {
  return apiCall("/api/dashboard/log-volume");
}

// ── Get top log sources ───────────────────────────────────
// Used for the top sources table on the dashboard
export async function getTopSources() {
  return apiCall("/api/dashboard/top-sources");
}
