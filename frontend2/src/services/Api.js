// ============================================================
// api.js — Base API configuration
// All services import from here — never hardcode URLs elsewhere
// ============================================================

const API_BASE_URL = import.meta.env.VITE_API_URL || "https://localhost:8000";

// ── Token management ──────────────────────────────────────
export const getToken = () => localStorage.getItem("siem_token");
export const setToken = (token) => localStorage.setItem("siem_token", token);
export const removeToken = () => localStorage.removeItem("siem_token");
export const getRole = () => localStorage.getItem("siem_role");
export const setRole = (role) => localStorage.setItem("siem_role", role);
export const removeRole = () => localStorage.removeItem("siem_role");

// ── Base fetch function ───────────────────────────────────
// All API calls go through this function
// It automatically adds the Authorization header and handles errors
export async function apiCall(endpoint, options = {}) {
  const token = getToken();

  const defaultHeaders = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  const config = {
    ...options,
    headers: {
      ...defaultHeaders,
      ...options.headers,
    },
  };

  const response = await fetch(`${API_BASE_URL}${endpoint}`, config);

  // Token expired or invalid — redirect to login
  if (response.status === 401) {
    removeToken();
    removeRole();
    window.location.href = "/login";
    return;
  }

  // Access denied — wrong role
  if (response.status === 403) {
    throw new Error("Access denied. You do not have permission for this action.");
  }

  // Any other error
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `HTTP error ${response.status}`);
  }

  return response.json();
}
