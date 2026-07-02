// ============================================================
// authService.js — Login, logout, token management
// ============================================================

import { apiCall, setToken, setRole, removeToken, removeRole, getToken } from "./api";

// ── Login ─────────────────────────────────────────────────
// Sends username + password to the API
// Stores the token and role in localStorage
// Returns the user object { username, role }
export async function login(username, password) {
  const data = await apiCall("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

  setToken(data.access_token);
  setRole(data.role);

  return {
    username: data.username,
    role: data.role,
  };
}

// ── Logout ────────────────────────────────────────────────
export async function logout() {
  try {
    await apiCall("/api/auth/logout", { method: "POST" });
  } catch {
    // Ignore errors on logout — always clear local storage
  } finally {
    removeToken();
    removeRole();
    window.location.href = "/login";
  }
}

// ── Get current user ──────────────────────────────────────
// Reads token info from the API
// Call this on page load to check if still logged in
export async function getCurrentUser() {
  return apiCall("/api/auth/me");
}

// ── Check if logged in ────────────────────────────────────
export function isLoggedIn() {
  return !!getToken();
}

// ── MFA verification (for administrators) ────────────────
export async function verifyMfa(code) {
  return apiCall("/api/auth/mfa/verify", {
    method: "POST",
    body: JSON.stringify({ code }),
  });
}
