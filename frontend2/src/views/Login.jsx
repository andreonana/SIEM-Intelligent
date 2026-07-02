import { useState } from 'react';
import { setToken, setRole } from '../services/api';

/**
 * Login Page — Smart SIEM
 * Works in two modes:
 * 1. Simulation mode — uses hardcoded test users (for demo)
 * 2. API mode — calls real backend when available
 */
export default function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);
  const [showDemoPanel, setShowDemoPanel] = useState(false);

  // ── Test accounts (demo / jury) ─────────────────────────
  const simulationUsers = [
    {
      name: "Edgar Stiles",
      title: "Technicien Réseau",
      user: "edgar",
      pass: "ctu2026",
      role: "reader"
    },
    {
      name: "Chloe O'Brian",
      title: "Analyste Cyber Senior",
      user: "chloe",
      pass: "ctu2026",
      role: "analyst"
    },
    {
      name: "Bill Buchanan",
      title: "Directeur de la CTU",
      user: "bill",
      pass: "ctu2026",
      role: "administrator"
    },
  ];

  // ── Main login handler ───────────────────────────────────
  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    // Step 1 — Try real API first
    try {
      const response = await fetch(
        `${import.meta.env.VITE_API_URL || 'https://localhost:443'}/api/auth/login`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password }),
        }
      );

      if (response.ok) {
        const data = await response.json();
        // Store token and role from real API
        setToken(data.access_token);
        setRole(data.role);
        setLoading(false);
        onLogin({ name: data.username, user: username, role: data.role });
        return;
      }
    } catch  {
      // API not reachable — fall through to simulation mode
    }

    // Step 2 — Fallback to simulation mode (demo / jury)
    setTimeout(() => {
      const foundUser = simulationUsers.find(
        (u) =>
          u.user === username.toLowerCase() &&
          u.pass === password
      );

      if (foundUser) {
        // Store role in localStorage for role-based UI
        localStorage.setItem('siem_role', foundUser.role);
        setLoading(false);
        onLogin(foundUser);
      } else {
        setLoading(false);
        setError('Authentification échouée. Identifiants invalides.');
      }
    }, 800);
  };

  // ── Quick login for demo panel ───────────────────────────
  const handleQuickLogin = (user) => {
    setUsername(user.user);
    setPassword(user.pass);
    setError('');
  };




  return (
    <div className="relative min-h-screen overflow-hidden bg-[radial-gradient(circle_at_top_left,_rgba(16,185,129,0.16),_transparent_28%),radial-gradient(circle_at_bottom_right,_rgba(6,182,212,0.12),_transparent_24%),linear-gradient(135deg,_#040814_0%,_#07111f_45%,_#030611_100%)] px-4 py-4 text-slate-100 sm:px-6 lg:px-8 lg:py-6">
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute left-[-8%] top-[-10%] h-60 w-60 rounded-full bg-emerald-500/10 blur-3xl" />
        <div className="absolute bottom-[-10%] right-[-6%] h-72 w-72 rounded-full bg-cyan-500/10 blur-3xl" />
      </div>

      <div className="relative mx-auto flex min-h-[calc(100vh-2rem)] max-w-7xl flex-col overflow-hidden rounded-[32px] border border-white/10 bg-slate-950/70 shadow-[0_40px_120px_rgba(2,6,23,0.55)] backdrop-blur-xl lg:flex-row">
        <div className="flex flex-1 flex-col justify-between border-b border-white/10 bg-gradient-to-br from-slate-900/90 to-slate-950/80 p-8 lg:w-3/5 lg:border-b-0 lg:border-r lg:p-12">
          <div>
            <div className="mb-12 flex items-center gap-3">
              <div className="relative flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-emerald-400 via-emerald-500 to-cyan-500 shadow-lg shadow-emerald-500/20">
                <div className="absolute inset-1 rounded-[14px] border border-white/25" />
                <div className="relative h-5 w-5 rounded-full border-2 border-white" />
              </div>
              <span className="font-black text-3xl tracking-[0.2em] text-white font-mono">SMART SIEM</span>
            </div>

            <div className="max-w-2xl space-y-6">
              <span className="inline-flex rounded-full border border-emerald-400/20 bg-emerald-500/10 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.32em] text-emerald-400">
                Cellule CTU — Secure Roles Gateway
              </span>
              <h1 className="text-4xl font-black leading-[1.05] tracking-[-0.03em] text-white sm:text-5xl lg:text-6xl">
                Analyse de logs et contrôle d'accès à la hauteur des opérations cyber.
              </h1>
              <p className="max-w-xl text-lg leading-8 text-slate-300/90">
                Le système <span className="font-semibold text-emerald-400">Smart SIEM</span> applique un cloisonnement strict des privilèges, avec supervision, réponse aux incidents et administration système adaptées au profil de chaque opérateur.
              </p>
            </div>
          </div>

          <div className="mt-10 grid gap-4 border-t border-white/10 pt-8 sm:grid-cols-3">
            <div className="rounded-2xl border border-emerald-400/20 bg-emerald-500/10 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]">
              <p className="text-[11px] font-semibold uppercase tracking-[0.3em] text-slate-400">RBAC</p>
              <p className="mt-2 text-xl font-black text-white">Niveaux 1 à 3</p>
            </div>
            <div className="rounded-2xl border border-cyan-400/20 bg-cyan-500/10 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]">
              <p className="text-[11px] font-semibold uppercase tracking-[0.3em] text-slate-400">Rafraîchissement</p>
              <p className="mt-2 text-xl font-black text-white">5 sec (Live)</p>
            </div>
            <div className="rounded-2xl border border-purple-400/20 bg-purple-500/10 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]">
              <p className="text-[11px] font-semibold uppercase tracking-[0.3em] text-slate-400">Flux global</p>
              <p className="mt-2 text-xl font-black text-emerald-400">~142k logs/h</p>
            </div>
          </div>
        </div>

        <div className="flex flex-col justify-center bg-slate-950/70 p-8 lg:w-2/5 lg:p-12">
          <div className="mx-auto w-full max-w-md space-y-8">
            <div className="space-y-4">
              <h2 className="text-3xl font-black text-white">Authentification CTU</h2>
              <div className="rounded-2xl border border-red-500/30 bg-gradient-to-r from-red-500/10 to-red-500/5 p-4 shadow-[inset_0_1px_0_rgba(239,68,68,0.15)]">
                <p className="text-xs font-semibold uppercase tracking-[0.32em] text-red-400">Accès réservé</p>
                <p className="mt-2 text-sm font-bold text-slate-100">Seul le personnel autorisé peut accéder à ce système de surveillance critique.</p>
              </div>
            </div>

            {error && (
              <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-4 text-sm font-semibold text-red-400">
                [ÉCHEC DE SÉCURITÉ] : {error}
              </div>
            )}

            <form onSubmit={handleLoginSubmit} className="space-y-5">
              <div className="group">
                <label className="mb-2 block text-xs font-semibold uppercase tracking-[0.3em] text-slate-400 group-hover:text-emerald-400">
                  Matricule opérateur
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="ex: chloe"
                  disabled={loading}
                  className="w-full rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3.5 text-base text-white transition-all duration-300 placeholder:text-slate-500 focus:border-emerald-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 disabled:opacity-60"
                  required
                />
              </div>

              <div className="group">
                <label className="mb-2 block text-xs font-semibold uppercase tracking-[0.3em] text-slate-400 group-hover:text-emerald-400">
                  Clé secrète
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  disabled={loading}
                  className="w-full rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3.5 text-base text-white transition-all duration-300 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 disabled:opacity-60"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="flex w-full items-center justify-center gap-2 rounded-2xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-4 py-3.5 text-base font-black text-white shadow-lg shadow-emerald-500/20 transition-all duration-300 hover:translate-y-[-1px] hover:shadow-xl hover:shadow-emerald-500/25 disabled:cursor-not-allowed disabled:opacity-70"
              >
                {loading ? (
                  <>
                    <span className="h-5 w-5 animate-spin rounded-full border-2 border-white border-t-transparent"></span>
                    Vérification des accès...
                  </>
                ) : 'Initialiser la session SOC'}
              </button>
            </form>

            <div className="border-t border-white/10 pt-5">
              <button
                type="button"
                onClick={() => setShowDemoPanel(!showDemoPanel)}
                className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.3em] text-slate-400 transition-colors hover:text-emerald-400"
              >
                {showDemoPanel ? 'Masquer le panneau d’injection' : 'Déployer le simulateur d’habilitation'}
              </button>

              {showDemoPanel && (
                <div className="mt-4 grid gap-3">
                  {simulationUsers.map((user, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => handleQuickLogin(user)}
                      className="group flex items-center justify-between rounded-2xl border border-slate-800 bg-slate-900/70 p-4 text-left transition-all duration-300 hover:border-emerald-400/20 hover:bg-slate-800"
                    >
                      <div>
                        <p className="font-black text-slate-100 transition-colors group-hover:text-emerald-400">{user.name}</p>
                        <p className="mt-1 text-xs text-slate-400">{user.title}</p>
                      </div>
                      <span className="rounded-full border border-slate-700 bg-slate-800 px-3 py-1.5 text-[11px] font-black uppercase tracking-[0.2em] text-slate-300">
                        {user.role}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}