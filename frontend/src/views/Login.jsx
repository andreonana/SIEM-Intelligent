import { useState } from 'react';
import { ShieldHalf, KeyRound, LockKeyhole } from 'lucide-react';
import { login as apiLogin, verifyMfa } from '../services/api';

/**
 * Page de connexion — authentification locale + étape MFA (TOTP) le cas échéant.
 * Aucun compte de secours : uniquement des appels API réels.
 */
export default function Login({ onLogin, sessionExpired = false }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [mfaStep, setMfaStep] = useState(false);
  const [mfaToken, setMfaToken] = useState('');
  const [mfaCode, setMfaCode] = useState('');

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await apiLogin(username, password);
      if (data.mfa_required) {
        setMfaToken(data.mfa_token);
        setMfaStep(true);
        return;
      }
      const payload = JSON.parse(atob(data.access_token.split('.')[1]));
      const role = payload.role || 'reader';
      localStorage.setItem('role', role);
      const identity = payload.username || payload.sub;
      onLogin({ name: identity, user: identity, role, title: role });
    } catch (err) {
      setError(err.message || 'Identifiants invalides ou backend indisponible.');
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await verifyMfa(mfaToken, mfaCode);
      const payload = JSON.parse(atob(data.access_token.split('.')[1]));
      const role = payload.role || 'reader';
      localStorage.setItem('role', role);
      const identity = payload.username || payload.sub;
      onLogin({ name: identity, user: identity, role, title: role });
    } catch (err) {
      setError(err.message || 'Code MFA invalide.');
    } finally {
      setLoading(false);
    }
  };

  const inputStyle = {
    background: 'var(--surface-2)',
    borderColor: 'var(--border-subtle)',
    color: 'var(--text-primary)',
  };

  return (
    <div className="flex min-h-screen items-center justify-center px-4" style={{ background: 'var(--surface-0)' }}>
      <div className="grid w-full max-w-4xl overflow-hidden rounded-2xl border md:grid-cols-2" style={{ borderColor: 'var(--border-subtle)', boxShadow: 'var(--shadow-card)' }}>

        {/* Panneau de présentation */}
        <div className="hidden flex-col justify-between p-10 md:flex" style={{ background: 'var(--surface-1)' }}>
          <div>
            <div className="mb-10 flex items-center gap-2.5">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl" style={{ background: 'var(--accent)' }}>
                <ShieldHalf size={22} color="#fff" strokeWidth={2} />
              </div>
              <span className="text-lg font-semibold tracking-tight" style={{ color: 'var(--text-primary)' }}>Smart SIEM</span>
            </div>
            <h1 className="text-2xl font-semibold leading-snug tracking-tight" style={{ color: 'var(--text-primary)' }}>
              Centraliser, corréler et répondre aux menaces de sécurité en temps réel.
            </h1>
            <p className="mt-4 text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              Contrôle d'accès par rôle, authentification à double facteur et traçabilité
              complète des actions — une plateforme conçue pour les équipes SOC.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3 pt-8">
            <div className="rounded-xl border p-3.5" style={{ borderColor: 'var(--border-subtle)' }}>
              <p className="text-[11px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Contrôle d'accès</p>
              <p className="mt-1 text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>RBAC 3 niveaux</p>
            </div>
            <div className="rounded-xl border p-3.5" style={{ borderColor: 'var(--border-subtle)' }}>
              <p className="text-[11px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Double facteur</p>
              <p className="mt-1 text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>TOTP RFC 6238</p>
            </div>
          </div>
        </div>

        {/* Formulaire */}
        <div className="flex flex-col justify-center p-8 sm:p-10" style={{ background: 'var(--surface-2)' }}>
          <h2 className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
            {mfaStep ? 'Vérification en deux étapes' : 'Connexion'}
          </h2>
          <p className="mt-1 mb-6 text-sm" style={{ color: 'var(--text-secondary)' }}>
            {mfaStep ? 'Saisissez le code généré par votre application d\'authentification.' : 'Accédez à votre espace de supervision.'}
          </p>

          {sessionExpired && !error && (
            <div className="mb-5 rounded-lg border px-3.5 py-2.5 text-sm"
                 style={{ borderColor: 'var(--accent-border)', background: 'var(--accent-soft)', color: 'var(--text-secondary)' }}>
              Votre session a expiré. Veuillez vous reconnecter.
            </div>
          )}

          {error && (
            <div className="mb-5 rounded-lg border px-3.5 py-2.5 text-sm"
                 style={{ borderColor: 'rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)', color: '#fca5a5' }}>
              {error}
            </div>
          )}

          {mfaStep ? (
            <form onSubmit={handleMfaSubmit} className="space-y-4">
              <div>
                <label className="mb-1.5 block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>Code à 6 chiffres</label>
                <div className="relative">
                  <LockKeyhole size={16} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-muted)' }} />
                  <input
                    type="text" inputMode="numeric" maxLength={6} value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="000000" disabled={loading} required autoFocus
                    className="w-full rounded-lg border py-2.5 pl-10 pr-3.5 text-center text-lg tracking-[0.4em] outline-none transition-colors focus:border-[var(--accent)]"
                    style={inputStyle}
                  />
                </div>
              </div>
              <button type="submit" disabled={loading}
                className="flex w-full items-center justify-center gap-2 rounded-lg py-2.5 text-sm font-medium text-white transition-opacity disabled:opacity-60"
                style={{ background: 'var(--accent)' }}>
                {loading && <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white border-t-transparent" />}
                {loading ? 'Vérification...' : 'Valider'}
              </button>
              <button type="button" onClick={() => { setMfaStep(false); setError(''); }}
                className="w-full text-xs" style={{ color: 'var(--text-muted)' }}>
                Retour à l'identification
              </button>
            </form>
          ) : (
            <form onSubmit={handleLoginSubmit} className="space-y-4">
              <div>
                <label className="mb-1.5 block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>Nom d'utilisateur</label>
                <input
                  type="text" value={username} onChange={(e) => setUsername(e.target.value)}
                  disabled={loading} required autoFocus
                  className="w-full rounded-lg border px-3.5 py-2.5 text-sm outline-none transition-colors focus:border-[var(--accent)]"
                  style={inputStyle}
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>Mot de passe</label>
                <div className="relative">
                  <KeyRound size={15} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-muted)' }} />
                  <input
                    type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••" disabled={loading} required
                    className="w-full rounded-lg border py-2.5 pl-9 pr-3.5 text-sm outline-none transition-colors focus:border-[var(--accent)]"
                    style={inputStyle}
                  />
                </div>
              </div>
              <button type="submit" disabled={loading}
                className="flex w-full items-center justify-center gap-2 rounded-lg py-2.5 text-sm font-medium text-white transition-opacity disabled:opacity-60"
                style={{ background: 'var(--accent)' }}>
                {loading && <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white border-t-transparent" />}
                {loading ? 'Vérification...' : 'Se connecter'}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
