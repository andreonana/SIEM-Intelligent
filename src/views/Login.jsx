import React, { useState } from 'react';

/**
 * COMPOSANT : Login / Page d'accueil Smart SIEM conforme RBAC
 * @param {Function} onLogin - Fonction de callback pour injecter l'utilisateur dans le state global (App.jsx)
 */
export default function Login({ onLogin }) {
  // États locaux pour le formulaire
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // État pour afficher/masquer proprement le mode démo/simulation destiné au jury
  const [showDemoPanel, setShowDemoPanel] = useState(false);

  /**
   * COMPTES DE TEST : Alignés STRICTEMENT sur le document de référence des rôles (RBAC)
   */
  const simulationUsers = [
    { name: "Edgar Stiles", title: "Technicien Réseau", user: "edgar", pass: "ctu2026", role: "reader" },
    { name: "Chloe O'Brian", title: "Analyste Cyber Senior", user: "chloe", pass: "ctu2026", role: "analyst" },
    { name: "Bill Buchanan", title: "Directeur de la CTU", user: "bill", pass: "ctu2026", role: "administrator" }
  ];

  /**
   * GESTIONNAIRE DE CONNEXION (CORRIGÉ : setLoading)
   */
  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true); // ✅ Correction de l'erreur ici (anciennement 'Loading')

    // Simulation d'un délai réseau de 800ms pour la présentation orale
    setTimeout(() => {
      const foundUser = simulationUsers.find(
        (u) => u.user === username.toLowerCase() && u.pass === password
      );

      if (foundUser) {
        setLoading(false);
        // On sauvegarde le rôle exact dans le localStorage
        localStorage.setItem('role', foundUser.role);
        onLogin(foundUser); // Envoi des données complètes à App.jsx
      } else {
        setLoading(false);
        setError("Authentification échouée. Signature de clé ou rôle invalide.");
      }
    }, 800);
  };

  /**
   * Raccourci de complétion automatique pour la démo devant le jury
   */
  const handleQuickLogin = (user) => {
    setUsername(user.user);
    setPassword(user.pass);
    setError('');
  };

  return (
    <div className="min-h-screen bg-[#070a13] flex flex-col lg:flex-row text-slate-100 overflow-hidden">
      
      {/* PANNEAU GAUCHE : PRÉSENTATION MAJEURE */}
      <div className="lg:w-3/5 p-10 lg:p-16 flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-slate-800/60 bg-gradient-to-br from-[#0b0f19] to-[#070a13] transition-all duration-1000 animate-in fade-in slide-in-from-left-12">
        <div>
          {/* Indicateur visuel d'activité du SOC */}
          <div className="flex items-center gap-4 mb-16">
            <div className="relative">
              <span className="text-5xl text-emerald-400 block drop-shadow-[0_0_15px_rgba(52,211,153,0.5)]">🛡️</span>
              <span className="absolute top-0 left-0 text-5xl text-emerald-400 block animate-ping opacity-30">🛡️</span>
            </div>
            <span className="font-black text-3xl tracking-widest text-white font-mono">SMART SIEM</span>
          </div>
          
          {/* Titre et description majeurs */}
          <div className="space-y-8 max-w-2xl">
            <div className="space-y-4">
              <span className="text-sm font-mono tracking-widest text-emerald-400 bg-emerald-500/10 px-4 py-2 rounded border border-emerald-500/20 uppercase shadow-[0_0_15px_rgba(52,211,153,0.1)] font-bold">
                 CELLULE CTU — SECURE ROLES GATEWAY
              </span>
              <h1 className="text-5xl lg:text-6xl font-black text-white tracking-tight leading-tight pt-3">
                Analyse de Logs & Contrôle d'Accès Basé sur les Rôles
              </h1>
            </div>
            <p className="text-slate-300 text-xl leading-relaxed font-sans">
              Le système <strong className="text-emerald-400 font-bold">Smart SIEM</strong> applique un cloisonnement strict des privilèges (RBAC). Les fonctionnalités de supervision, de réponse aux incidents (Playbooks SOAR) et d'administration système sont restreintes dynamiquement selon l'habilitation de l'opérateur connecté.
            </p>
          </div>
        </div>

        {/* Métriques Métiers Cyber réelles */}
        <div className="mt-12 grid grid-cols-3 gap-6 border-t border-slate-800/80 pt-10 delay-300 animate-in fade-in slide-in-from-bottom-6 duration-1000 fill-mode-both">
          <div className="border-l-4 border-emerald-500 pl-4">
            <span className="block text-sm font-mono text-slate-500 uppercase tracking-wider font-bold">Habilitation RBAC</span>
            <span className="text-2xl font-black text-white font-mono mt-1 block">Niveaux 1 à 3</span>
          </div>
          <div className="border-l-4 border-blue-500 pl-4">
            <span className="block text-sm font-mono text-slate-500 uppercase tracking-wider font-bold">Rafraîchissement</span>
            <span className="text-2xl font-black text-white font-mono mt-1 block">5 sec (Live)</span>
          </div>
          <div className="border-l-4 border-purple-500 pl-4">
            <span className="block text-sm font-mono text-slate-500 uppercase tracking-wider font-bold">Flux global</span>
            <span className="text-2xl font-black text-emerald-400 font-mono mt-1 block">~142k logs/h</span>
          </div>
        </div>
      </div>

      {/* PANNEAU DROIT : FORMULAIRE D'ACCÈS DU SOC */}
      <div className="lg:w-2/5 p-10 lg:p-16 flex flex-col justify-center bg-[#090d1a] transition-all duration-1000 animate-in fade-in slide-in-from-right-12">
        <div className="max-w-md w-full mx-auto space-y-10">
          
          <div className="space-y-3">
            <h2 className="text-3xl font-black text-white tracking-wide">Terminal d'Accès</h2>
            <p className="text-xs text-red-400 font-mono tracking-widest font-bold">🚨 AUTHORIZED PERSONNEL ONLY — SECURITY LEVEL REQUIRED</p>
          </div>

          {/* Erreurs d'authentification */}
          {error && (
            <div className="bg-red-500/10 border border-red-500/30 text-red-400 text-sm p-4 rounded-lg font-mono font-bold">
              [ÉCHEC DE SÉCURITÉ] : {error}
            </div>
          )}

          {/* Formulaire */}
          <form onSubmit={handleLoginSubmit} className="space-y-6">
            <div className="group">
              <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 mb-2.5 transition-colors group-hover:text-emerald-400 font-bold">
                // Matricule Opérateur
              </label>
              <input 
                type="text" 
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="ex: chloe" 
                disabled={loading}
                className="w-full bg-[#111827] border border-slate-800 rounded-lg px-4 py-4 text-base focus:outline-none focus:border-emerald-500 text-white font-mono transition-all duration-300 hover:border-slate-600 focus:ring-1 focus:ring-emerald-500/30 disabled:opacity-50"
                required
              />
            </div>

            <div className="group">
              <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 mb-2.5 transition-colors group-hover:text-emerald-400 font-bold">
                // Clé Secrète de Chiffrement
              </label>
              <input 
                type="password" 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••" 
                disabled={loading}
                className="w-full bg-[#111827] border border-slate-800 rounded-lg px-4 py-4 text-base focus:outline-none focus:border-emerald-500 text-white font-mono transition-all duration-300 hover:border-slate-600 focus:ring-1 focus:ring-emerald-500/30 disabled:opacity-50"
                required
              />
            </div>

            <button 
              type="submit" 
              disabled={loading}
              className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-black text-base py-4 px-4 rounded-lg transition-all duration-300 shadow-lg cursor-pointer flex justify-center items-center gap-2 tracking-wide"
            >
              {loading ? (
                <>
                  <span className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                  Vérification des accès privilèges...
                </>
              ) : "Initialiser la session SOC"}
            </button>
          </form>

          {/* PANNEAU DÉMO COMPTES DE TESTS RE-DESIGNÉS COMPATIBLES AVEC L'APP */}
          <div className="border-t border-slate-800/80 pt-6">
            <button 
              type="button"
              onClick={() => setShowDemoPanel(!showDemoPanel)}
              className="text-xs font-mono text-slate-400 hover:text-emerald-400 transition-colors flex items-center gap-2 font-bold uppercase tracking-wider cursor-pointer"
            >
               {showDemoPanel ? "Masquer le panneau d'injection" : "Déployer le simulateur d'habilitation (Jury)"}
            </button>
            
            {showDemoPanel && (
              <div className="grid grid-cols-1 gap-3.5 mt-4 animate-in fade-in slide-in-from-top-2 duration-300">
                {simulationUsers.map((user, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleQuickLogin(user)}
                    className="group flex justify-between items-center bg-[#111827]/60 hover:bg-[#1c263d] border border-slate-800/60 hover:border-emerald-500/40 p-4 rounded-lg text-left transition-all duration-300 cursor-pointer"
                  >
                    <div>
                      <span className="font-black text-base text-slate-100 block group-hover:text-emerald-400 transition-colors duration-300">{user.name}</span>
                      <span className="text-xs text-slate-400 font-medium mt-1 block">{user.title}</span>
                    </div>
                    <div className="text-xs font-mono font-black text-slate-300 bg-slate-800 px-3 py-2 rounded group-hover:bg-emerald-500/10 group-hover:text-emerald-400 border border-slate-700/50 tracking-wide uppercase">
                      {user.role}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>

        </div>
      </div>

    </div>
  );
}