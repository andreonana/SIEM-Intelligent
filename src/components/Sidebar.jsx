import React, { useState, useEffect } from 'react';

/**
 * COMPOSANT : Sidebar (Navigation Granulaire Multi-Pages — Version Soutenance Jury Élargie)
 */
export default function Sidebar({ activeView, setActiveView, user, onLogout }) {
  const currentRole = user?.role; // 'reader' | 'analyst' | 'administrator'

  // --- LOGIQUE DE THÈME (DARK / LIGHT MODE) ---
  const [isLightMode, setIsLightMode] = useState(() => {
    return localStorage.getItem('theme') === 'light';
  });

  useEffect(() => {
    const root = window.document.documentElement;
    if (isLightMode) {
      root.classList.add('light');
      root.classList.remove('dark');
      localStorage.setItem('theme', 'light');
    } else {
      root.classList.add('dark');
      root.classList.remove('light');
      localStorage.setItem('theme', 'dark');
    }
  }, [isLightMode]);

  // Structure complète avec icônes textuelles monochromes
  const menuSections = [
    {
      title: "OVERVIEW",
      roles: ['reader', 'analyst', 'administrator'],
      items: [
        { id: 'dashboard', name: 'Dashboard Global', icon: '☷', allowedRoles: ['reader', 'analyst', 'administrator'] }
      ]
    },
    {
      title: "INVESTIGATION",
      roles: ['reader', 'analyst', 'administrator'], 
      items: [
        { id: 'logs', name: 'Log Explorer', icon: '⚲', allowedRoles: ['analyst', 'administrator'] },
        { id: 'alerts', name: 'Alert Triage', icon: '▲', allowedRoles: ['reader', 'analyst', 'administrator'] },
        { id: 'playbooks', name: 'Playbooks / SOAR', icon: '☍', allowedRoles: ['analyst', 'administrator'] }
      ]
    },
    {
      title: "REPORTING & COMPLIANCE",
      roles: ['reader', 'analyst', 'administrator'],
      items: [
        { id: 'crisis', name: 'Crisis Room', icon: '◆', allowedRoles: ['reader', 'analyst', 'administrator'] },
        { id: 'compliance', name: 'Compliance Dashboard', icon: '⬢', allowedRoles: ['reader', 'analyst', 'administrator'] },
        { id: 'reports', name: 'Rapports Cyber (PDF)', icon: '▼', allowedRoles: ['reader', 'analyst', 'administrator'] }
      ]
    },
    {
      title: "ADMINISTRATION",
      roles: ['analyst', 'administrator'], 
      items: [
        { id: 'roles', name: 'Gestion des Rôles (RBAC)', icon: '⑆', allowedRoles: ['administrator'] },
        { id: 'rules', name: 'Rule Management', icon: '❖', allowedRoles: ['analyst', 'administrator'] },
        { id: 'audit', name: 'Audit Trail', icon: '☰', allowedRoles: ['administrator'] },
        { id: 'sysconfig', name: 'Configuration Système', icon: '⚙', allowedRoles: ['administrator'] }
      ]
    }
  ];

  const allowedSections = menuSections.filter(section => section.roles.includes(currentRole));

  const getInitials = (name) => {
    if (!name) return "??";
    const words = name.split(" ");
    if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase();
    return name.slice(0, 2).toUpperCase();
  };

  return (
    /* REMPLACÉ light: PAR [.light_&]: POUR DU TAILWIND NATIF SANS CONFIGURATION COMPLEXE */
    <div className="w-76 h-full bg-[#0f172a] [.light_&]:bg-slate-100 border-r border-slate-800 [.light_&]:border-slate-300 flex flex-col justify-between p-5 transition-all duration-300 shadow-xl select-none shrink-0 text-slate-300 [.light_&]:text-slate-800">
      <div>
        {/* Entête du SOC */}
        <div className="flex items-center gap-3.5 px-2 py-5 border-b border-slate-800/80 [.light_&]:border-slate-300 mb-6">
          <div className="relative">
            <span className="text-3xl block animate-pulse">🛡️</span>
          </div>
          <div>
            <h1 className="font-black text-xl tracking-wider text-white [.light_&]:text-slate-900 font-mono">SMART SIEM</h1>
            <p className="text-xs text-slate-500 [.light_&]:text-slate-500 font-mono tracking-widest uppercase font-bold mt-0.5">Cellule CTU</p>
          </div>
        </div>

        {/* Liste dynamique des Sections */}
        <nav className="space-y-6 overflow-y-auto max-h-[calc(100vh-250px)] pr-1 scrollbar-thin">
          {allowedSections.map((section, idx) => {
            const visibleItems = section.items.filter(item => item.allowedRoles.includes(currentRole));
            if (visibleItems.length === 0) return null;

            return (
              <div key={idx} className="space-y-2">
                <div className="text-[11px] font-mono font-black text-slate-400 [.light_&]:text-slate-500 tracking-widest px-2 uppercase opacity-80">
                  // {section.title}
                </div>
                
                <div className="space-y-1">
                  {visibleItems.map((item) => {
                    const isActive = activeView === item.id;
                    return (
                      <button
                        key={item.id}
                        onClick={() => setActiveView(item.id)}
                        className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-bold font-mono transition-all duration-200 cursor-pointer ${
                          isActive
                            ? 'bg-emerald-600 text-white shadow-md shadow-emerald-900/40 translate-x-1'
                            : 'text-slate-400 [.light_&]:text-slate-600 hover:bg-slate-800/50 [.light_&]:hover:bg-slate-200 hover:text-slate-200 [.light_&]:hover:text-slate-900'
                        }`}
                      >
                        <span className="text-xl shrink-0 font-sans font-normal tracking-normal">{item.icon}</span>
                        <span className="tracking-wide text-left block">{item.name}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </nav>
      </div>

      {/* FOOTER CONTENANT LE SWITCH ET LES INFOS DU COMPTE */}
      <div className="space-y-3 mt-4">
        
        {/* ☀️ COMMUTATEUR DE THEME INTERACTIF 🌙 */}
        <button
          onClick={() => setIsLightMode(!isLightMode)}
          className="w-full flex items-center justify-between bg-slate-950 hover:bg-slate-900/80 [.light_&]:bg-white [.light_&]:hover:bg-slate-50 border border-slate-800 [.light_&]:border-slate-300 px-3.5 py-2.5 rounded-xl text-xs font-mono font-bold transition-all duration-200 cursor-pointer text-slate-200 [.light_&]:text-slate-800 shadow-inner"
        >
          <span>{isLightMode ? " MODE CLAIR" : " MODE SOMBRE"}</span>
          <span className="text-[10px] bg-slate-800 [.light_&]:bg-slate-200 text-slate-400 [.light_&]:text-slate-600 px-1.5 py-0.5 rounded font-black uppercase">
            {isLightMode ? "Clair" : "Noir"}
          </span>
        </button>

        {/* Informations du compte connecté */}
        <div className="p-3 bg-slate-950/40 [.light_&]:bg-white rounded-xl border border-slate-900 [.light_&]:border-slate-300 flex items-center justify-between gap-2.5 shadow-sm">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="w-11 h-11 rounded-full bg-slate-800 [.light_&]:bg-slate-200 flex items-center justify-center text-sm font-mono font-black text-emerald-400 [.light_&]:text-emerald-600 border border-slate-700 [.light_&]:border-slate-300 shrink-0 uppercase">
              {getInitials(user?.name)}
            </div>
            <div className="truncate">
              <p className="text-sm font-black text-slate-200 [.light_&]:text-slate-900 truncate font-mono">{user?.name || "Opérateur"}</p>
              <p className="text-xs text-cyan-400 [.light_&]:text-cyan-600 font-mono font-bold truncate tracking-wide uppercase mt-0.5">
                [{user?.role || "Inconnu"}]
              </p>
            </div>
          </div>

          <button 
            onClick={onLogout}
            title="Fermer la session sécurisée"
            className="p-2.5 rounded-lg text-slate-400 [.light_&]:text-slate-500 hover:text-red-400 [.light_&]:hover:text-red-500 hover:bg-red-500/10 transition-all cursor-pointer text-xl font-sans"
          >
            ⎋
          </button>
        </div>
      </div>

    </div>
  );
}