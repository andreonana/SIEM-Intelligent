
/**
 * COMPOSANT : Sidebar (Navigation Granulaire Multi-Pages — Version Soutenance Jury Élargie)
 */
export default function Sidebar({ activeView, setActiveView, user, onLogout, isLightMode, setIsLightMode }) {
  const currentRole = user?.role; // 'reader' | 'analyst' | 'administrator'

  // Structure complète avec icônes textuelles monochromes
  const menuSections = [
    {
      title: "OVERVIEW",
      roles: ['reader', 'analyst', 'administrator'],
      items: [
        { id: 'dashboard', name: 'Dashboard Global', icon: '◦', allowedRoles: ['reader', 'analyst', 'administrator'] }
      ]
    },
    {
      title: "INVESTIGATION",
      roles: ['reader', 'analyst', 'administrator'], 
      items: [
        { id: 'logs', name: 'Log Explorer', icon: '◌', allowedRoles: ['reader', 'analyst', 'administrator'] },
        { id: 'alerts', name: 'Alert Triage', icon: '△', allowedRoles: ['reader', 'analyst', 'administrator'] },
        { id: 'playbooks', name: 'Playbooks / SOAR', icon: '◈', allowedRoles: ['analyst', 'administrator'] }
      ]
    },
    {
      title: "REPORTING & COMPLIANCE",
      roles: ['reader', 'analyst', 'administrator'],
      items: [
        { id: 'crisis', name: 'Crisis Room', icon: '⬡', allowedRoles: ['analyst', 'administrator'] },
        { id: 'compliance', name: 'Tableau de conformité', icon: '◼', allowedRoles: ['reader', 'analyst', 'administrator'] },
        { id: 'reports', name: 'Rapports Cyber (PDF)', icon: '▾', allowedRoles: ['reader', 'analyst', 'administrator'] }
      ]
    },
    {
      title: "ADMINISTRATION",
      roles: ['analyst', 'administrator'], 
      items: [
        { id: 'roles', name: 'Gestion des Rôles (RBAC)', icon: '⟡', allowedRoles: ['administrator'] },
        { id: 'rules', name: 'Rule Management', icon: '✦', allowedRoles: ['analyst', 'administrator'] },
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
    <aside className={`flex h-screen w-72 shrink-0 flex-col justify-between border-r px-5 py-6 shadow-[12px_0_40px_rgba(2,6,23,0.28)] backdrop-blur-xl ${isLightMode ? 'border-slate-200 bg-white/85 text-slate-900' : 'border-white/10 bg-slate-950/80 text-slate-100'}`}>
      <div>
        <div className="mb-8 flex items-center gap-3 rounded-2xl border border-emerald-400/20 bg-emerald-500/10 px-3 py-3">
          <div className="relative flex h-11 w-11 items-center justify-center rounded-2xl bg-linear-to-br from-emerald-400 via-emerald-500 to-cyan-500 shadow-lg shadow-emerald-500/20">
            <div className="absolute inset-1 rounded-[14px] border border-white/25" />
            <div className="relative h-5 w-5 rounded-full border-2 border-white" />
          </div>
          <div>
            <h1 className="font-black text-lg tracking-[0.2em] text-white font-mono">SMART SIEM</h1>
            <p className="mt-1 text-[11px] font-semibold uppercase tracking-[0.28em] text-slate-400">Cellule CTU</p>
          </div>
        </div>

        <nav className="space-y-6 overflow-y-auto pr-1 max-h-[calc(100vh-280px)]">
          {allowedSections.map((section, idx) => {
            const visibleItems = section.items.filter(item => item.allowedRoles.includes(currentRole));
            if (visibleItems.length === 0) return null;

            return (
              <div key={idx} className="space-y-2">
                <div className="px-2 text-[10px] font-black uppercase tracking-[0.35em] text-slate-500">
                  {section.title}
                </div>

                <div className="space-y-1.5">
                  {visibleItems.map((item) => {
                    const isActive = activeView === item.id;
                    return (
                      <button
                        key={item.id}
                        onClick={() => setActiveView(item.id)}
                        className={`flex w-full items-center gap-3 rounded-xl border px-3.5 py-2.5 text-left text-sm font-semibold transition-all duration-200 ${
                          isActive
                            ? 'border-emerald-400/20 bg-linear-to-r from-emerald-500/20 to-cyan-500/10 text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]'
                            : 'border-transparent text-slate-400 hover:border-white/10 hover:bg-slate-800/70 hover:text-slate-100'
                        }`}
                      >
                        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-900/80 text-base font-semibold shadow-inner">{item.icon}</span>
                        <span className="tracking-wide">{item.name}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </nav>
      </div>

      <div className="mt-4 space-y-3">
        <button
          onClick={() => setIsLightMode(!isLightMode)}
          className={`flex w-full items-center justify-between rounded-2xl border px-3.5 py-2.5 text-xs font-semibold uppercase tracking-[0.2em] transition-all duration-200 ${isLightMode ? 'border-slate-300 bg-slate-100 text-slate-700 hover:border-emerald-400/20 hover:bg-slate-200 hover:text-slate-900' : 'border-white/10 bg-slate-900/80 text-slate-300 hover:border-emerald-400/20 hover:bg-slate-800 hover:text-white'}`}
        >
          <span>{isLightMode ? 'MODE CLAIR' : 'MODE SOMBRE'}</span>
          <span className={`rounded-full px-2 py-1 text-[10px] font-black ${isLightMode ? 'bg-slate-200 text-slate-600' : 'bg-slate-800 text-slate-400'}`}>
            {isLightMode ? 'Clair' : 'Noir'}
          </span>
        </button>

        <div className={`flex items-center justify-between gap-2.5 rounded-2xl border p-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.06)] ${isLightMode ? 'border-slate-300 bg-slate-50' : 'border-white/10 bg-slate-900/70'}`}>
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full border border-emerald-400/20 bg-emerald-500/10 text-sm font-black uppercase text-emerald-400">
              {getInitials(user?.name)}
            </div>
            <div className="truncate">
              <p className="truncate text-sm font-black text-slate-100">{user?.name || 'Opérateur'}</p>
              <p className="mt-0.5 truncate text-[11px] font-semibold uppercase tracking-[0.2em] text-cyan-400">
                [{user?.role || 'Inconnu'}]
              </p>
            </div>
          </div>

          <button
            onClick={onLogout}
            title="Fermer la session sécurisée"
            className="rounded-xl p-2.5 text-xl text-slate-400 transition-all hover:bg-red-500/10 hover:text-red-400"
          >
            ⎋
          </button>
        </div>
      </div>
    </aside>
  );
}