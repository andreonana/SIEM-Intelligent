import {
  LayoutDashboard, Gauge, SearchCode, TriangleAlert, Workflow, Radar,
  Siren, ShieldCheck, FileBarChart, KeyRound, ListChecks, ScrollText,
  Settings2, Sun, Moon, LogOut, ShieldHalf,
} from 'lucide-react';
import { MENU_SECTIONS } from '../config/navigation';

/** Icônes associées à chaque identifiant de vue (la structure/permissions
 *  proviennent de la source unique config/navigation.js). */
const ICONS = {
  dashboard: LayoutDashboard, rssi: Gauge, logs: SearchCode, alerts: TriangleAlert,
  playbooks: Workflow, ueba: Radar, crisis: Siren, compliance: ShieldCheck,
  reports: FileBarChart, roles: KeyRound, rules: ListChecks, audit: ScrollText,
  sysconfig: Settings2,
};

const ROLE_LABELS = {
  reader: 'Lecteur',
  analyst: 'Analyste',
  administrator: 'Administrateur',
};

function getInitials(name) {
  if (!name) return '??';
  const words = name.trim().split(' ');
  if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

export default function Sidebar({ activeView, setActiveView, user, onLogout, isLightMode, setIsLightMode }) {
  const role = user?.role;

  return (
    <aside
      className="flex h-screen w-64 shrink-0 flex-col justify-between border-r px-4 py-5"
      style={{ background: 'var(--surface-1)', borderColor: 'var(--border-subtle)' }}
    >
      <div className="min-h-0">
        {/* Logo / marque */}
        <div className="mb-6 flex items-center gap-2.5 px-1.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl" style={{ background: 'var(--accent)' }}>
            <ShieldHalf size={20} strokeWidth={2} color="#fff" />
          </div>
          <div className="leading-tight">
            <p className="text-sm font-semibold tracking-tight" style={{ color: 'var(--text-primary)' }}>Smart SIEM</p>
            <p className="text-[11px]" style={{ color: 'var(--text-muted)' }}>Centre d'opérations</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="max-h-[calc(100vh-220px)] space-y-5 overflow-y-auto pr-1">
          {MENU_SECTIONS.map((section) => {
            const visibleItems = section.items.filter((item) => item.allowedRoles.includes(role));
            if (visibleItems.length === 0) return null;

            return (
              <div key={section.title}>
                <p className="mb-1.5 px-2.5 text-[10px] font-semibold uppercase tracking-[0.14em]" style={{ color: 'var(--text-muted)' }}>
                  {section.title}
                </p>
                <div className="space-y-0.5">
                  {visibleItems.map((item) => {
                    const isActive = activeView === item.id;
                    const Icon = ICONS[item.id];
                    return (
                      <button
                        key={item.id}
                        onClick={() => setActiveView(item.id)}
                        aria-current={isActive ? 'page' : undefined}
                        className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm font-medium transition-colors duration-150"
                        style={
                          isActive
                            ? { background: 'var(--accent-soft)', color: 'var(--text-primary)' }
                            : { color: 'var(--text-secondary)' }
                        }
                        onMouseEnter={(e) => { if (!isActive) e.currentTarget.style.background = 'var(--surface-3)'; }}
                        onMouseLeave={(e) => { if (!isActive) e.currentTarget.style.background = 'transparent'; }}
                      >
                        <Icon size={17} strokeWidth={1.75} style={{ color: isActive ? 'var(--accent)' : 'var(--text-muted)' }} />
                        <span className="truncate">{item.name}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </nav>
      </div>

      {/* Bas de sidebar : thème + profil */}
      <div className="space-y-2 pt-3">
        <button
          onClick={() => setIsLightMode(!isLightMode)}
          className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm font-medium transition-colors duration-150"
          style={{ color: 'var(--text-secondary)' }}
          onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--surface-3)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
        >
          {isLightMode ? <Moon size={17} strokeWidth={1.75} /> : <Sun size={17} strokeWidth={1.75} />}
          {isLightMode ? 'Mode sombre' : 'Mode clair'}
        </button>

        <div className="flex items-center justify-between gap-2 rounded-lg border p-2.5" style={{ borderColor: 'var(--border-subtle)' }}>
          <div className="flex min-w-0 items-center gap-2.5">
            <div
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs font-semibold"
              style={{ background: 'var(--accent-soft)', color: 'var(--accent)' }}
            >
              {getInitials(user?.name || user?.user)}
            </div>
            <div className="min-w-0 leading-tight">
              <p className="truncate text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{user?.name || user?.user}</p>
              <p className="truncate text-[11px]" style={{ color: 'var(--text-muted)' }}>{ROLE_LABELS[role] || role}</p>
            </div>
          </div>
          <button
            onClick={onLogout}
            title="Se déconnecter"
            className="shrink-0 rounded-md p-1.5 transition-colors"
            style={{ color: 'var(--text-muted)' }}
            onMouseEnter={(e) => { e.currentTarget.style.color = '#f87171'; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-muted)'; }}
          >
            <LogOut size={16} strokeWidth={1.75} />
          </button>
        </div>
      </div>
    </aside>
  );
}
