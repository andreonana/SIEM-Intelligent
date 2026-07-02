import { useEffect, useState } from 'react';
import Sidebar from './components/Sidebar';
import Login from './views/Login';
import Dashboard from './views/Dashboard';
import LogExplorer from './views/LogExplorer.jsx';
import AlertTriage from './views/AlertTriage';
import PlaybooksSOAR from './views/PlaybooksSOAR';
import CrisisRoom from './views/CrisisRoom';
import Compliance from './views/Compliance';
import CyberReports from './views/CyberReports';
import RoleManagement from './views/RoleManagement.jsx';
import RuleManagement from './views/RuleManagement';
import AuditTrail from './views/AuditTrail';
import SystemConfig from './views/SystemConfig';
import initialRules from './mocks/rules_mock.json';

// ── Real API data hook (falls back to mocks if API is down) ──
import { useAppData } from './hooks/useAppData';

export default function App() {
  const [user,        setUser]        = useState(null);
  const [activeView,  setActiveView]  = useState('dashboard');
  const [rules,       setRules]       = useState(initialRules);

  const [isLightMode, setIsLightMode] = useState(() => {
    if (typeof window === 'undefined') return false;
    return window.localStorage.getItem('theme') === 'light';
  });

  // ── Pull live data from API (or mocks if API unreachable) ──
  const { logs, setLogs, alerts, setAlerts, apiConnected } = useAppData();

  useEffect(() => {
    const root = window.document.documentElement;
    const body = window.document.body;
    root.classList.toggle('light', isLightMode);
    root.classList.toggle('dark', !isLightMode);
    root.style.colorScheme = isLightMode ? 'light' : 'dark';
    body.classList.toggle('light-theme', isLightMode);
    body.classList.toggle('dark-theme', !isLightMode);
    window.localStorage.setItem('theme', isLightMode ? 'light' : 'dark');
  }, [isLightMode]);

  const handleLogin = (loggedInUser) => {
    setUser(loggedInUser);
    setActiveView('dashboard');
  };

  const renderView = () => {
    switch (activeView) {
      case 'dashboard':
        return <Dashboard user={user} logs={logs} />;

      case 'logs':
        return <LogExplorer user={user} logs={logs} />;

      case 'alerts':
        // AlertTriage gets both logs (for mock mode) and alerts (for API mode)
        // It uses whichever has data
        return (
          <AlertTriage
            user={user}
            logs={alerts.length > 0 ? alerts : logs}
            setLogs={(updated) => {
              setAlerts(updated);
              setLogs(updated);
            }}
          />
        );

      case 'playbooks':
        return <PlaybooksSOAR user={user} logs={logs} setLogs={setLogs} />;

      case 'crisis':
        return <CrisisRoom user={user} logs={logs} setLogs={setLogs} />;

      case 'compliance':
        return <Compliance user={user} logs={logs} setActiveView={setActiveView} />;

      case 'reports':
        return <CyberReports user={user} logs={logs} rules={rules} />;

      case 'roles':
        return <RoleManagement user={user} />;

      case 'rules':
        return <RuleManagement user={user} rules={rules} setRules={setRules} />;

      case 'audit':
        return <AuditTrail user={user} />;

      case 'sysconfig':
        return <SystemConfig user={user} />;

      default:
        return <Dashboard user={user} logs={logs} />;
    }
  };

  if (!user) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div className={`flex min-h-screen w-screen overflow-hidden ${
      isLightMode
        ? 'bg-[radial-gradient(circle_at_top_left,_rgba(16,185,129,0.12),_transparent_28%),linear-gradient(135deg,_#f8fafc_0%,_#f1f5f9_50%,_#e2e8f0_100%)] text-slate-900'
        : 'bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.10),_transparent_28%),linear-gradient(135deg,_#050816_0%,_#0b1120_50%,_#05070d_100%)] text-slate-100'
    }`}>

      {/* API connection indicator — small badge top right */}
      <div className="fixed right-4 top-4 z-50">
        <span className={`rounded-full px-2 py-1 text-[10px] font-bold ${
          apiConnected
            ? 'bg-emerald-500/20 text-emerald-400'
            : 'bg-amber-500/20 text-amber-400'
        }`}>
          {apiConnected ? '● API Live' : '● Demo Mode'}
        </span>
      </div>

      <Sidebar
        activeView={activeView}
        setActiveView={setActiveView}
        user={user}
        isLightMode={isLightMode}
        setIsLightMode={setIsLightMode}
        onLogout={() => {
          localStorage.removeItem('role');
          localStorage.removeItem('siem_token');
          localStorage.removeItem('siem_role');
          setUser(null);
        }}
      />

      <main className="flex-1 h-screen overflow-y-auto px-3 py-3 sm:px-4 sm:py-4 lg:px-6 lg:py-6">
        <div className={`min-h-full rounded-[28px] border p-4 shadow-[0_30px_90px_rgba(2,6,23,0.45)] backdrop-blur-xl sm:p-6 lg:p-8 ${
          isLightMode
            ? 'border-slate-200 bg-white/80 text-slate-900 shadow-[0_30px_90px_rgba(15,23,42,0.08)]'
            : 'border-white/10 bg-slate-950/60 text-slate-100 shadow-[0_30px_90px_rgba(2,6,23,0.45)]'
        }`}>
          {renderView()}
        </div>
      </main>
    </div>
  );
}
