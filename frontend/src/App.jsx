import { useEffect, useState, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import Login from './views/Login';

import Dashboard from './views/Dashboard';
import RSSIView from './views/RSSIView';
import LogExplorer from './views/LogExplorer.jsx';
import AlertTriage from './views/AlertTriage';
import PlaybooksSOAR from './views/PlaybooksSOAR';
import CrisisRoom from './views/CrisisRoom';
import UEBA from './views/UEBA';
import Compliance from './views/Compliance';
import CyberReports from './views/CyberReports';
import RoleManagement from './views/RoleManagement.jsx';
import RuleManagement from './views/RuleManagement';
import AuditTrail from './views/AuditTrail';
import SystemConfig from './views/SystemConfig';

import { getAlerts, getLogs, getRules, mapAlert, mapLog, mapRule, logout } from './services/api';
import { getHomeViewForRole, isViewAllowedForRole } from './config/navigation';

export default function App() {
  const [user, setUser] = useState(null);
  const [activeView, setActiveView] = useState('dashboard');
  const [sessionExpiredNotice, setSessionExpiredNotice] = useState(false);
  const [isLightMode, setIsLightMode] = useState(() => {
    if (typeof window === 'undefined') return false;
    return window.localStorage.getItem('theme') === 'light';
  });

  // Aucune donnée de démarrage fictive : tableaux vides tant que l'API n'a pas répondu.
  const [logs, setLogs] = useState([]);
  const [rules, setRules] = useState([]);
  const [dataStatus, setDataStatus] = useState('loading'); // 'loading' | 'ready' | 'error'
  const [dataError, setDataError] = useState(null);

  // Session expirée/invalide (JWT expiré, backend redémarré...) : distincte
  // d'une panne backend. Ramène honnêtement à l'écran de connexion au lieu
  // d'afficher "Backend indisponible" dans chaque vue.
  useEffect(() => {
    const handleSessionExpired = () => {
      setUser(null);
      setLogs([]);
      setRules([]);
      setDataStatus('loading');
      setSessionExpiredNotice(true);
    };
    window.addEventListener('session-expired', handleSessionExpired);
    return () => window.removeEventListener('session-expired', handleSessionExpired);
  }, []);

  const loadFromApi = useCallback(async () => {
    setDataStatus((prev) => (prev === 'ready' ? 'ready' : 'loading'));
    const [apiAlerts, apiLogs, apiRules] = await Promise.allSettled([
      getAlerts(),
      getLogs(),
      getRules(),
    ]);

    const failures = [apiAlerts, apiLogs, apiRules].filter((r) => r.status === 'rejected');
    if (failures.length === 3) {
      setDataStatus('error');
      setDataError(failures[0].reason?.message || 'Backend indisponible.');
      return;
    }

    const mappedAlerts = apiAlerts.status === 'fulfilled' ? apiAlerts.value.map(mapAlert) : [];
    const mappedLogs = apiLogs.status === 'fulfilled' ? apiLogs.value.map(mapLog) : [];
    const mappedRules = apiRules.status === 'fulfilled' ? apiRules.value.map(mapRule) : [];

    setLogs([...mappedAlerts, ...mappedLogs]);
    setRules(mappedRules);
    setDataStatus('ready');
    setDataError(null);
  }, []);

  // Charge au login et rafraîchit toutes les 30 secondes
  useEffect(() => {
    if (!user) return;
    loadFromApi();
    const interval = setInterval(loadFromApi, 30000);
    return () => clearInterval(interval);
  }, [user, loadFromApi]);

  // Garde-fou RBAC : si la vue active n'est pas autorisée pour le rôle courant
  // (changement de rôle, état restauré, navigation directe), on redirige vers
  // l'interface d'atterrissage du rôle plutôt que d'afficher une vue interdite.
  useEffect(() => {
    if (!user) return;
    if (!isViewAllowedForRole(activeView, user.role)) {
      setActiveView(getHomeViewForRole(user.role));
    }
  }, [user, activeView]);

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
    setActiveView(getHomeViewForRole(loggedInUser.role));
    setSessionExpiredNotice(false);
  };

  const handleLogout = async () => {
    await logout();
    setUser(null);
    setLogs([]);
    setRules([]);
    setDataStatus('loading');
  };

  const renderView = () => {
    switch (activeView) {
      case 'dashboard':
        return <Dashboard user={user} logs={logs} dataStatus={dataStatus} dataError={dataError} />;
      case 'rssi':
        return <RSSIView user={user} logs={logs} rules={rules} />;
      case 'logs':
        return <LogExplorer user={user} logs={logs} dataStatus={dataStatus} />;
      case 'alerts':
        return <AlertTriage user={user} logs={logs} setLogs={setLogs} onRefresh={loadFromApi} dataStatus={dataStatus} />;
      case 'playbooks':
        return <PlaybooksSOAR user={user} logs={logs} setLogs={setLogs} onRefresh={loadFromApi} />;
      case 'crisis':
        return <CrisisRoom user={user} logs={logs} setLogs={setLogs} onRefresh={loadFromApi} />;
      case 'ueba':
        return <UEBA user={user} />;
      case 'compliance':
        return <Compliance user={user} logs={logs} dataStatus={dataStatus} />;
      case 'reports':
        return <CyberReports user={user} />;
      case 'roles':
        return <RoleManagement user={user} onRefresh={loadFromApi} />;
      case 'rules':
        return <RuleManagement user={user} rules={rules} setRules={setRules} onRefresh={loadFromApi} dataStatus={dataStatus} />;
      case 'audit':
        return <AuditTrail user={user} />;
      case 'sysconfig':
        return <SystemConfig user={user} />;
      default:
        return <Dashboard user={user} logs={logs} dataStatus={dataStatus} dataError={dataError} />;
    }
  };

  if (!user) {
    return <Login onLogin={handleLogin} sessionExpired={sessionExpiredNotice} />;
  }

  return (
    <div className="flex h-screen w-screen overflow-hidden" style={{ background: 'var(--surface-0)', color: 'var(--text-primary)' }}>
      <Sidebar
        activeView={activeView}
        setActiveView={setActiveView}
        user={user}
        isLightMode={isLightMode}
        setIsLightMode={setIsLightMode}
        onLogout={handleLogout}
      />
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-[1400px] px-6 py-6 lg:px-10 lg:py-8">
          {renderView()}
        </div>
      </main>
    </div>
  );
}
