import { useEffect, useState } from 'react';
import Sidebar from './components/Sidebar';
import Login from './views/Login'; 

// Importation des vues principales de base
import Dashboard from './views/Dashboard';
import LogExplorer from './views/LogExplorer.jsx'; 
import AlertTriage from './views/AlertTriage';    
import PlaybooksSOAR from './views/PlaybooksSOAR'; 
import CrisisRoom from './views/CrisisRoom';

// IMPORTATION DES NOUVEAUX COMPOSANTS CYBER ET CONFIGURATION DETECTÉE
import Compliance from './views/Compliance';
import CyberReports from './views/CyberReports';
import RoleManagement from './views/RoleManagement.jsx';
import RuleManagement from './views/RuleManagement';
import AuditTrail from './views/AuditTrail';
import SystemConfig from './views/SystemConfig';

// IMPORTATION DES MOCKS CENTRAUX
import initialLogs from './mocks/logs_mock.json';
import initialRules from './mocks/rules_mock.json';

export default function App() {
  // Gère l'utilisateur connecté (null = non connecté)
  const [user, setUser] = useState(null);
  
  // Gère la vue active parmi les 11 identifiants définis dans la Sidebar
  const [activeView, setActiveView] = useState('dashboard');

  const [isLightMode, setIsLightMode] = useState(() => {
    if (typeof window === 'undefined') return false;
    return window.localStorage.getItem('theme') === 'light';
  });

  // ÉTAT CENTRALISÉ DES LOGS PARTAGÉ ENTRE LES COMPOSANTS GRAPHICK WORKFLOW
  const [logs, setLogs] = useState(initialLogs);

  const [rules, setRules] = useState(initialRules);

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

  /**
   * GESTIONNAIRE DE CONNEXION ÉTENDU
   */
  const handleLogin = (loggedInUser) => {
    setUser(loggedInUser);
    // RÈGLE ABSOLUE : Tout le monde commence sur l'Overview global pour la démo
    setActiveView('dashboard'); 
  };

  /**
   * RENDER CENTRALISÉ DES 11 VUES DU SIEM (Aiguillage sécurisé avec transmission d'état)
   */
  const renderView = () => {
    switch (activeView) {
      // 1. Section OVERVIEW
      case 'dashboard': 
        return <Dashboard user={user} logs={logs} />;

      // 2. Section INVESTIGATION (Interconnectées via l'état global ⚡)
      case 'logs': 
        return <LogExplorer user={user} logs={logs} />; 
      case 'alerts': 
        return <AlertTriage user={user} logs={logs} setLogs={setLogs} />;
      case 'playbooks': 
        return <PlaybooksSOAR user={user} logs={logs} setLogs={setLogs} />;

      // 3. Section REPORTING & COMPLIANCE
      case 'crisis': 
        return <CrisisRoom user={user} logs={logs} setLogs={setLogs} />;
      case 'compliance': 
        return <Compliance user={user} logs={logs} />;
      case 'reports': 
        return <CyberReports user={user} logs={logs} rules={rules}/>;

      // 4. Section ADMINISTRATION
      case 'roles': 
        return <RoleManagement user={user} />; 
      case 'rules': 
        return <RuleManagement user={user} rules={rules} setRules={setRules} />;
      case 'audit': 
        return <AuditTrail user={user} />;
      case 'sysconfig': 
        return <SystemConfig user={user} />;

      // Sécurité par défaut
      default: 
        return <Dashboard user={user} logs={logs} />;
    }
  };

  // CONDITION : Si aucun utilisateur n'est connecté, on affiche l'écran de Login
  if (!user) {
    return <Login onLogin={handleLogin} />;
  }

  // AFFICHAGE PRINCIPAL (Une fois authentifié)
  return (
    <div className={`flex min-h-screen w-screen overflow-hidden ${isLightMode ? 'bg-[radial-gradient(circle_at_top_left,_rgba(16,185,129,0.12),_transparent_28%),linear-gradient(135deg,_#f8fafc_0%,_#f1f5f9_50%,_#e2e8f0_100%)] text-slate-900' : 'bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.10),_transparent_28%),linear-gradient(135deg,_#050816_0%,_#0b1120_50%,_#05070d_100%)] text-slate-100'}`}>
      <Sidebar 
        activeView={activeView} 
        setActiveView={setActiveView} 
        user={user} 
        isLightMode={isLightMode}
        setIsLightMode={setIsLightMode}
        onLogout={() => {
          localStorage.removeItem('role');
          setUser(null);
        }} 
      />

      <main className="flex-1 h-screen overflow-y-auto px-3 py-3 sm:px-4 sm:py-4 lg:px-6 lg:py-6">
        <div className={`min-h-full rounded-[28px] border p-4 shadow-[0_30px_90px_rgba(2,6,23,0.45)] backdrop-blur-xl sm:p-6 lg:p-8 ${isLightMode ? 'border-slate-200 bg-white/80 text-slate-900 shadow-[0_30px_90px_rgba(15,23,42,0.08)]' : 'border-white/10 bg-slate-950/60 text-slate-100 shadow-[0_30px_90px_rgba(2,6,23,0.45)]'}`}>
          {renderView()}
        </div>
      </main>
    </div>
  );
}