import React, { useState } from 'react';
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

  // ÉTAT CENTRALISÉ DES LOGS PARTAGÉ ENTRE LES COMPOSANTS GRAPHICK WORKFLOW
  const [logs, setLogs] = useState(initialLogs);

  const [rules, setRules] = useState(initialRules);

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
    /* CORRIGÉ : Ajout de [.light_&]:bg-slate-200 et [.light_&]:text-slate-900 pour la structure globale */
    <div className="flex h-screen w-screen bg-[#0b0f19] [.light_&]:bg-slate-200 text-gray-100 [.light_&]:text-slate-900 overflow-hidden font-mono selection:bg-emerald-500/20">
      
      {/* Barre latérale de navigation granulaire (Filtrage RBAC des 11 sous-pages) */}
      <Sidebar 
        activeView={activeView} 
        setActiveView={setActiveView} 
        user={user} 
        onLogout={() => {
          localStorage.removeItem('role');
          setUser(null);
        }} 
      />
      
      {/* Contenu de la page active */}
      {/* CORRIGÉ : Ajout de [.light_&]:bg-slate-50 pour blanchir la zone centrale principale */}
      <main className="flex-1 h-full overflow-y-auto p-8 lg:p-10 bg-[#090d1a] [.light_&]:bg-slate-50">
        {renderView()}
      </main>

    </div>
  );
}