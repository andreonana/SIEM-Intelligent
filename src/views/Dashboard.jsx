import React, { useState } from 'react';
import WorldAttackMap from '../components/WorldAttackMap';

// IMPORTATION DES FLUX DE LOGS DE SIMULATION
import alertsData from '../mocks/alerts_mock.json';

export default function Dashboard({ user }) {
  // Période sélectionnée pour le filtre temporel (Démo Jury)
  const [timePeriod, setTimePeriod] = useState('24h');

  // ANALYSE STATISTIQUE DES LOGS POUR LES DIAGRAMMES
  const totalLogs = 142840;
  const criticalCount = alertsData.filter(a => a.severity === 'CRITICAL').length;
  const warningCount = alertsData.filter(a => a.severity === 'WARNING').length;
  const infoCount = alertsData.filter(a => a.severity === 'INFO' || a.status === 'FAUX_POSITIF').length;
  const totalAlerts = criticalCount + warningCount + infoCount || 1;

  // Calcul des pourcentages pour les camemberts
  const pctCritical = Math.round((criticalCount / totalAlerts) * 100);
  const pctWarning = Math.round((warningCount / totalAlerts) * 100);
  const pctInfo = Math.round((infoCount / totalAlerts) * 100);

  return (
    <div className="space-y-6 font-mono text-slate-200 [.light_&]:text-slate-800 overflow-y-auto max-h-[85vh] pr-2 animate-in fade-in duration-300">
      
      {/* 1. BARRE D'ENTÊTE AVEC FILTRE TEMPOREL */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-800/80 [.light_&]:border-slate-300 pb-5 gap-4">
        <div>
          <h2 className="text-2xl font-black text-white [.light_&]:text-slate-900 tracking-wide"> DASHBOARD OPÉRATIONNEL GLOBAL</h2>
          <p className="text-sm text-slate-400 [.light_&]:text-slate-600 mt-1">
            Console de Corrélation Tactique — Opérateur : <strong className="text-cyan-400 [.light_&]:text-cyan-700 text-base">{user?.name || "Chloe O'Brian"}</strong>
          </p>
        </div>
        
        {/* FILTRE PAR PÉRIODE */}
        <div className="flex bg-slate-950 [.light_&]:bg-white p-1.5 rounded-lg border border-slate-800 [.light_&]:border-slate-300 text-xs shadow-sm">
          {['1h', '6h', '24h', '7j'].map((period) => (
            <button
              key={period}
              onClick={() => setTimePeriod(period)}
              className={`px-4 py-2 rounded transition-all cursor-pointer font-bold uppercase tracking-wider ${
                timePeriod === period 
                  ? 'bg-cyan-600 [.light_&]:bg-cyan-700 text-white shadow-md' 
                  : 'text-slate-400 [.light_&]:text-slate-500 hover:text-slate-200 [.light_&]:hover:text-slate-900'
              }`}
            >
               {period}
            </button>
          ))}
        </div>
      </div>

      {/* 2. COMPTEURS DE PERFORMANCES CYBER (KPI CARDS) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="bg-[#0f172a] [.light_&]:bg-white border border-slate-800/80 [.light_&]:border-slate-200 p-5 rounded-xl shadow-lg">
          <span className="block text-xs text-slate-500 [.light_&]:text-slate-400 uppercase font-bold tracking-wider">// Flux Global Ingesté</span>
          <div className="text-3xl font-black text-blue-400 [.light_&]:text-blue-600 mt-2">{totalLogs.toLocaleString()}</div>
          <span className="text-xs text-slate-400 [.light_&]:text-slate-600 block mt-2">Événements bruts analysés</span>
        </div>
        
        <div className="bg-[#0f172a] [.light_&]:bg-white border border-slate-800/80 [.light_&]:border-slate-200 p-5 rounded-xl shadow-lg">
          <span className="block text-xs text-slate-500 [.light_&]:text-slate-400 uppercase font-bold tracking-wider">// Alertes Critiques Actives</span>
          <div className="text-3xl font-black text-red-500 [.light_&]:text-red-600 animate-pulse mt-2">{criticalCount} Menaces</div>
          <span className="text-xs text-red-400/80 [.light_&]:text-red-600 block mt-2 font-bold"> Action d'escalade impérative</span>
        </div>
        
        <div className="bg-[#0f172a] [.light_&]:bg-white border border-slate-800/80 [.light_&]:border-slate-200 p-5 rounded-xl shadow-lg">
          <span className="block text-xs text-slate-500 [.light_&]:text-slate-400 uppercase font-bold tracking-wider">// Incidents en Salle de Crise</span>
          <div className="text-3xl font-black text-amber-500 [.light_&]:text-amber-600 mt-2">
            {alertsData.filter(a => a.escalated === true).length} Assignés
          </div>
          <span className="text-xs text-slate-400 [.light_&]:text-slate-600 block mt-2">Pris en charge par Bill Buchanan</span>
        </div>
        
        <div className="bg-[#0f172a] [.light_&]:bg-white border border-slate-800/80 [.light_&]:border-slate-200 p-5 rounded-xl shadow-lg">
          <span className="block text-xs text-slate-500 [.light_&]:text-slate-400 uppercase font-bold tracking-wider">// Remédiations SOAR</span>
          <div className="text-3xl font-black text-emerald-400 [.light_&]:text-emerald-600 mt-2">
            {alertsData.filter(a => a.status === 'TRAITÉ').length} Clos
          </div>
          <span className="text-xs text-slate-400 [.light_&]:text-slate-600 block mt-2">Contre-mesures exécutées à 100%</span>
        </div>
      </div>

      {/* 3. L'ÉCRAN CENTRAL : LE PANNEAU GÉO + COLLECTEURS */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
        <div className="lg:col-span-3 w-full">
          <WorldAttackMap />
        </div>

        {/* LE PANNEAU DES AGENTS ET COLLECTEURS SÉCURITÉ */}
        <div className="bg-[#0f172a] [.light_&]:bg-white border border-slate-800/80 [.light_&]:border-slate-200 p-5 rounded-xl flex flex-col justify-between min-h-[520px] h-full shadow-lg">
          <div>
            <h3 className="text-xs font-black text-slate-200 [.light_&]:text-slate-800 uppercase tracking-wider border-b border-slate-900 [.light_&]:border-slate-200 pb-2">// STATUT DES COLLECTEURS (SIEM FEEDS)</h3>
            <span className="text-xs text-slate-500 block mb-4 mt-1">Inflow agents synchronisés avec le CTU Core</span>
            
            <div className="space-y-3.5">
              <div className="p-3 bg-slate-950/60 [.light_&]:bg-slate-50 rounded border border-slate-900 [.light_&]:border-slate-200 flex flex-col gap-1.5">
                <div className="flex justify-between items-center">
                  <span className="text-xs text-slate-200 [.light_&]:text-slate-800 font-bold">syslog_forwarder_linux</span>
                  <span className="text-[10px] bg-emerald-500/10 text-emerald-400 [.light_&]:text-emerald-600 px-2 py-0.5 rounded font-bold border border-emerald-500/20">ONLINE</span>
                </div>
                <div className="text-xs text-slate-400 [.light_&]:text-slate-600">Flux d'authentification SSH • 244 eps</div>
              </div>

              <div className="p-3 bg-slate-950/60 [.light_&]:bg-slate-50 rounded border border-slate-900 [.light_&]:border-slate-200 flex flex-col gap-1.5">
                <div className="flex justify-between items-center">
                  <span className="text-xs text-slate-200 [.light_&]:text-slate-800 font-bold">winlogbeat_ctu_dc01</span>
                  <span className="text-[10px] bg-emerald-500/10 text-emerald-400 [.light_&]:text-emerald-600 px-2 py-0.5 rounded font-bold border border-emerald-500/20">ONLINE</span>
                </div>
                <div className="text-xs text-slate-400 [.light_&]:text-slate-600">Contrôleur de domaine CTU • 810 eps</div>
              </div>

              <div className="p-3 bg-slate-950/60 [.light_&]:bg-slate-50 rounded border border-slate-900 [.light_&]:border-red-300 flex flex-col gap-1.5 border-red-500/30">
                <div className="flex justify-between items-center">
                  <span className="text-xs text-red-400 [.light_&]:text-red-600 font-black">aws_cloudtrail_pentagon</span>
                  <span className="text-[10px] bg-red-500/10 text-red-400 [.light_&]:text-red-600 px-2 py-0.5 rounded font-bold border border-red-500/20 animate-pulse">ATTACK</span>
                </div>
                <div className="text-xs text-red-400/90 [.light_&]:text-red-600 font-bold">Anomalie volumétrique détectée (Exfiltration)</div>
              </div>
            </div>
          </div>

          <div className="mt-4 border-t border-slate-800/60 [.light_&]:border-slate-200 pt-3.5 flex items-center justify-between text-xs">
            <span className="text-slate-500 font-bold">Intégrité Pipeline SIEM:</span>
            <span className="text-amber-400 [.light_&]:text-amber-600 font-black text-sm">94.2%</span>
          </div>
        </div>
      </div>

      {/* 4. ZONE DES GRAPHES : CAMEMBERT CYBER vs HISTOGRAMME BAR CHART */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* GRAPH 1 : LE DIAGRAMME CAMEMBERT DONUT */}
        <div className="bg-[#0f172a] [.light_&]:bg-white border border-slate-800/80 [.light_&]:border-slate-200 p-5 rounded-xl flex flex-col justify-between h-[380px] shadow-lg">
          <div>
            <h3 className="text-xs font-black text-slate-200 [.light_&]:text-slate-800 uppercase tracking-wider">// Répartition de Gravité (Camembert)</h3>
            <span className="text-xs text-slate-500 block mb-4 mt-1">Distribution proportionnelle des alertes corrélées</span>
          </div>

          <div className="flex items-center justify-center my-3 gap-6">
            <div 
              style={{
                background: `conic-gradient(
                  #ef4444 0% ${pctCritical}%, 
                  #f59e0b ${pctCritical}% ${pctCritical + pctWarning}%, 
                  #3b82f6 ${pctCritical + pctWarning}% 100%
                )`
              }}
              className="w-40 h-40 rounded-full relative shadow-2xl flex items-center justify-center border border-slate-900 [.light_&]:border-slate-200"
            >
              {/* Le centre évidé du donut s'adapte au fond d'écran */}
              <div className="w-24 h-24 rounded-full bg-[#0f172a] [.light_&]:bg-white flex flex-col items-center justify-center border border-slate-800/60 [.light_&]:border-slate-200 shadow-inner">
                <span className="text-xs text-slate-500 font-bold uppercase tracking-wider">Total</span>
                <span className="text-lg font-black text-white [.light_&]:text-slate-900">{totalAlerts}</span>
              </div>
            </div>

            {/* LÉGENDE STATISTIQUE DU CAMEMBERT */}
            <div className="space-y-3 text-xs">
              <div className="flex items-center gap-2.5">
                <span className="w-3 h-3 rounded bg-red-500 block"></span>
                <div>
                  <span className="text-slate-400 [.light_&]:text-slate-500 block font-bold">Critique</span>
                  <strong className="text-red-400 [.light_&]:text-red-600 text-sm">{pctCritical}% ({criticalCount})</strong>
                </div>
              </div>
              <div className="flex items-center gap-2.5">
                <span className="w-3 h-3 rounded bg-amber-500 block"></span>
                <div>
                  <span className="text-slate-400 [.light_&]:text-slate-500 block font-bold">Warning</span>
                  <strong className="text-amber-400 [.light_&]:text-amber-600 text-sm">{pctWarning}% ({warningCount})</strong>
                </div>
              </div>
              <div className="flex items-center gap-2.5">
                <span className="w-3 h-3 rounded bg-blue-500 block"></span>
                <div>
                  <span className="text-slate-400 [.light_&]:text-slate-500 block font-bold">Info / FP</span>
                  <strong className="text-blue-400 [.light_&]:text-blue-600 text-sm">{pctInfo}% ({infoCount})</strong>
                </div>
              </div>
            </div>
          </div>

          <div className="text-xs text-slate-400 [.light_&]:text-slate-600 text-center bg-slate-950/40 [.light_&]:bg-slate-50 p-2.5 rounded border border-slate-900 [.light_&]:border-slate-200 font-medium">
            Moteur d'analyse comportementale (UEBA) actif.
          </div>
        </div>

        {/* GRAPH 2 : HISTOGRAMME PAR PÉRIODE / HEURE */}
        <div className="lg:col-span-2 bg-[#0f172a] [.light_&]:bg-white border border-slate-800/80 [.light_&]:border-slate-200 p-5 rounded-xl flex flex-col justify-between h-[380px] shadow-lg">
          <div>
            <h3 className="text-xs font-black text-slate-200 [.light_&]:text-slate-800 uppercase tracking-wider">// Analyse de Fréquence Chronologique (Historique)</h3>
            <span className="text-xs text-slate-500 block mb-6 mt-1">Pics d'attaques enregistrés par créneaux de 4 heures</span>
          </div>

          {/* COLONNES CHRONOLOGIQUES */}
          <div className="flex-1 flex items-end justify-between gap-3 px-2 border-b border-slate-800 [.light_&]:border-slate-200 pb-2.5">
            
            <div className="flex-1 flex flex-col items-center gap-2 group">
              <span className="text-xs text-slate-400 [.light_&]:text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity font-bold">12k logs</span>
              <div className="w-full bg-slate-800/60 [.light_&]:bg-slate-200 rounded-t-md h-12 relative overflow-hidden transition-all group-hover:bg-slate-700 [.light_&]:group-hover:bg-slate-300">
                <div className="absolute bottom-0 left-0 right-0 bg-blue-500 h-[60%]"></div>
              </div>
              <span className="text-xs text-slate-300 [.light_&]:text-slate-700 font-bold">00h-04h</span>
            </div>

            <div className="flex-1 flex flex-col items-center gap-2 group">
              <span className="text-xs text-red-400 [.light_&]:text-red-600 font-black opacity-0 group-hover:opacity-100 transition-opacity">45k (DDoS)</span>
              <div className="w-full bg-slate-800/60 [.light_&]:bg-slate-200 rounded-t-md h-44 relative overflow-hidden transition-all border border-transparent group-hover:border-red-500/40">
                <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-red-600 to-amber-500 h-full"></div>
              </div>
              <span className="text-xs text-red-400 [.light_&]:text-red-600 font-black tracking-wide">04h-08h</span>
            </div>

            <div className="flex-1 flex flex-col items-center gap-2 group">
              <span className="text-xs text-slate-400 [.light_&]:text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity font-bold">18k logs</span>
              <div className="w-full bg-slate-800/60 [.light_&]:bg-slate-200 rounded-t-md h-24 relative overflow-hidden transition-all group-hover:bg-slate-700 [.light_&]:group-hover:bg-slate-300">
                <div className="absolute bottom-0 left-0 right-0 bg-blue-500 h-[40%]"></div>
                <div className="absolute bottom-0 left-0 right-0 bg-amber-500 h-[15%]"></div>
              </div>
              <span className="text-xs text-slate-300 [.light_&]:text-slate-700 font-bold">08h-12h</span>
            </div>

            <div className="flex-1 flex flex-col items-center gap-2 group">
              <span className="text-xs text-slate-400 [.light_&]:text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity font-bold">9k logs</span>
              <div className="w-full bg-slate-800/60 [.light_&]:bg-slate-200 rounded-t-md h-10 relative overflow-hidden transition-all group-hover:bg-slate-700 [.light_&]:group-hover:bg-slate-300">
                <div className="absolute bottom-0 left-0 right-0 bg-blue-500 h-[25%]"></div>
              </div>
              <span className="text-xs text-slate-300 [.light_&]:text-slate-700 font-bold">12h-16h</span>
            </div>

            <div className="flex-1 flex flex-col items-center gap-2 group">
              <span className="text-xs text-slate-400 [.light_&]:text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity font-bold">15k logs</span>
              <div className="w-full bg-slate-800/60 [.light_&]:bg-slate-200 rounded-t-md h-16 relative overflow-hidden transition-all group-hover:bg-slate-700 [.light_&]:group-hover:bg-slate-300">
                <div className="absolute bottom-0 left-0 right-0 bg-blue-500 h-[45%]"></div>
              </div>
              <span className="text-xs text-slate-300 [.light_&]:text-slate-700 font-bold">16h-20h</span>
            </div>

            <div className="flex-1 flex flex-col items-center gap-2 group">
              <span className="text-xs text-slate-400 [.light_&]:text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity font-bold">22k logs</span>
              <div className="w-full bg-slate-800/60 [.light_&]:bg-slate-200 rounded-t-md h-28 relative overflow-hidden transition-all group-hover:bg-slate-700 [.light_&]:group-hover:bg-slate-300">
                <div className="absolute bottom-0 left-0 right-0 bg-blue-500 h-[50%]"></div>
                <div className="absolute bottom-0 left-0 right-0 bg-amber-500 h-[10%]"></div>
              </div>
              <span className="text-xs text-slate-300 [.light_&]:text-slate-700 font-bold">20h-00h</span>
            </div>

          </div>

          {/* LÉGENDE DE L'HISTOGRAMME */}
          <div className="flex flex-wrap justify-start gap-5 text-xs text-slate-400 [.light_&]:text-slate-600 pt-4">
            <div className="flex items-center gap-2"><span className="w-3 h-1.5 bg-red-500 block rounded-sm"></span> Flux Critique / Infiltration</div>
            <div className="flex items-center gap-2"><span className="w-3 h-1.5 bg-amber-500 block rounded-sm"></span> Alertes Firewall</div>
            <div className="flex items-center gap-2"><span className="w-3 h-1.5 bg-blue-500 block rounded-sm"></span> Activité Nominale</div>
          </div>
        </div>

      </div>
      
    </div>
  );
}