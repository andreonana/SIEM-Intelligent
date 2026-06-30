import React, { useState } from 'react';

/**
 * COMPOSANT : SystemConfig (Santé de la Plateforme & Statut des Agents de Collecte)
 * @param {Object} user - L'utilisateur connecté transmis par App.jsx
 */
export default function SystemConfig({ user }) {
    // 1. ÉTAT LOCAL : Liste des serveurs et capteurs surveillés par le SIEM
    const [agents, setAgents] = useState([
        { id: "AGT-001", hostname: "ctu-auth-prod.local", type: "EDR / Wazuh", ip: "10.0.4.12", status: "ONLINE", version: "v4.7.2" },
        { id: "AGT-002", hostname: "ctu-sql-cluster.local", type: "Database Agent", ip: "10.0.4.20", status: "ONLINE", version: "v4.7.2" },
        { id: "AGT-003", hostname: "ctu-dmz-nginx.local", type: "Syslog Collector", ip: "192.168.10.5", status: "ONLINE", version: "v3.35.1" },
        { id: "AGT-004", hostname: "ctu-backup-san.local", type: "Storage Monitor", ip: "10.0.6.100", status: "DEGRADED", version: "v4.7.0" },
        { id: "AGT-005", hostname: "ctu-hr-portal.local", type: "EDR / Wazuh", ip: "10.0.4.55", status: "OFFLINE", version: "v4.7.1" }
    ]);

    // Rôle requis pour pouvoir "Relancer" un agent (Bill a les droits, Chloé non)
    const canManageAgents = user?.role === 'administrator';

    // Fonction de simulation pour redémarrer un agent de collecte
    const handleRestartAgent = (id, hostname) => {
        if (!canManageAgents) {
            alert("❌ [RBAC ERROR] Droits insuffisants. Seul l'administrateur peut redémarrer des services d'infrastructure.");
            return;
        }
        
        // Simulation visuelle du redémarrage
        setAgents(prev => prev.map(agt => agt.id === id ? { ...agt, status: "RESTARTING" } : agt));
        
        setTimeout(() => {
            setAgents(prev => prev.map(agt => agt.id === id ? { ...agt, status: "ONLINE" } : agt));
            alert(`[INFRA] L'agent de collecte sur ${hostname} a été réinitialisé avec succès.`);
        }, 1500);
    };

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 font-mono text-sm">
            
            {/* ENTÊTE DU COMPOSANT */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-5">
                <div>
                    <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
                        <span className="w-2 h-2 rounded-full bg-slate-500 shadow-[0_0_8px_rgba(148,163,184,0.5)]"></span>
                        <span>[SIEM INFRASTRUCTURE MONITORING & ENGINE HEALTH]</span>
                    </div>
                    <h1 className="text-3xl font-black text-white tracking-tight">// Configuration Système & Agents</h1>
                </div>
            </div>

            {/* SECTION 1 : METRICS MATÉRIEL DU SERVEUR SIEM */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-[#0f172a] border border-slate-800 p-4 rounded-xl space-y-2">
                    <span className="text-[10px] text-slate-500 uppercase font-bold">Charge CPU Serveur</span>
                    <div className="flex justify-between items-baseline">
                        <span className="text-2xl font-black text-white">24%</span>
                        <span className="text-xs text-emerald-400 font-bold">STABLE</span>
                    </div>
                    <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden">
                        <div className="bg-emerald-500 h-full" style={{ width: '24%' }}></div>
                    </div>
                </div>

                <div className="bg-[#0f172a] border border-slate-800 p-4 rounded-xl space-y-2">
                    <span className="text-[10px] text-slate-500 uppercase font-bold">Allocation RAM (Moteur)</span>
                    <div className="flex justify-between items-baseline">
                        <span className="text-2xl font-black text-white">14.2 / 32 <span className="text-xs text-slate-500 font-normal">Go</span></span>
                        <span className="text-xs text-emerald-400 font-bold">OK</span>
                    </div>
                    <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden">
                        <div className="bg-cyan-500 h-full" style={{ width: '44%' }}></div>
                    </div>
                </div>

                <div className="bg-[#0f172a] border border-slate-800 p-4 rounded-xl space-y-2">
                    <span className="text-[10px] text-slate-500 uppercase font-bold">Stockage Indexation Logs</span>
                    <div className="flex justify-between items-baseline">
                        <span className="text-2xl font-black text-white">68%</span>
                        <span className="text-xs text-amber-400 font-bold">RÉTENTION 365J</span>
                    </div>
                    <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden">
                        <div className="bg-amber-500 h-full" style={{ width: '68%' }}></div>
                    </div>
                </div>
            </div>

            {/* SECTION 2 : TABLEAU DU STATUT DES AGENTS PIPELINE */}
            <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
                <div className="bg-slate-900/40 p-4 border-b border-slate-800">
                    <h3 className="text-xs font-bold uppercase text-slate-300">// État des capteurs réseau et EDR (Pipelines de Logs)</h3>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                        <thead>
                            <tr className="border-b border-slate-800 text-slate-500 uppercase font-bold bg-slate-950/20">
                                <th className="p-3.5">ID Capteur</th>
                                <th className="p-3.5">Machine Cible</th>
                                <th className="p-3.5">Type de Collecteur</th>
                                <th className="p-3.5">Adresse IP</th>
                                <th className="p-3.5">Version</th>
                                <th className="p-3.5">Statut</th>
                                <th className="p-3.5 text-right">Contrôle</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 text-slate-300">
                            {agents.map((agt) => (
                                <tr key={agt.id} className="hover:bg-slate-900/20 transition-all">
                                    <td className="p-3.5 font-bold text-slate-400">{agt.id}</td>
                                    <td className="p-3.5 text-white font-bold">{agt.hostname}</td>
                                    <td className="p-3.5 text-slate-400">{agt.type}</td>
                                    <td className="p-3.5 text-slate-500">{agt.ip}</td>
                                    <td className="p-3.5 text-slate-500">{agt.version}</td>
                                    <td className="p-3.5">
                                        <span className={`px-2 py-0.5 rounded text-[10px] font-black border ${
                                            agt.status === 'ONLINE' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
                                            agt.status === 'DEGRADED' ? 'bg-amber-500/10 border-amber-500/20 text-amber-400 animate-pulse' :
                                            agt.status === 'RESTARTING' ? 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400 animate-spin inline-block' :
                                            'bg-red-500/10 border-red-500/20 text-red-400 animate-pulse'
                                        }`}>
                                            ● {agt.status}
                                        </span>
                                    </td>
                                    <td className="p-3.5 text-right">
                                        <button
                                            onClick={() => handleRestartAgent(agt.id, agt.hostname)}
                                            disabled={agt.status === 'RESTARTING'}
                                            className={`text-[11px] px-2.5 py-1 rounded transition-colors border ${
                                                !canManageAgents
                                                    ? 'bg-slate-900 text-slate-600 border-slate-800/40 cursor-not-allowed'
                                                    : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-600 hover:text-white cursor-pointer'
                                            }`}
                                        >
                                            Relancer
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

        </div>
    );
}