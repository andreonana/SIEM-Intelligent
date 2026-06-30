import React from 'react';

/**
 * COMPOSANT : AuditTrail (Journal d'autosurveillance et d'audit du SOC)
 * @param {Object} user - L'utilisateur connecté transmis par App.jsx
 */
export default function AuditTrail({ user }) {
    // Liste statique mais ultra-réaliste des dernières actions de vos opérateurs pour la soutenance
    const auditLogs = [
        { id: "AUDIT-901", timestamp: "2026-06-27 10:14:22", operator: "Chloe O'Brian", role: "analyst", action: "Escalade d'alerte", target: "Log #AL-402 -> Crisis Room", status: "SUCCESS", ip: "10.0.4.12" },
        { id: "AUDIT-902", timestamp: "2026-06-27 10:18:05", operator: "Bill Buchanan", role: "administrator", action: "Déclenchement SOAR", target: "Isolation IP 192.168.1.50 (Firewall)", status: "SUCCESS", ip: "10.0.2.1" },
        { id: "AUDIT-903", timestamp: "2026-06-27 10:45:12", operator: "Edgar Stiles", role: "reader", action: "Tentative d'accès refusée", target: "Désactivation Règle #RULE-02", status: "DENIED", ip: "10.0.4.55" },
        { id: "AUDIT-904", timestamp: "2026-06-27 11:02:40", operator: "Bill Buchanan", role: "administrator", action: "Modification RBAC", target: "Réactivation du compte Jack Bauer", status: "SUCCESS", ip: "10.0.2.1" },
        { id: "AUDIT-905", timestamp: "2026-06-27 11:15:00", operator: "Chloe O'Brian", role: "analyst", action: "Génération Rapport", target: "Export PDF - Bilan Mensuel", status: "SUCCESS", ip: "10.0.4.12" }
    ];

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 font-mono text-sm">
            
            {/* ENTÊTE DU COMPOSANT */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-5">
                <div>
                    <div className="flex items-center gap-2 text-xs text-indigo-400 mb-1">
                        <span className="w-2 h-2 rounded-full bg-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.5)]"></span>
                        <span>[SOC SECURITY AUDIT TRAIL — IMMUTABLE LOGS]</span>
                    </div>
                    <h1 className="text-3xl font-black text-white tracking-tight">// Audit Trail (Suivi d'Actions)</h1>
                </div>
                <div className="bg-slate-900 border border-slate-800 px-4 py-2 rounded-xl text-xs text-slate-400">
                    Chaîne d'intégrité : <span className="font-bold text-emerald-400 ml-1">SÉCURISÉE (WORM)</span>
                </div>
            </div>

            {/* MESSAGE SUR L'INTÉGRITÉ */}
            <div className="bg-slate-950 border border-slate-900 text-slate-400 p-4 rounded-xl text-xs space-y-1.5 font-sans leading-relaxed">
                <p>
                    <strong className="font-mono text-slate-200"> Note pour l'Audit :</strong> Ce journal d'activité enregistre de manière inaltérable toutes les actions exécutées sur le cœur du SIEM. Conformément à la norme <strong className="font-mono text-cyan-400">ISO 27001 (A.12.4.2)</strong>, ces événements de traçabilité ne peuvent être modifiés ou supprimés, même par un compte administrateur.
                </p>
            </div>

            {/* TABLEAU DES LOGS D'AUDIT TRAIL */}
            <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
                <div className="bg-slate-900/40 p-4 border-b border-slate-800">
                    <h3 className="text-xs font-bold uppercase text-slate-300">// Événements d'accès et de contrôle internes</h3>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                        <thead>
                            <tr className="border-b border-slate-800 text-slate-500 uppercase font-bold bg-slate-950/20">
                                <th className="p-3.5">Horodatage</th>
                                <th className="p-3.5">Opérateur</th>
                                <th className="p-3.5">Action Menée</th>
                                <th className="p-3.5">Cible / Détails</th>
                                <th className="p-3.5">Origine IP</th>
                                <th className="p-3.5 text-right">Résultat</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 text-slate-300">
                            {auditLogs.map((log) => (
                                <tr key={log.id} className="hover:bg-slate-900/20 transition-all">
                                    <td className="p-3.5 text-slate-500 whitespace-nowrap">{log.timestamp}</td>
                                    <td className="p-3.5">
                                        <span className="text-white font-bold block">{log.operator}</span>
                                        <span className="text-[10px] text-slate-500 uppercase">[{log.role}]</span>
                                    </td>
                                    <td className="p-3.5 text-indigo-400 font-bold">{log.action}</td>
                                    <td className="p-3.5 font-sans text-slate-400 max-w-xs truncate" title={log.target}>
                                        {log.target}
                                    </td>
                                    <td className="p-3.5 text-slate-500 font-mono">{log.ip}</td>
                                    <td className="p-3.5 text-right">
                                        <span className={`px-2 py-0.5 rounded text-[10px] font-black border ${
                                            log.status === 'SUCCESS' 
                                                ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' 
                                                : 'bg-red-500/10 border-red-500/20 text-red-400 animate-pulse'
                                        }`}>
                                            {log.status}
                                        </span>
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