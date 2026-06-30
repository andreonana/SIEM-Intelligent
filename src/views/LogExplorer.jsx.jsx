import React, { useState } from 'react';

/**
 * COMPOSANT : LogExplorer
 * Vue dédiée exclusivement au Threat Hunting et à la Cyber Forensics.
 */
export default function LogExplorer({ user, logs }) {
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedSeverity, setSelectedSeverity] = useState('ALL');
    const [selectedStatus, setSelectedStatus] = useState('ALL'); // 🔍 NOUVEL ÉTAT POUR LE STATUT SIEM
    const [selectedLog, setSelectedLog] = useState(null);

    // FILTRAGE AVANCÉ SUR LES FLUX BRUTS
    const filteredLogs = logs.filter(log => {
        // 1. Recherche textuelle
        const matchesSearch =
            log.event.toLowerCase().includes(searchTerm.toLowerCase()) ||
            log.source.includes(searchTerm) ||
            log.service.toLowerCase().includes(searchTerm.toLowerCase());

        // 2. Filtrage par Sévérité
        const matchesSeverity = selectedSeverity === 'ALL' || log.severity === selectedSeverity;

        // 3. Filtrage par État SIEM
        const logStatus = log.escalated ? 'ESCALADÉ' : (log.status || 'NON_TRAITÉ');
        const matchesStatus = selectedStatus === 'ALL' || logStatus === selectedStatus;

        return matchesSearch && matchesSeverity && matchesStatus;
    });

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">

            {/* ENTÊTE CYBER SÉCURISÉ */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800/60 pb-5">
                <div>
                    <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
                        <span>[FORENSICS & THREAT HUNTING — RAW LIVE STREAM: siem-core-brut-*]</span>
                    </div>
                    <h1 className="text-3xl font-black text-white font-mono mt-1">// LOG EXPLORER</h1>
                </div>
                <div className="bg-[#111827] border border-slate-800 px-4 py-2 rounded-lg text-xs font-mono text-slate-400">
                    Analyste SOC : <span className="text-cyan-400 font-bold">{user?.name || "Chloe O'Brian"}</span>
                </div>
            </div>

            {/* BARRE DE RECHERCHE + FILTRES (RÉALIGNÉS AVEC LE MENU DÉROULANT) */}
            <div className="bg-[#0f172a] border border-slate-800/80 rounded-xl p-4 flex flex-col xl:flex-row gap-4 justify-between items-center">
                <div className="w-full xl:w-80 relative group">
                    <span className="absolute left-3.5 top-3.5 text-slate-500 text-sm">🔍</span>
                    <input
                        type="text"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        placeholder="Requête Lucene / KQL..."
                        className="w-full bg-[#111827] border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-sm focus:outline-none focus:border-cyan-500 text-white font-mono transition-all duration-300 hover:border-slate-700"
                    />
                </div>

                {/* ZONE DES FILTRES : SÉVÉRITÉ + ÉTAT SIEM */}
                <div className="flex flex-col sm:flex-row items-center gap-4 w-full xl:w-auto justify-end">
                    
                    {/* BOUTONS SÉVÉRITÉ */}
                    <div className="flex gap-1.5 w-full sm:w-auto overflow-x-auto pb-1 sm:pb-0">
                        {['ALL', 'CRITICAL', 'WARNING', 'INFO'].map((severity) => (
                            <button
                                key={severity}
                                onClick={() => setSelectedSeverity(severity)}
                                className={`px-3 py-2 rounded-lg text-xs font-mono font-bold transition-all border cursor-pointer uppercase whitespace-nowrap ${
                                    selectedSeverity === severity
                                        ? 'bg-cyan-600 text-white border-cyan-500 shadow-md shadow-cyan-950/40'
                                        : 'bg-[#111827] text-slate-400 border-slate-800 hover:border-slate-600 hover:text-slate-200'
                                }`}
                            >
                                {severity === 'ALL' ? 'Tous les flux' : severity}
                            </button>
                        ))}
                    </div>

                    {/*  MENU DÉROULANT : ÉTAT SIEM */}
                    <div className="w-full sm:w-48 font-mono">
                        <select
                            value={selectedStatus}
                            onChange={(e) => setSelectedStatus(e.target.value)}
                            className="w-full bg-[#111827] border border-slate-800 rounded-lg p-2.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 hover:border-slate-700 transition-colors cursor-pointer uppercase font-bold"
                        >
                            <option value="ALL"> TOUS LES ÉTATS</option>
                            <option value="NON_TRAITÉ"> NON TRAITÉS</option>
                            <option value="TRAITÉ"> TRAITÉS</option>
                            <option value="FAUX_POSITIF"> FAUX POSITIFS</option>
                            <option value="ESCALADÉ"> ESCALADÉS</option>
                        </select>
                    </div>

                </div>
            </div>

            {/* STRATE DE VISUALISATION */}
            <div className="flex flex-col lg:flex-row gap-6">

                {/* VISUALISEUR DU TERMINAL DE LOGS */}
                <div className={`transition-all duration-300 bg-[#0f172a] border border-slate-800/80 rounded-xl overflow-hidden ${selectedLog ? 'lg:w-2/3' : 'w-full'}`}>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-[#111827] border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                                    <th className="p-4">Horodatage</th>
                                    <th className="p-4">Sévérité</th>
                                    <th className="p-4">Source IP</th>
                                    <th className="p-4">Événement brut intercepté</th>
                                    <th className="p-4 text-right">État SIEM</th>
                                </tr>
                            </thead>    
                        </table>
                        <table>
                            <tbody className="divide-y divide-slate-800/50 font-mono text-xs">
                                {filteredLogs.length === 0 ? (
                                    <tr>
                                        <td colSpan="5" className="p-8 text-center text-slate-500 font-mono">[Aucun événement brut trouvé pour ces critères de filtrage]</td>
                                    </tr>
                                ) : (
                                    filteredLogs.map((log) => {
                                        return (
                                            <tr
                                                key={log.id}
                                                onClick={() => setSelectedLog(log)}
                                                className={`hover:bg-[#162035]/60 transition-all cursor-pointer group ${
                                                    selectedLog?.id === log.id ? 'bg-[#1e293b]' : ''
                                                }`}
                                            >
                                                <td className="p-4 text-slate-400 whitespace-nowrap">{log.timestamp}</td>
                                                <td className="p-4">
                                                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                                        log.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
                                                        log.severity === 'WARNING' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                                                        'bg-blue-500/10 text-blue-400 border-blue-500/30'
                                                    }`}>
                                                        {log.severity}
                                                    </span>
                                                </td>
                                                <td className="p-4 text-cyan-400 font-bold tracking-wide">{log.source}</td>
                                                <td className="p-4 text-slate-300 max-w-xs truncate group-hover:text-white transition-colors">{log.event}</td>
                                                <td className="p-4 text-right">
                                                    {log.escalated ? (
                                                        <span className="text-[10px] font-bold text-red-400 bg-red-950/40 border border-red-800 px-2 py-1 rounded">🚨 ESCALADÉ</span>
                                                    ) : (
                                                        <span className={`text-[10px] font-bold px-2 py-1 rounded border ${
                                                            log.status === 'FAUX_POSITIF' ? 'bg-slate-800 text-slate-400 border-slate-700' :
                                                            log.status === 'TRAITÉ' ? 'bg-cyan-950/20 text-cyan-500 border-cyan-900/30' :
                                                            log.status === 'EN_COURS' ? 'bg-amber-950/40 text-amber-400 border-amber-900/30' :
                                                            'bg-[#111827] text-slate-400 border-slate-800'
                                                        }`}>
                                                            {log.status || 'NON_TRAITÉ'}
                                                        </span>
                                                    )}
                                                </td>
                                            </tr>
                                        );
                                    })
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* PANNEAU LATÉRAL : INSPECTEUR FORENSICS DU LOG BRUT */}
                {selectedLog && (
                    <div className="lg:w-1/3 bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-6 animate-in slide-in-from-right-4 duration-300">
                        <div className="space-y-4">
                            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                                <div>
                                    <h3 className="text-sm font-bold text-white font-mono">{selectedLog.id}</h3>
                                    <p className="text-[10px] text-slate-500 font-mono">Index-Facility: {selectedLog.service}</p>
                                </div>
                                <button onClick={() => setSelectedLog(null)} className="text-slate-400 hover:text-white text-xs bg-slate-800 px-2 py-1 rounded cursor-pointer">Fermer</button>
                            </div>

                            <div className="space-y-3 font-mono text-xs">
                                <div>
                                    <span className="block text-slate-500 text-[10px] uppercase">// Source Network IP</span>
                                    <span className="text-cyan-400 font-bold bg-cyan-500/5 px-2 py-0.5 rounded border border-cyan-500/10 inline-block">{selectedLog.source}</span>
                                </div>
                                <div>
                                    <span className="block text-slate-500 text-[10px] uppercase">// Message Syslog Intercepté</span>
                                    <p className="text-slate-200 bg-slate-900/60 p-2.5 rounded border border-slate-800/80 font-sans">{selectedLog.event}</p>
                                </div>
                                <div>
                                    <span className="block text-slate-500 text-[10px] uppercase">// Données Métadonnées Payload (JSON)</span>
                                    <pre className="text-[11px] text-amber-400/90 bg-slate-950 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap border border-slate-900 shadow-inner leading-tight">{selectedLog.payload}</pre>
                                </div>
                            </div>
                        </div>

                        <div className="border-t border-slate-800 pt-4 text-center font-mono text-[11px] text-slate-500">
                             Pour qualifier, traiter ou escalader cet événement, utilisez la console de supervision <strong className="text-amber-500">Alert Triage</strong>.
                        </div>
                    </div>
                )}

            </div>
        </div>
    );
}