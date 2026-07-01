import { useState } from 'react';

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

            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800/60 pb-5">
                <div>
                    <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.3em] text-cyan-400 mb-2">
                        <span>Forensics & Threat Hunting • Live Raw Stream</span>
                    </div>
                    <h1 className="text-3xl font-black text-white mt-1">Log Explorer</h1>
                </div>
                <div className="rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-2 text-xs text-slate-400 shadow-lg">
                    Analyste SOC : <span className="font-bold text-cyan-400">{user?.name || "Chloe O'Brian"}</span>
                </div>
            </div>

            <div className="rounded-2xl border border-slate-800/80 bg-slate-900/70 p-4 shadow-lg flex flex-col xl:flex-row gap-4 justify-between items-center">
                <div className="w-full xl:w-80 relative group">
                    <input
                        type="text"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        placeholder="Requête Lucene / KQL..."
                        className="w-full rounded-xl border border-slate-800 bg-slate-950/80 pl-4 pr-4 py-2.5 text-sm text-white transition-all duration-300 hover:border-slate-700 focus:border-cyan-500 focus:outline-none"
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
                <div className={`transition-all duration-300 rounded-2xl border border-slate-800/80 bg-slate-900/70 shadow-lg overflow-hidden ${selectedLog ? 'lg:w-2/3' : 'w-full'}`}>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="border-b border-slate-800 bg-slate-950/80 text-slate-400 text-[11px] uppercase tracking-[0.25em]">
                                    <th className="p-4">Timestamp</th>
                                    <th className="p-4">Severity</th>
                                    <th className="p-4">Source IP</th>
                                    <th className="p-4">Event</th>
                                    <th className="p-4 text-right">Status</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/50 text-xs">
                                {filteredLogs.length === 0 ? (
                                    <tr>
                                        <td colSpan="5" className="p-8 text-center text-slate-500">No raw events found for the current filters.</td>
                                    </tr>
                                ) : (
                                    filteredLogs.map((log) => {
                                        return (
                                            <tr
                                                key={log.id}
                                                onClick={() => setSelectedLog(log)}
                                                className={`cursor-pointer transition-all hover:bg-slate-800/60 ${selectedLog?.id === log.id ? 'bg-slate-800/70' : ''}`}
                                            >
                                                <td className="p-4 whitespace-nowrap text-slate-400">{log.timestamp}</td>
                                                <td className="p-4">
                                                    <span className={`rounded border px-2 py-0.5 text-[10px] font-bold ${
                                                        log.severity === 'CRITICAL' ? 'border-red-500/30 bg-red-500/10 text-red-400' :
                                                        log.severity === 'WARNING' ? 'border-amber-500/30 bg-amber-500/10 text-amber-400' :
                                                        'border-blue-500/30 bg-blue-500/10 text-blue-400'
                                                    }`}>
                                                        {log.severity}
                                                    </span>
                                                </td>
                                                <td className="p-4 font-semibold tracking-wide text-cyan-400">{log.source}</td>
                                                <td className="p-4 max-w-xs truncate text-slate-300 transition-colors group-hover:text-white">
                                                    {log.event}
                                                    {(log.mitre_tactic_id || log.mitre_technique_id) && (
                                                        <div className="mt-2 text-[11px] text-slate-400">
                                                            {log.mitre_tactic_id && <div className="font-bold text-slate-200">{log.mitre_tactic_id} — {log.mitre_tactic_name}</div>}
                                                            {log.mitre_technique_id && <div>{log.mitre_technique_id} — {log.mitre_technique_name}</div>}
                                                        </div>
                                                    )}
                                                </td>
                                                <td className="p-4 text-right">
                                                    {log.escalated ? (
                                                        <span className="rounded border border-red-800 bg-red-950/40 px-2 py-1 text-[10px] font-bold text-red-400">ESCALATED</span>
                                                    ) : (
                                                        <span className={`rounded border px-2 py-1 text-[10px] font-bold ${
                                                            log.status === 'FAUX_POSITIF' ? 'border-slate-700 bg-slate-800 text-slate-400' :
                                                            log.status === 'TRAITÉ' ? 'border-cyan-900/30 bg-cyan-950/20 text-cyan-500' :
                                                            log.status === 'EN_COURS' ? 'border-amber-900/30 bg-amber-950/40 text-amber-400' :
                                                            'border-slate-800 bg-slate-950/70 text-slate-400'
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
                    <div className="flex flex-col justify-between space-y-6 rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg animate-in slide-in-from-right-4 duration-300 lg:w-1/3">
                        <div className="space-y-4">
                            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                                <div>
                                    <h3 className="text-sm font-bold text-white">{selectedLog.id}</h3>
                                    <p className="text-[10px] uppercase tracking-[0.25em] text-slate-500">Index Facility: {selectedLog.service}</p>
                                </div>
                                <button onClick={() => setSelectedLog(null)} className="cursor-pointer rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-400 transition-colors hover:text-white">Close</button>
                            </div>

                            <div className="space-y-3 text-xs">
                                <div>
                                    <span className="mb-1 block text-[10px] uppercase tracking-[0.25em] text-slate-500">Source Network IP</span>
                                    <span className="inline-block rounded border border-cyan-500/10 bg-cyan-500/5 px-2 py-0.5 font-semibold text-cyan-400">{selectedLog.source}</span>
                                </div>
                                <div>
                                    <span className="mb-1 block text-[10px] uppercase tracking-[0.25em] text-slate-500">Syslog Message</span>
                                    <p className="rounded border border-slate-800/80 bg-slate-950/70 p-2.5 text-slate-200">{selectedLog.event}</p>
                                </div>
                                <div>
                                    <span className="mb-1 block text-[10px] uppercase tracking-[0.25em] text-slate-500">Metadata Payload</span>
                                    <pre className="overflow-x-auto whitespace-pre-wrap rounded-lg border border-slate-900 bg-slate-950 p-3 text-[11px] leading-tight text-amber-400/90">{selectedLog.payload}</pre>
                                </div>
                                {(selectedLog.mitre_tactic_id || selectedLog.mitre_technique_id) && (
                                    <div className="mt-3 bg-[#0b1220] p-3 rounded-lg border border-slate-800 text-sm">
                                        <div className="text-[11px] text-slate-500 uppercase font-bold mb-1">Contexte MITRE ATT&CK</div>
                                        {selectedLog.mitre_tactic_id && <div className="font-bold text-slate-200">{selectedLog.mitre_tactic_id} — {selectedLog.mitre_tactic_name}</div>}
                                        {selectedLog.mitre_technique_id && <div className="text-slate-400">{selectedLog.mitre_technique_id} — {selectedLog.mitre_technique_name}</div>}
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="border-t border-slate-800 pt-4 text-center text-[11px] text-slate-500">
                            To qualify, process, or escalate this event, use the alert triage console.
                        </div>
                    </div>
                )}

            </div>
        </div>
    );
}