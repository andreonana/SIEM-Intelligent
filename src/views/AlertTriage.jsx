import React, { useState } from 'react';

/**
 * COMPOSANT : AlertTriage (Version Nettoyage Dynamique de l'Espace)
 * Console de gestion des alertes du SOC.
 * Dès qu'une alerte est qualifiée (Traité / Faux Positif), elle disparaît 
 * instantanément de l'affichage pour désencombrer l'écran.
 */
export default function AlertTriage({ user, logs, setLogs }) {
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedAlert, setSelectedAlert] = useState(null);
    const [selectedAlertIds, setSelectedAlertIds] = useState([]);

    const isReader = user?.role === 'reader';

    // FILTRAGE STRICT : Gravité (CRITICAL/WARNING) AND Non traité (Exclure FAUX_POSITIF et TRAITÉ)
    const alerts = logs.filter(log => {
        const isAlert = log.severity === 'CRITICAL' || log.severity === 'WARNING';
        const isNotProcessed = log.status !== 'FAUX_POSITIF' && log.status !== 'TRAITÉ';
        
        const matchesSearch = 
            log.event.toLowerCase().includes(searchTerm.toLowerCase()) ||
            log.source.includes(searchTerm) ||
            log.service.toLowerCase().includes(searchTerm.toLowerCase());
            
        return isAlert && isNotProcessed && matchesSearch;
    });

    const handleSelectAlert = (id, e) => {
        e.stopPropagation();
        if (selectedAlertIds.includes(id)) {
            setSelectedAlertIds(selectedAlertIds.filter(item => item !== id));
        } else {
            setSelectedAlertIds([...selectedAlertIds, id]);
        }
    };

    const handleSelectAll = () => {
        const visibleIds = alerts.map(a => a.id);
        const allVisibleAreSelected = visibleIds.every(id => selectedAlertIds.includes(id));

        if (allVisibleAreSelected) {
            setSelectedAlertIds(selectedAlertIds.filter(id => !visibleIds.includes(id)));
        } else {
            setSelectedAlertIds(Array.from(new Set([...selectedAlertIds, ...visibleIds])));
        }
    };

    // MUTATION EN MASSE (Disparition collective)
    const handleBulkUpdate = (newStatus) => {
        if (isReader) return;
        setLogs(prevLogs => prevLogs.map(log => 
            selectedAlertIds.includes(log.id) ? { ...log, status: newStatus, escalated: false } : log
        ));
        // Si l'alerte ouverte fait partie du lot, on ferme le panneau
        if (selectedAlert && selectedAlertIds.includes(selectedAlert.id)) {
            setSelectedAlert(null);
        }
        setSelectedAlertIds([]);
    };

    // QUALIFICATION UNITAIRE (Disparition immédiate de la ligne et fermeture du panneau)
    const handleUpdateSingleStatus = (id, newStatus) => {
        if (isReader) return;
        setLogs(prevLogs => prevLogs.map(log => 
            log.id === id ? { ...log, status: newStatus, escalated: false } : log
        ));
        // L'alerte change de statut et disparaît du filtre -> On ferme l'inspecteur
        if (selectedAlert?.id === id) {
            setSelectedAlert(null);
        }
    };

    // ESCALADE CRITIQUE (Reste visible car passe en statut 'EN_COURS')
    const handleEscalate = (id) => {
        if (isReader) return;
        setLogs(prevLogs => prevLogs.map(log => 
            log.id === id ? { ...log, escalated: true, status: 'EN_COURS' } : log
        ));
        if (selectedAlert?.id === id) {
            setSelectedAlert(prev => ({ ...prev, escalated: true, status: 'EN_COURS' }));
        }
    };

    const allVisibleSelected = alerts.length > 0 && alerts.every(a => selectedAlertIds.includes(a.id));

    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 font-mono text-sm">
            
            {/* EN-TÊTE CONFIGURATION SALLE DE CONTRÔLE */}
            <div className="flex flex-col xl:flex-row justify-between items-start xl:items-center gap-6 border-b border-slate-800/80 pb-6">
                <div>
                    <span className="text-sm tracking-widest text-amber-500 block font-black mb-1">
                         [SIEM CORRELATION ENGINE // ACTIVE THREAT DETECTION]
                    </span>
                    <h1 className="text-4xl font-black text-white tracking-tight mt-1">// ALERT TRIAGE & INCIDENT RESPONSE</h1>
                </div>
                <div className="flex items-center gap-4">
                    {isReader && (
                        <span className="bg-red-950/50 text-red-400 px-4 py-2 rounded-xl border border-red-500/30 font-bold text-xs animate-pulse">
                               READ-ONLY MONITOR
                        </span>
                    )}
                    <div className="bg-[#111827] border-2 border-slate-800 px-5 py-3 rounded-xl text-slate-300 text-sm shadow-xl">
                        Opérateur SOC : <span className="text-amber-400 font-black">{user?.name}</span> <span className="text-slate-500">({user?.role})</span>
                    </div>
                </div>
            </div>

            {/* BARRE DE RECHERCHE XL */}
            <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 flex flex-col md:flex-row gap-4 justify-between items-center shadow-lg">
                <div className="w-full relative group">
                    <span className="absolute left-4 top-4 text-slate-500 text-lg">🔍</span>
                    <input
                        type="text"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        placeholder="Filtrer par IP, Signature d'attaque, Payload MITRE ATT&CK..."
                        className="w-full bg-[#111827] border-2 border-slate-800 focus:border-amber-500 rounded-xl pl-12 pr-5 py-3.5 text-base focus:outline-none text-white transition-all duration-300 placeholder-slate-500"
                    />
                </div>
            </div>

            {/* BARRE D'ACTIONS GROUPÉES AMÉLIORÉE */}
            {selectedAlertIds.length > 0 && !isReader && (
                <div className="bg-amber-950/30 border-2 border-amber-500/50 rounded-2xl p-5 flex flex-col sm:flex-row items-center justify-between gap-4 animate-in zoom-in-95 duration-200 shadow-xl shadow-amber-950/20">
                    <div className="text-base text-amber-400 font-bold">
                         ACTION EN MASSE : <span className="font-black text-white bg-amber-500 text-slate-950 px-3 py-1 rounded-md mx-2">{selectedAlertIds.length}</span> alerte(s) sous contrôle
                    </div>
                    <div className="flex gap-3 w-full sm:w-auto">
                        <button
                            onClick={() => handleBulkUpdate('FAUX_POSITIF')}
                            className="w-full sm:w-auto bg-slate-800 hover:bg-slate-700 text-slate-200 font-black px-5 py-2.5 rounded-xl border border-slate-600 transition-all cursor-pointer text-sm"
                        >
                             Classer Faux Positif
                        </button>
                        <button
                            onClick={() => handleBulkUpdate('TRAITÉ')}
                            className="w-full sm:w-auto bg-emerald-600 hover:bg-emerald-500 text-white font-black px-5 py-2.5 rounded-xl border border-emerald-500 transition-all cursor-pointer text-sm shadow-md"
                        >
                             Clôturer les alertes
                        </button>
                    </div>
                </div>
            )}

            {/* SPLIT VIEW GRAPHIQUE */}
            <div className="flex flex-col lg:flex-row gap-8 items-start">
                
                {/* TABLEAU DES ALERTES TEMPS RÉEL */}
                <div className={`transition-all duration-300 bg-[#0f172a] border border-slate-800 rounded-2xl overflow-hidden shadow-2xl ${selectedAlert ? 'lg:w-7/12 xl:w-1/2' : 'w-full'}`}>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-[#111827] border-b-2 border-slate-800 text-slate-400 font-bold text-xs uppercase tracking-wider">
                                    <th className="p-5 w-12 text-center">
                                        <input
                                            type="checkbox"
                                            checked={allVisibleSelected}
                                            onChange={handleSelectAll}
                                            disabled={isReader}
                                            className="cursor-pointer accent-amber-500 w-4 h-4"
                                        />
                                    </th>
                                    <th className="p-5">Niveau</th>
                                    <th className="p-5">Cible Réseau</th>
                                    <th className="p-5">Signature Incident</th>
                                    <th className="p-5 text-right">Statut</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/60 text-sm">
                                {alerts.length === 0 ? (
                                    <tr>
                                        <td colSpan="5" className="p-10 text-center text-emerald-400 font-medium text-base animate-pulse">
                                             [Félicitations : La file d'attente des menaces est totalement vide]
                                        </td>
                                    </tr>
                                ) : (
                                    alerts.map((alert) => {
                                        const isChecked = selectedAlertIds.includes(alert.id);

                                        return (
                                            <tr
                                                key={alert.id}
                                                onClick={() => setSelectedAlert(alert)}
                                                className={`hover:bg-[#162035]/80 transition-all cursor-pointer transform duration-150 active:scale-[0.99] ${
                                                    selectedAlert?.id === alert.id ? 'bg-[#1e293b] border-l-4 border-amber-500' : ''
                                                } ${isChecked ? 'bg-amber-950/20' : ''}`}
                                            >
                                                <td className="p-5 text-center" onClick={(e) => handleSelectAlert(alert.id, e)}>
                                                    <input
                                                        type="checkbox"
                                                        checked={isChecked}
                                                        disabled={isReader}
                                                        className="cursor-pointer accent-amber-500 w-4 h-4"
                                                        readOnly
                                                    />
                                                </td>
                                                <td className="p-5">
                                                    <span className={`px-2.5 py-1 rounded-md text-xs font-black border tracking-wide ${
                                                        alert.severity === 'CRITICAL' 
                                                            ? 'bg-red-500/10 text-red-400 border-red-500/40' 
                                                            : 'bg-amber-500/10 text-amber-400 border-amber-500/40'
                                                    }`}>
                                                        {alert.severity}
                                                    </span>
                                                </td>
                                                <td className="p-5 text-cyan-400 font-black text-sm tracking-wide">{alert.source}</td>
                                                <td className="p-5 text-slate-300 truncate max-w-[200px] xl:max-w-xs text-sm">{alert.event}</td>
                                                <td className="p-5 text-right">
                                                    {alert.escalated ? (
                                                        <span className="text-xs font-black text-red-400 bg-red-950/60 border border-red-600 px-2.5 py-1 rounded-md animate-pulse">
                                                             CRISIS ROOM
                                                        </span>
                                                    ) : (
                                                        <span className={`text-xs font-bold px-2.5 py-1 rounded-md border ${
                                                            alert.status === 'EN_COURS' ? 'bg-amber-950/40 text-amber-400 border-amber-800/40' :
                                                            'bg-[#111827] text-slate-400 border-slate-800'
                                                        }`}>
                                                            {alert.status || 'NON_TRAITÉ'}
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

                {/* PANNEAU LATÉRAL IMMERSIF : LABORATOIRE FORENSIC */}
                {selectedAlert && (
                    <div className="w-full lg:w-5/12 xl:w-1/2 bg-[#090f1d] border-2 border-slate-800 rounded-2xl p-6 flex flex-col justify-between space-y-6 shadow-2xl animate-in slide-in-from-right-6 duration-300 sticky top-4">
                        
                        <div className="space-y-5">
                            {/* Titre & ID */}
                            <div className="flex justify-between items-start border-b border-slate-800 pb-4">
                                <div>
                                    <span className="text-xs font-bold text-cyan-400 uppercase tracking-widest">// DEEP FILE ANALYSIS</span>
                                    <h3 className="text-xl font-black text-white mt-1 select-all">{selectedAlert.id}</h3>
                                    <p className="text-xs text-slate-500 mt-0.5">Microservice Origin: <span className="text-slate-400 underline font-sans">{selectedAlert.service}</span></p>
                                </div>
                                <button 
                                    onClick={() => setSelectedAlert(null)} 
                                    className="text-slate-400 hover:text-white text-xs bg-slate-800/80 hover:bg-slate-700 px-3 py-1.5 rounded-lg transition-colors cursor-pointer border border-slate-700"
                                >
                                    Fermer [X]
                                </button>
                            </div>

                            {/* Section Contenu Immersif */}
                            <div className="space-y-4">
                                <div className="bg-[#111827]/60 p-4 rounded-xl border border-slate-800/80">
                                    <span className="block text-slate-500 text-xs uppercase font-bold tracking-wider mb-1">// Target Node / Source IP</span>
                                    <span className="text-cyan-400 font-black text-base bg-cyan-950/30 px-3 py-1 rounded-lg border border-cyan-500/20 inline-block">
                                        {selectedAlert.source}
                                    </span>
                                </div>

                                <div className="bg-[#111827]/60 p-4 rounded-xl border border-slate-800/80">
                                    <span className="block text-slate-500 text-xs uppercase font-bold tracking-wider mb-2">// Intercepted Syslog Message</span>
                                    <p className="text-slate-200 text-sm font-sans bg-[#0c101a] p-3 rounded-lg border border-slate-900/80 leading-relaxed">
                                        {selectedAlert.event}
                                    </p>
                                </div>

                                <div>
                                    <span className="block text-slate-500 text-xs uppercase font-bold tracking-wider mb-2">// Extraction Structurelle Métadonnées (JSON Payload)</span>
                                    <pre className="text-xs text-amber-400 bg-slate-950 p-4 rounded-xl overflow-x-auto max-h-[220px] overflow-y-auto border-2 border-slate-900 shadow-inner leading-relaxed font-mono whitespace-pre-wrap">
                                        {selectedAlert.payload}
                                    </pre>
                                </div>
                            </div>
                        </div>

                        {/* ACTIONS DE RÉSOLUTION STRATÉGIQUE (QUALIFICATION & DISPARITION) */}
                        <div className="border-t border-slate-800/80 pt-5 space-y-4">
                            
                            {/* Choix 1 : Qualification Unitaire Locale */}
                            {!selectedAlert.escalated && (
                                <div>
                                    <span className="block text-slate-500 text-xs uppercase font-bold tracking-wider mb-2">// Option A : Écarter l'incident (Nettoyer la file)</span>
                                    <div className="grid grid-cols-2 gap-3">
                                        <button
                                            onClick={() => handleUpdateSingleStatus(selectedAlert.id, 'FAUX_POSITIF')}
                                            disabled={isReader}
                                            className="py-3 px-4 rounded-xl font-black text-xs bg-slate-900/40 hover:bg-slate-800 text-slate-400 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer uppercase tracking-wider"
                                        >
                                             Faux Positif
                                        </button>
                                        <button
                                            onClick={() => handleUpdateSingleStatus(selectedAlert.id, 'TRAITÉ')}
                                            disabled={isReader}
                                            className="py-3 px-4 rounded-xl font-black text-xs bg-slate-900/40 hover:bg-slate-800 text-slate-400 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer uppercase tracking-wider"
                                        >
                                             Résolu / Clos
                                        </button>
                                    </div>
                                </div>
                            )}

                            {/* Choix 2 : Escalade de crise */}
                            <div>
                                {!selectedAlert.escalated && (
                                    <span className="block text-slate-500 text-xs uppercase font-bold tracking-wider mb-2">// Option B : Menace avérée (Garder visible)</span>
                                )}
                                {selectedAlert.escalated ? (
                                    <div className="w-full bg-red-950/40 text-red-400 border-2 border-red-900 text-center font-black text-sm py-4 rounded-xl shadow-lg animate-pulse tracking-wide">
                                         TRANSMIS AUX ENQUÊTEURS DE LA CRISIS ROOM
                                    </div>
                                ) : (
                                    <button
                                        onClick={() => handleEscalate(selectedAlert.id)}
                                        disabled={isReader}
                                        className={`w-full font-black text-xs py-4 px-4 rounded-xl text-center block transition-all uppercase tracking-widest border shadow-xl ${
                                            isReader 
                                                ? 'bg-slate-800 border-slate-700 text-slate-500 cursor-not-allowed'
                                                : 'bg-red-950/40 hover:bg-red-700 border-red-500/40 hover:border-red-500 text-red-400 hover:text-white cursor-pointer active:scale-[0.99]'
                                        }`}
                                    >
                                         Déclencher Escalade Critique (Crisis Room)
                                    </button>
                                )}
                            </div>

                        </div>

                    </div>
                )}

            </div>
        </div>
    );
}