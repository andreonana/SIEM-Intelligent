import { useState } from 'react';

export default function PlaybooksSOAR({ user, logs, setLogs }) {
    const [selectedAlert, setSelectedAlert] = useState(null);
    const [runningAction, setRunningAction] = useState(null);
    const [consoleLogs, setConsoleLogs] = useState([]);

    const isReader = user?.role === 'reader';

    // FILTRAGE ALIGNÉ SUR ALERT TRIAGE : Gravité (CRITICAL/WARNING) AND Non traité (Exclure FAUX_POSITIF et TRAITÉ)
    const activeAlerts = logs.filter(log => {
        const isAlert = log.severity === 'CRITICAL' || log.severity === 'WARNING';
        const isNotProcessed = log.status !== 'FAUX_POSITIF' && log.status !== 'TRAITÉ';
        return isAlert && isNotProcessed;
    });

    const countermeasures = [
        {
            id: "CMD-01",
            name: "Bannissement IP (WAF / Firewall)",
            icon: "🚫",
            desc: "Injecte une règle de Null-Route pour bloquer tout trafic entrant venant de l'IP cible."
        },
        {
            id: "CMD-02",
            name: "Isolation Réseau de l'Hôte (Agent EDR)",
            icon: "🔌",
            desc: "Coupe les connexions logiques de la machine pour stopper les scans ou déplacements latéraux."
        },
        {
            id: "CMD-03",
            name: "Révocation de Session IAM & Force MFA",
            icon: "🔐",
            desc: "Tuer les tokens OAuth/Active Directory et force l'utilisateur à réinitialiser son mot de passe."
        }
    ];

    // LOGIQUE ALIGNÉE SUR LE NETTOYAGE DYNAMIQUE
    const handleExecuteCountermeasure = (cmd, alertId) => {
        if (isReader) return;

        setRunningAction({ cmdId: cmd.id, alertId: alertId });
        setConsoleLogs([`[SOAR] Lancement manuel de la contre-mesure : ${cmd.name}`]);

        setTimeout(() => {
            setConsoleLogs(prev => [...prev, `[LINK] Connexion API établie avec l'infrastructure réseau.`]);
        }, 600);

        setTimeout(() => {
            setConsoleLogs(prev => [...prev, `[SUCCESS] Confinement appliqué avec succès.`]);
            
            // ICI : On applique EXACTEMENT la même mutation que handleUpdateSingleStatus de ton AlertTriage
            setLogs(prevLogs => prevLogs.map(log => 
                log.id === alertId ? { ...log, status: 'TRAITÉ', escalated: false } : log
            ));

            // Petit délai pour donner un feedback visuel du SUCCESS à l'opérateur, puis fermeture
            setTimeout(() => {
                setSelectedAlert(null); // <-- Ferme l'inspecteur central de la même façon
                setRunningAction(null);
            }, 800);

        }, 1600);
    };

    return (
        <div className="space-y-6 font-mono text-sm animate-in fade-in duration-300">
            
            {/* EN-TÊTE CONFIGURATION COMPOSANT */}
            <div className="flex justify-between items-center border-b border-slate-800 pb-4">
                <div>
                    <span className="text-xs font-bold uppercase tracking-[0.3em] text-emerald-400 block">Centre d’orchestration des threats</span>
                    <h1 className="text-2xl font-black text-white mt-1">Playbook interactif</h1>
                </div>
                <div className="bg-[#111827] border border-slate-800 px-3 py-1.5 rounded-md text-xs text-slate-400">
                    File d'attente Playbook : <span className="text-amber-400 font-bold">{activeAlerts.length} alertes</span>
                </div>
            </div>

            {/* SPLIT VIEW DE TRAVAIL */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
                
                {/* COLONNE 1 : SÉLECTION DE L'ALERTE À TRAITER */}
                <div className="lg:col-span-1 bg-[#0f172a] border border-slate-800 rounded-xl p-4 space-y-3">
                    <span className="text-slate-500 text-xs font-bold block uppercase tracking-wider">1. Choisir l’alerte active</span>
                    
                    <div className="space-y-2 max-h-[450px] overflow-y-auto pr-1">
                        {activeAlerts.length === 0 ? (
                            <div className="text-[#10b981] text-center py-8 italic border border-dashed border-emerald-800/40 bg-emerald-950/10 rounded-xl">
                                💚 Tout est traité. File d'attente vide.
                            </div>
                        ) : (
                            activeAlerts.map((alert) => (
                                <div
                                    key={alert.id}
                                    onClick={() => !runningAction && setSelectedAlert(alert)}
                                    className={`p-3 rounded-lg border text-left cursor-pointer transition-all ${
                                        selectedAlert?.id === alert.id
                                            ? 'bg-cyan-950/40 border-cyan-500 text-white'
                                            : 'bg-[#111827]/80 border-slate-800 hover:border-slate-700 text-slate-300'
                                    } ${runningAction ? 'opacity-50 cursor-not-allowed' : ''}`}
                                >
                                    <div className="flex justify-between items-center mb-1.5">
                                        <div className="flex items-center gap-1.5">
                                            <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold border ${
                                                alert.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border-red-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                                            }`}>
                                                {alert.severity}
                                            </span>
                                            {alert.escalated && <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>}
                                        </div>
                                        <span className="text-[10px] text-slate-500">{alert.status || 'NON_TRAITÉ'}</span>
                                    </div>
                                    <div className="text-xs font-bold truncate text-slate-200">{alert.source}</div>
                                    <div className="text-[11px] text-slate-400 font-sans mt-1 line-clamp-2 italic">"{alert.event}"</div>
                                    {(alert.mitre_tactic_id || alert.mitre_technique_id) && (
                                        <div className="mt-2 text-[11px] text-slate-400">
                                            {alert.mitre_tactic_id && <div className="font-bold text-slate-200">{alert.mitre_tactic_id} — {alert.mitre_tactic_name}</div>}
                                            {alert.mitre_technique_id && <div>{alert.mitre_technique_id} — {alert.mitre_technique_name}</div>}
                                        </div>
                                    )}
                                </div>
                            ))
                        )}
                    </div>
                </div>

                {/* COLONNE 2 & 3 : VUE COMPLÈTE DE L'ALERTE ET SES CONTRE-MESURES */}
                <div className="lg:col-span-2 space-y-6">
                    {selectedAlert ? (
                        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-6 space-y-6 relative overflow-hidden">
                            
                            {/* INDICATEUR SPECIFIQUE : TRANSMIS À LA CRISIS ROOM */}
                            {selectedAlert.escalated && (
                                <div className="bg-red-950/40 border border-red-700/50 rounded-lg p-3 flex items-center justify-between animate-pulse">
                                    <div className="flex items-center gap-2">
                                        <span className="text-sm text-red-400">•</span>
                                        <span className="text-xs font-black text-red-400 uppercase tracking-wide">Incident en cours dans la crisis room</span>
                                    </div>
                                    <span className="text-[9px] bg-red-500 text-white font-black px-2 py-0.5 rounded uppercase tracking-wider">Priorité max</span>
                                </div>
                            )}

                            {/* INSPECTION COMPLÈTE DE L'ALERTE */}
                            <div className="space-y-4 border-b border-slate-800/80 pb-5">
                                <div className="flex justify-between items-start">
                                    <div>
                                        <span className="text-[10px] text-cyan-400 font-bold block tracking-widest">Alerte en inspection playbook</span>
                                        <h2 className="text-lg font-black text-white mt-0.5">{selectedAlert.id}</h2>
                                    </div>
                                    <button 
                                        disabled={runningAction !== null}
                                        onClick={() => setSelectedAlert(null)} 
                                        className="text-xs text-slate-500 hover:text-slate-300 bg-slate-900 border border-slate-800 px-2 py-1 rounded cursor-pointer"
                                    >
                                        Fermer la fiche
                                    </button>
                                </div>

                                <div className="grid grid-cols-2 gap-4 bg-[#111827] p-3 rounded-lg border border-slate-800/60 text-xs">
                                    <div><span className="text-slate-500">Cible Réseau :</span> <span className="text-cyan-400 font-bold block select-all">{selectedAlert.source}</span></div>
                                    <div><span className="text-slate-500">Microservice :</span> <span className="text-slate-300 font-bold block">{selectedAlert.service || 'N/A'}</span></div>
                                </div>

                                <div className="space-y-1">
                                    <span className="text-[10px] text-slate-500 uppercase font-bold block">Contenu de l’alerte</span>
                                    <p className="bg-[#111827] text-slate-200 p-3 rounded-lg border border-slate-800 text-xs font-sans italic leading-relaxed">
                                        "{selectedAlert.event}"
                                    </p>
                                </div>

                                {(selectedAlert.mitre_tactic_id || selectedAlert.mitre_technique_id) && (
                                    <div className="mt-3 bg-[#0b1220] p-3 rounded-lg border border-slate-800 text-sm">
                                        <div className="text-[11px] text-slate-500 uppercase font-bold mb-1">Contexte MITRE ATT&CK</div>
                                        {selectedAlert.mitre_tactic_id && <div className="font-bold text-slate-200">{selectedAlert.mitre_tactic_id} — {selectedAlert.mitre_tactic_name}</div>}
                                        {selectedAlert.mitre_technique_id && <div className="text-slate-400">{selectedAlert.mitre_technique_id} — {selectedAlert.mitre_technique_name}</div>}
                                    </div>
                                )}

                                {selectedAlert.payload && (
                                    <div className="space-y-1">
                                        <span className="text-[10px] text-slate-500 uppercase font-bold block">Payload métadonnées (JSON)</span>
                                        <pre className="text-[11px] text-amber-400 bg-slate-950 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap border border-slate-900 max-h-32 shadow-inner">
                                            {selectedAlert.payload}
                                        </pre>
                                    </div>
                                )}
                            </div>

                            {/* CATALOGUE DE CONTRE-MESURES POSSIBLES */}
                            <div className="space-y-4">
                                <span className="text-emerald-400 text-xs font-black block uppercase tracking-wider">Actions disponibles</span>
                                
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                                    {countermeasures.map((cmd) => (
                                        <div 
                                            key={cmd.id}
                                            className="bg-[#111827]/80 border border-slate-800/80 p-4 rounded-xl flex flex-col justify-between space-y-4 hover:border-slate-700 transition-all group"
                                        >
                                            <div className="space-y-1.5">
                                                <div className="flex items-center gap-2">
                                                    <span className="text-[10px] font-bold text-slate-500 group-hover:text-cyan-400 transition-colors">{cmd.id}</span>
                                                </div>
                                                <h4 className="text-xs font-black text-white tracking-tight leading-tight">{cmd.name}</h4>
                                                <p className="text-[11px] text-slate-400 font-sans leading-normal">{cmd.desc}</p>
                                            </div>

                                            <button
                                                disabled={runningAction !== null || isReader}
                                                onClick={() => handleExecuteCountermeasure(cmd, selectedAlert.id)}
                                                className={`w-full py-2 rounded-lg text-[11px] font-bold tracking-wider cursor-pointer transition-all border uppercase ${
                                                    runningAction 
                                                        ? 'bg-slate-800 text-slate-500 border-slate-700 cursor-not-allowed'
                                                        : 'bg-emerald-950/20 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500 hover:text-white hover:border-emerald-500 shadow-sm'
                                                }`}
                                            >
                                                Appliquer {cmd.id}
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* POP-UP / TERMINAL DE MITIGATION APPRÊTÉ */}
                            {runningAction?.alertId === selectedAlert.id && (
                                <div className="absolute inset-0 bg-[#090d1a]/95 flex flex-col justify-center p-6 border border-cyan-500/30 rounded-xl animate-in fade-in duration-200">
                                    <div className="max-w-md mx-auto w-full space-y-3 bg-[#0f172a] p-5 rounded-xl border border-slate-800 shadow-2xl">
                                        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                                            <span className="text-cyan-400 font-bold text-xs tracking-widest">Orchestration en cours</span>
                                            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
                                        </div>
                                        <div className="space-y-1.5 max-h-40 overflow-y-auto text-xs">
                                            {consoleLogs.map((log, index) => (
                                                <div 
                                                    key={index} 
                                                    className={`${log.includes('SUCCESS') ? 'text-emerald-400 font-bold' : 'text-slate-300'}`}
                                                >
                                                    {log}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            )}

                        </div>
                    ) : (
                        <div className="bg-[#0f172a] border border-slate-800 border-dashed rounded-xl p-12 text-center text-slate-500 italic flex flex-col items-center justify-center min-h-[400px]">
                            <span>Aucun événement en cours d’analyse.</span>
                            <span className="text-[11px] text-slate-600 font-sans mt-1">Sélectionnez une alerte active à gauche pour dérouler le playbook de contre-mesures.</span>
                        </div>
                    )}
                </div>

            </div>
        </div>
    );
}