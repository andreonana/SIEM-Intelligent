import { useState } from 'react';

/**
 * COMPOSANT : CrisisRoom (Gestion des Incidents Majeurs interconnectée)
 * @param {Object} user - L'utilisateur connecté transmis par App.jsx
 * @param {Array} logs - L'état global des logs
 * @param {Function} setLogs - La fonction globale de mise à jour des logs
 */
export default function CrisisRoom({ user, logs, setLogs }) {
    // FILTRAGE GLOBAL : On extrait directement les incidents escaladés depuis la source de vérité
    const activeIncidents = logs.filter(log => log.escalated === true);

    // ÉTAT INDÉPENDANT : Incident sélectionné pour affichage/remédiation
    const [selectedIncident, setSelectedIncident] = useState(null);

    // ÉTAT : Suivi des étapes du Playbook SOAR de crise
    const [playbookSteps, setPlaybookSteps] = useState({
        blockIP: false,
        isolateHost: false,
        resetCredentials: false,
        syslogExport: false
    });

    // 🔒 CONTRÔLE D'ACCÈS (RBAC) : Seul 'bill' (Directeur/RSSI) peut appliquer les contre-mesures.
    const isReadOnly = user?.user !== 'bill';

    // Sécurité de sélection : s'aligner sur l'incident en cours ou par défaut le premier de la liste
    const currentIncident = selectedIncident && activeIncidents.some(i => i.id === selectedIncident.id)
        ? activeIncidents.find(i => i.id === selectedIncident.id)
        : activeIncidents[0];

    // Réinitialise le playbook quand on change de cible
    const handleSelectIncident = (incident) => {
        setSelectedIncident(incident);
        setPlaybookSteps({ blockIP: false, isolateHost: false, resetCredentials: false, syslogExport: false });
    };

    // Action globale : Clôture définitive de l'incident après application des mesures lourdes
    const handleResolveIncident = (incidentId) => {
        if (isReadOnly) return; // Sécurité anti-contournement
        
        // Mise à jour de la source de vérité (App.jsx) : l'incident repasse à escalated: false et devient TRAITÉ
        setLogs(prevLogs => prevLogs.map(log => {
            if (log.id === incidentId) {
                return { ...log, escalated: false, status: 'TRAITÉ' };
            }
            return log;
        }));
        
        // Reset des états locaux pour fermer la vue actuelle
        setSelectedIncident(null);
        setPlaybookSteps({ blockIP: false, isolateHost: false, resetCredentials: false, syslogExport: false });
        
        alert(`[CRISIS ROOM] L'incident ${incidentId} a été clôturé avec le statut [TRAITÉ] par Bill Buchanan.`);
    };

    // Si aucune crise n'est présente dans l'état global
    if (activeIncidents.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[60vh] border border-dashed border-slate-800 rounded-2xl bg-[#0f172a]/40 p-8 text-center animate-in fade-in duration-500">
                <div className="text-4xl mb-4 text-emerald-400">•</div>
                <h2 className="text-xl font-bold text-slate-200 font-mono">Périmètre sécurisé</h2>
                <p className="text-xs text-slate-500 font-mono mt-2 max-w-md">
                    Aucun incident majeur n'est actif dans la cellule de crise. Tous les flux de production sont nominaux.
                </p>
            </div>
        );
    }

    // Le bouton de clôture ne se débloque QUE si toutes les actions critiques ont été menées
    const allStepsCompleted = playbookSteps.blockIP && playbookSteps.isolateHost && playbookSteps.resetCredentials && playbookSteps.syslogExport;

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            
            {/* BANNIÈRE DE SÉCURITÉ CONTROLE D'ACCÈS (S'affiche pour Chloé) */}
            {isReadOnly && (
                <div className="bg-amber-500/10 border border-amber-500/30 text-amber-400 p-4 rounded-xl font-mono text-xs flex items-center gap-3 shadow-[0_0_15px_rgba(245,158,11,0.05)]">
                    <span className="text-lg text-amber-400">•</span>
                    <div>
                        <strong className="uppercase">Mode Consultation Uniquement :</strong> Vous êtes connectée en tant que <strong>{user?.name || "Chloe O'Brian"}</strong>. Vos privilèges de niveau 2 ne vous permettent pas d'exécuter des contre-mesures sur l'infrastructure. Seul l administrateur possède les clés d'activation du Playbook SOAR.
                    </div>
                </div>
            )}

            {/* ENTÊTE WAR ROOM */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-red-950 pb-5">
                <div>
                    <div className="flex items-center gap-2 text-xs font-mono text-red-400 mb-1 animate-pulse">
                        <span className="w-2 h-2 rounded-full bg-red-500"></span>
                        <span>[SALLE DE CRISE CYBER — CELLULE D'INCIDENT RESPONSE]</span>
                    </div>
                    <h1 className="text-3xl font-black text-white tracking-tight">Gestion des Incidents Majeurs</h1>
                </div>
                <div className="bg-red-950/20 border border-red-900/40 px-4 py-2 rounded-lg text-xs font-mono text-red-400">
                    Menaces actives : <span className="font-bold text-white bg-red-500 px-1.5 py-0.5 rounded ml-1">{activeIncidents.length}</span>
                </div>
            </div>

            {/* SPLIT SCREEN : FILE DES CRISES vs PLAYBOOK */}
            <div className="flex flex-col lg:flex-row gap-6">
                
                {/* GAUCHE : SÉLECTEUR D'INCIDENTS */}
                <div className="lg:w-1/3 space-y-3">
                    <span className="block text-slate-500 font-mono text-[10px] uppercase tracking-wider">File des crises à traiter</span>
                    
                    {activeIncidents.map((incident) => (
                        <div
                            key={incident.id}
                            onClick={() => handleSelectIncident(incident)}
                            className={`p-4 border rounded-xl cursor-pointer transition-all ${
                                currentIncident.id === incident.id
                                    ? 'bg-red-950/20 border-red-500 shadow-lg'
                                    : 'bg-[#0f172a] border-slate-800/80 hover:border-red-900/60'
                            }`}
                        >
                            <div className="flex justify-between items-start mb-2">
                                <span className="text-xs font-mono font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                                    Code rouge
                                </span>
                                <span className="text-[10px] font-mono text-slate-500">{incident.timestamp}</span>
                            </div>
                            <h3 className="text-sm font-bold text-white font-mono truncate">{incident.id}</h3>
                            <p className="text-xs text-slate-400 font-mono mt-1">Source: {incident.source}</p>
                            <p className="text-[11px] text-slate-500 font-mono mt-2 line-clamp-2 bg-slate-950/50 p-2 rounded border border-slate-900">
                                {incident.event}
                            </p>
                            {(incident.mitre_tactic_id || incident.mitre_technique_id) && (
                                <div className="mt-2 text-[11px] text-slate-400">
                                    {incident.mitre_tactic_id && <div className="font-bold text-slate-200">{incident.mitre_tactic_id} — {incident.mitre_tactic_name}</div>}
                                    {incident.mitre_technique_id && <div>{incident.mitre_technique_id} — {incident.mitre_technique_name}</div>}
                                </div>
                            )}
                        </div>
                    ))}
                </div>

                {/* DROITE : LE PLAN D'ACTION AVEC LES ACTIONS À MENER */}
                <div className="lg:flex-1 bg-[#0f172a] border border-slate-800 rounded-xl p-6 flex flex-col justify-between space-y-6">
                    
                    <div className="space-y-4">
                        <div className="border-b border-slate-800 pb-4 flex flex-col md:flex-row md:items-center justify-between gap-2">
                            <div>
                                <span className="text-[10px] font-mono text-slate-500 uppercase">Incident sélectionné</span>
                                <h2 className="text-xl font-mono font-black text-white">{currentIncident.id}</h2>
                                <p className="text-xs font-mono text-slate-400 mt-1">
                                    Service impacté : <span className="text-red-400 font-bold">{currentIncident.service?.toUpperCase() || 'N/A'}</span>
                                </p>
                            </div>
                            <div className="bg-slate-950 border border-slate-800 p-2 rounded text-right">
                                <span className="block text-[9px] font-mono text-slate-500 uppercase">IP Attaquante</span>
                                <span className="text-xs font-mono font-bold text-emerald-400 select-all">{currentIncident.source}</span>
                            </div>
                        </div>

                        {/* Payload technique */}
                        <div className="space-y-2">
                            <span className="block text-slate-500 font-mono text-[10px] uppercase tracking-wider">Preuve technique (payload JSON)</span>
                            <pre className="text-xs text-amber-400/90 bg-slate-950 p-4 rounded-lg overflow-x-auto whitespace-pre-wrap border border-slate-900 shadow-inner max-h-40 font-mono leading-tight">
                                {currentIncident.payload || JSON.stringify({ event: currentIncident.event }, null, 2)}
                            </pre>
                            {(currentIncident.mitre_tactic_id || currentIncident.mitre_technique_id) && (
                                <div className="mt-3 bg-[#0b1220] p-3 rounded-lg border border-slate-800 text-sm">
                                    <div className="text-[11px] text-slate-500 uppercase font-bold mb-1">Contexte MITRE ATT&CK</div>
                                    {currentIncident.mitre_tactic_id && <div className="font-bold text-slate-200">{currentIncident.mitre_tactic_id} — {currentIncident.mitre_tactic_name}</div>}
                                    {currentIncident.mitre_technique_id && <div className="text-slate-400">{currentIncident.mitre_technique_id} — {currentIncident.mitre_technique_name}</div>}
                                </div>
                            )}
                        </div>

                        {/* PLAYBOOK INTERACTIF : LES ACTIONS À MENER AVANT RÉSOLUTION */}
                        <div className="space-y-3 pt-2">
                            <span className="block text-slate-500 font-mono text-[10px] uppercase tracking-wider">Actions de remédiation à mener</span>
                            
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                {/* Étape 1 */}
                                <label className={`flex items-start gap-3 p-3 border rounded-lg transition-colors ${isReadOnly ? 'opacity-40 cursor-not-allowed bg-slate-900/50' : playbookSteps.blockIP ? 'bg-emerald-950/10 border-emerald-500/40 text-emerald-400 cursor-pointer' : 'bg-[#111827] border-slate-800 hover:border-slate-700 cursor-pointer'}`}>
                                    <input 
                                        type="checkbox" 
                                        disabled={isReadOnly}
                                        checked={playbookSteps.blockIP} 
                                        onChange={(e) => setPlaybookSteps({...playbookSteps, blockIP: e.target.checked})}
                                        className="mt-0.5 accent-emerald-500 disabled:cursor-not-allowed cursor-pointer"
                                    />
                                    <div className="text-xs font-mono">
                                        <span className="block font-bold">1. Isoler l'IP Attaquante</span>
                                        <span className="text-[10px] text-slate-500">Injecter un blocage sur le Pare-feu pour {currentIncident.source}</span>
                                    </div>
                                </label>

                                {/* Étape 2 */}
                                <label className={`flex items-start gap-3 p-3 border rounded-lg transition-colors ${isReadOnly ? 'opacity-40 cursor-not-allowed bg-slate-900/50' : playbookSteps.isolateHost ? 'bg-emerald-950/10 border-emerald-500/40 text-emerald-400 cursor-pointer' : 'bg-[#111827] border-slate-800 hover:border-slate-700 cursor-pointer'}`}>
                                    <input 
                                        type="checkbox" 
                                        disabled={isReadOnly}
                                        checked={playbookSteps.isolateHost} 
                                        onChange={(e) => setPlaybookSteps({...playbookSteps, isolateHost: e.target.checked})}
                                        className="mt-0.5 accent-emerald-500 disabled:cursor-not-allowed cursor-pointer"
                                    />
                                    <div className="text-xs font-mono">
                                        <span className="block font-bold">2. Confinement Machine</span>
                                        <span className="text-[10px] text-slate-500">Isoler l'hôte cible via l'agent EDR réseau</span>
                                    </div>
                                </label>

                                {/* Étape 3 */}
                                <label className={`flex items-start gap-3 p-3 border rounded-lg transition-colors ${isReadOnly ? 'opacity-40 cursor-not-allowed bg-slate-900/50' : playbookSteps.resetCredentials ? 'bg-emerald-950/10 border-emerald-500/40 text-emerald-400 cursor-pointer' : 'bg-[#111827] border-slate-800 hover:border-slate-700 cursor-pointer'}`}>
                                    <input 
                                        type="checkbox" 
                                        disabled={isReadOnly}
                                        checked={playbookSteps.resetCredentials} 
                                        onChange={(e) => setPlaybookSteps({...playbookSteps, resetCredentials: e.target.checked})}
                                        className="mt-0.5 accent-emerald-500 disabled:cursor-not-allowed cursor-pointer"
                                    />
                                    <div className="text-xs font-mono">
                                        <span className="block font-bold">3. Révocation de Session</span>
                                        <span className="text-[10px] text-slate-500">Forcer l'expiration des accès Active Directory</span>
                                    </div>
                                </label>

                                {/* Étape 4 */}
                                <label className={`flex items-start gap-3 p-3 border rounded-lg transition-colors ${isReadOnly ? 'opacity-40 cursor-not-allowed bg-slate-900/50' : playbookSteps.syslogExport ? 'bg-emerald-950/10 border-emerald-500/40 text-emerald-400 cursor-pointer' : 'bg-[#111827] border-slate-800 hover:border-slate-700 cursor-pointer'}`}>
                                    <input 
                                        type="checkbox" 
                                        disabled={isReadOnly}
                                        checked={playbookSteps.syslogExport} 
                                        onChange={(e) => setPlaybookSteps({...playbookSteps, syslogExport: e.target.checked})}
                                        className="mt-0.5 accent-emerald-500 disabled:cursor-not-allowed cursor-pointer"
                                    />
                                    <div className="text-xs font-mono">
                                        <span className="block font-bold">4. Rapport Forensics</span>
                                        <span className="text-[10px] text-slate-500">Sauvegarder les artefacts et exporter le dossier</span>
                                    </div>
                                </label>
                            </div>
                        </div>
                    </div>

                    {/* BLOC ACTIONS DE CLÔTURE DEFINITIVE */}
                    <div className="border-t border-slate-800/60 pt-5 flex flex-col md:flex-row items-center justify-between gap-4 mt-6">
                        <div className="text-[11px] font-mono text-slate-500 text-center md:text-left">
                            {isReadOnly 
                                ? "Autorisation insuffisante (niveau RSSI requis pour clore)." 
                                : !allStepsCompleted 
                                    ? "Cochez l'ensemble du protocole technique pour valider la remédiation globale."
                                    : "Protocole entièrement appliqué. Prêt pour archivage."
                            }
                        </div>
                        
                        <div className="flex w-full md:w-auto">
                            {/* Bouton Unique : Remédiation complète (Devient vert et cliquable si tout est validé) */}
                            <button
                                onClick={() => handleResolveIncident(currentIncident.id)}
                                disabled={isReadOnly || !allStepsCompleted}
                                className={`w-full md:w-auto font-mono text-xs font-bold px-6 py-3 rounded-lg transition-all text-center uppercase tracking-wide border ${
                                    !isReadOnly && allStepsCompleted
                                        ? 'bg-emerald-600 hover:bg-emerald-500 border-emerald-500 text-white cursor-pointer shadow-lg shadow-emerald-950/20'
                                        : 'bg-slate-900 border-slate-800/40 text-slate-600 cursor-not-allowed'
                                }`}
                            >
                                {isReadOnly ? "Droits insuffisants" : "Menace neutralisée et close"}
                            </button>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    );
}