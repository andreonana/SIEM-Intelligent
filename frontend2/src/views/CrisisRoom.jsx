import { useState } from 'react';

const RECOMMENDED_STEPS = [
    {
        key: 'blockIP',
        title: "1. Isoler l'IP Attaquante",
        description: (incident) => `Injecter un blocage sur le Pare-feu pour ${incident.source}`,
    },
    {
        key: 'isolateHost',
        title: '2. Confinement Machine',
        description: () => "Isoler l'hôte cible via l'agent EDR réseau",
    },
    {
        key: 'resetCredentials',
        title: '3. Révocation de Session',
        description: () => "Forcer l'expiration des accès Active Directory",
    },
    {
        key: 'syslogExport',
        title: '4. Rapport Forensics',
        description: () => 'Sauvegarder les artefacts et exporter le dossier',
    },
];

const CRISIS_STATUS_LABELS = {
    EN_COURS: 'En investigation',
    EN_ATTENTE_RSSI: 'En attente RSSI',
    REMEDIATION_EN_COURS: 'Remédiation en cours',
};

function getCrisisStatusClass(status) {
    if (status === 'EN_ATTENTE_RSSI') return 'border-amber-500/40 bg-amber-500/10 text-amber-400';
    if (status === 'REMEDIATION_EN_COURS') return 'border-cyan-500/40 bg-cyan-500/10 text-cyan-400';
    return 'border-red-500/40 bg-red-500/10 text-red-400';
}

function formatTimestamp() {
    return new Date().toLocaleString('fr-FR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    });
}

/**
 * COMPOSANT : CrisisRoom (Coordination des incidents majeurs — Option A)
 * Analyste : notes + demande d'intervention RSSI
 * Administrateur : exécution remédiation + clôture
 */
export default function CrisisRoom({ user, logs, setLogs }) {
    const activeIncidents = logs.filter((log) => log.escalated === true);

    const [selectedIncident, setSelectedIncident] = useState(null);
    const [noteDraft, setNoteDraft] = useState('');
    const [playbookSteps, setPlaybookSteps] = useState({
        blockIP: false,
        isolateHost: false,
        resetCredentials: false,
        syslogExport: false,
    });

    const isAdmin = user?.role === 'administrator';
    const isAnalyst = !isAdmin;

    const currentIncident =
        selectedIncident && activeIncidents.some((i) => i.id === selectedIncident.id)
            ? activeIncidents.find((i) => i.id === selectedIncident.id)
            : activeIncidents[0];

    const pendingRssiCount = activeIncidents.filter(
        (incident) => incident.status === 'EN_ATTENTE_RSSI'
    ).length;

    const crisisStatus = currentIncident?.status || 'EN_COURS';
    const crisisNotes = currentIncident?.crisisNotes || [];

    const handleSelectIncident = (incident) => {
        setSelectedIncident(incident);
        setNoteDraft('');
        setPlaybookSteps({
            blockIP: false,
            isolateHost: false,
            resetCredentials: false,
            syslogExport: false,
        });
    };

    const handleAddNote = () => {
        if (!currentIncident || !noteDraft.trim()) return;

        const newNote = {
            author: user?.name || 'Analyste',
            text: noteDraft.trim(),
            timestamp: formatTimestamp(),
        };

        setLogs((prevLogs) =>
            prevLogs.map((log) => {
                if (log.id !== currentIncident.id) return log;
                return {
                    ...log,
                    crisisNotes: [...(log.crisisNotes || []), newNote],
                };
            })
        );
        setNoteDraft('');
    };

    const handleRequestRssi = () => {
        if (!currentIncident || !isAnalyst) return;
        if (currentIncident.status === 'EN_ATTENTE_RSSI') return;

        setLogs((prevLogs) =>
            prevLogs.map((log) => {
                if (log.id !== currentIncident.id) return log;
                return {
                    ...log,
                    status: 'EN_ATTENTE_RSSI',
                    rssiRequestedAt: formatTimestamp(),
                    rssiRequestedBy: user?.name || 'Analyste',
                };
            })
        );
    };

    const handlePlaybookChange = (key, checked) => {
        if (!isAdmin) return;

        const nextSteps = { ...playbookSteps, [key]: checked };
        setPlaybookSteps(nextSteps);

        const anyChecked = Object.values(nextSteps).some(Boolean);
        if (anyChecked && crisisStatus !== 'REMEDIATION_EN_COURS') {
            setLogs((prevLogs) =>
                prevLogs.map((log) =>
                    log.id === currentIncident.id && log.status === 'EN_ATTENTE_RSSI'
                        ? { ...log, status: 'REMEDIATION_EN_COURS' }
                        : log
                )
            );
        }
    };

    const handleResolveIncident = (incidentId) => {
        if (!isAdmin) return;

        setLogs((prevLogs) =>
            prevLogs.map((log) => {
                if (log.id !== incidentId) return log;
                return { ...log, escalated: false, status: 'TRAITÉ' };
            })
        );

        setSelectedIncident(null);
        setPlaybookSteps({
            blockIP: false,
            isolateHost: false,
            resetCredentials: false,
            syslogExport: false,
        });
        setNoteDraft('');

        alert(
            `[CRISIS ROOM] L'incident ${incidentId} a été clôturé avec le statut [TRAITÉ] par ${user?.name || 'Administrateur'}.`
        );
    };

    if (activeIncidents.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[60vh] border border-dashed border-slate-800 rounded-2xl bg-[#0f172a]/40 p-8 text-center animate-in fade-in duration-500">
                <div className="text-4xl mb-4 text-emerald-400">•</div>
                <h2 className="text-xl font-bold text-slate-200 font-mono">Périmètre sécurisé</h2>
                <p className="text-xs text-slate-500 font-mono mt-2 max-w-md">
                    Aucun incident majeur n'est actif dans la cellule de crise. Tous les flux de production sont
                    nominaux.
                </p>
            </div>
        );
    }

    const allStepsCompleted =
        playbookSteps.blockIP &&
        playbookSteps.isolateHost &&
        playbookSteps.resetCredentials &&
        playbookSteps.syslogExport;

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {isAnalyst && (
                <div className="bg-amber-500/10 border border-amber-500/30 text-amber-400 p-4 rounded-xl font-mono text-xs flex items-center gap-3 shadow-[0_0_15px_rgba(245,158,11,0.05)]">
                    <span className="text-lg text-amber-400">•</span>
                    <div>
                        <strong className="uppercase">Mode coordination analyste :</strong> Connectée en tant que{' '}
                        <strong>{user?.name || "Chloe O'Brian"}</strong>. Documentez l'investigation, consultez le
                        plan de réponse recommandé, puis demandez l'intervention RSSI. L'exécution technique est
                        réservée à l'administrateur.
                    </div>
                </div>
            )}

            {isAdmin && pendingRssiCount > 0 && (
                <div className="bg-red-500/10 border border-red-500/30 text-red-300 p-4 rounded-xl font-mono text-xs flex items-center gap-3">
                    <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                    <div>
                        <strong className="uppercase text-red-400">Intervention requise :</strong>{' '}
                        {pendingRssiCount} incident{pendingRssiCount > 1 ? 's' : ''} en attente de remédiation
                        RSSI. Exécutez le protocole technique puis clôturez l'incident.
                    </div>
                </div>
            )}

            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-red-950 pb-5">
                <div>
                    <div className="flex items-center gap-2 text-xs font-mono text-red-400 mb-1 animate-pulse">
                        <span className="w-2 h-2 rounded-full bg-red-500" />
                        <span>[SALLE DE CRISE CYBER — CELLULE D'INCIDENT RESPONSE]</span>
                    </div>
                    <h1 className="text-3xl font-black text-white tracking-tight">Coordination des Incidents Majeurs</h1>
                </div>
                <div className="bg-red-950/20 border border-red-900/40 px-4 py-2 rounded-lg text-xs font-mono text-red-400">
                    Menaces actives :{' '}
                    <span className="font-bold text-white bg-red-500 px-1.5 py-0.5 rounded ml-1">
                        {activeIncidents.length}
                    </span>
                </div>
            </div>

            <div className="flex flex-col lg:flex-row gap-6">
                <div className="lg:w-1/3 space-y-3">
                    <span className="block text-slate-500 font-mono text-[10px] uppercase tracking-wider">
                        File des crises à traiter
                    </span>

                    {activeIncidents.map((incident) => {
                        const status = incident.status || 'EN_COURS';
                        return (
                            <div
                                key={incident.id}
                                onClick={() => handleSelectIncident(incident)}
                                className={`p-4 border rounded-xl cursor-pointer transition-all ${
                                    currentIncident.id === incident.id
                                        ? 'bg-red-950/20 border-red-500 shadow-lg'
                                        : 'bg-[#0f172a] border-slate-800/80 hover:border-red-900/60'
                                }`}
                            >
                                <div className="flex justify-between items-start mb-2 gap-2">
                                    <span
                                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${getCrisisStatusClass(status)}`}
                                    >
                                        {CRISIS_STATUS_LABELS[status] || CRISIS_STATUS_LABELS.EN_COURS}
                                    </span>
                                    <span className="text-[10px] font-mono text-slate-500 shrink-0">
                                        {incident.timestamp}
                                    </span>
                                </div>
                                <h3 className="text-sm font-bold text-white font-mono truncate">{incident.id}</h3>
                                <p className="text-xs text-slate-400 font-mono mt-1">Source: {incident.source}</p>
                                <p className="text-[11px] text-slate-500 font-mono mt-2 line-clamp-2 bg-slate-950/50 p-2 rounded border border-slate-900">
                                    {incident.event}
                                </p>
                                {incident.rssiRequestedBy && (
                                    <p className="text-[10px] font-mono text-amber-500/80 mt-2">
                                        Demande RSSI par {incident.rssiRequestedBy}
                                    </p>
                                )}
                            </div>
                        );
                    })}
                </div>

                <div className="lg:flex-1 bg-[#0f172a] border border-slate-800 rounded-xl p-6 flex flex-col space-y-6">
                    <div className="space-y-4">
                        <div className="border-b border-slate-800 pb-4 flex flex-col md:flex-row md:items-center justify-between gap-2">
                            <div>
                                <span className="text-[10px] font-mono text-slate-500 uppercase">
                                    Incident sélectionné
                                </span>
                                <div className="flex items-center gap-3 mt-1">
                                    <h2 className="text-xl font-mono font-black text-white">{currentIncident.id}</h2>
                                    <span
                                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${getCrisisStatusClass(crisisStatus)}`}
                                    >
                                        {CRISIS_STATUS_LABELS[crisisStatus] || CRISIS_STATUS_LABELS.EN_COURS}
                                    </span>
                                </div>
                                <p className="text-xs font-mono text-slate-400 mt-1">
                                    Service impacté :{' '}
                                    <span className="text-red-400 font-bold">
                                        {currentIncident.service?.toUpperCase() || 'N/A'}
                                    </span>
                                </p>
                            </div>
                            <div className="bg-slate-950 border border-slate-800 p-2 rounded text-right">
                                <span className="block text-[9px] font-mono text-slate-500 uppercase">
                                    IP Attaquante
                                </span>
                                <span className="text-xs font-mono font-bold text-emerald-400 select-all">
                                    {currentIncident.source}
                                </span>
                            </div>
                        </div>

                        <div className="space-y-2">
                            <span className="block text-slate-500 font-mono text-[10px] uppercase tracking-wider">
                                Preuve technique (payload JSON)
                            </span>
                            <pre className="text-xs text-amber-400/90 bg-slate-950 p-4 rounded-lg overflow-x-auto whitespace-pre-wrap border border-slate-900 shadow-inner max-h-40 font-mono leading-tight">
                                {currentIncident.payload ||
                                    JSON.stringify({ event: currentIncident.event }, null, 2)}
                            </pre>
                            {(currentIncident.mitre_tactic_id || currentIncident.mitre_technique_id) && (
                                <div className="mt-3 bg-[#0b1220] p-3 rounded-lg border border-slate-800 text-sm">
                                    <div className="text-[11px] text-slate-500 uppercase font-bold mb-1">
                                        Contexte MITRE ATT&CK
                                    </div>
                                    {currentIncident.mitre_tactic_id && (
                                        <div className="font-bold text-slate-200">
                                            {currentIncident.mitre_tactic_id} — {currentIncident.mitre_tactic_name}
                                        </div>
                                    )}
                                    {currentIncident.mitre_technique_id && (
                                        <div className="text-slate-400">
                                            {currentIncident.mitre_technique_id} —{' '}
                                            {currentIncident.mitre_technique_name}
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>

                        {/* Plan recommandé — lecture seule pour tous */}
                        <div className="space-y-3 pt-2">
                            <span className="block text-slate-500 font-mono text-[10px] uppercase tracking-wider">
                                Plan de réponse recommandé
                            </span>
                            <p className="text-[10px] font-mono text-slate-600">
                                Protocole suggéré selon la gravité de l'incident. L'analyste valide le contexte ;
                                seul le RSSI exécute les actions techniques.
                            </p>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                {RECOMMENDED_STEPS.map((step) => (
                                    <div
                                        key={step.key}
                                        className="flex items-start gap-3 p-3 border rounded-lg bg-[#111827] border-slate-800"
                                    >
                                        <span className="mt-0.5 text-slate-600 font-mono text-xs">○</span>
                                        <div className="text-xs font-mono">
                                            <span className="block font-bold text-slate-300">{step.title}</span>
                                            <span className="text-[10px] text-slate-500">
                                                {step.description(currentIncident)}
                                            </span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Notes d'investigation — analyste rédige, admin consulte */}
                        <div className="space-y-3 pt-2 border-t border-slate-800/60">
                            <span className="block text-slate-500 font-mono text-[10px] uppercase tracking-wider">
                                Notes d'investigation
                            </span>

                            {crisisNotes.length > 0 ? (
                                <div className="space-y-2 max-h-36 overflow-y-auto">
                                    {crisisNotes.map((note, index) => (
                                        <div
                                            key={`${note.timestamp}-${index}`}
                                            className="bg-slate-950 border border-slate-800 rounded-lg p-3"
                                        >
                                            <div className="flex justify-between text-[10px] font-mono text-slate-500 mb-1">
                                                <span className="text-cyan-400">{note.author}</span>
                                                <span>{note.timestamp}</span>
                                            </div>
                                            <p className="text-xs font-mono text-slate-300 whitespace-pre-wrap">
                                                {note.text}
                                            </p>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <p className="text-[11px] font-mono text-slate-600 italic">
                                    Aucune note pour cet incident. Documentez vos constats avant de solliciter le
                                    RSSI.
                                </p>
                            )}

                            {isAnalyst && (
                                <div className="space-y-2">
                                    <textarea
                                        value={noteDraft}
                                        onChange={(e) => setNoteDraft(e.target.value)}
                                        placeholder="Ex. : Brute force SSH confirmé sur admin, 15 tentatives en 3 min. Recommandation : blocage IP + révocation session."
                                        rows={3}
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-amber-500/50 resize-none"
                                    />
                                    <button
                                        type="button"
                                        onClick={handleAddNote}
                                        disabled={!noteDraft.trim()}
                                        className="font-mono text-xs font-bold px-4 py-2 rounded-lg border border-slate-700 bg-slate-900 text-slate-300 hover:border-amber-500/40 hover:text-amber-400 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                                    >
                                        Ajouter la note
                                    </button>
                                </div>
                            )}
                        </div>

                        {/* Actions analyste : demande RSSI */}
                        {isAnalyst && (
                            <div className="border-t border-slate-800/60 pt-4">
                                {crisisStatus === 'EN_ATTENTE_RSSI' ? (
                                    <div className="bg-amber-500/10 border border-amber-500/30 text-amber-400 p-3 rounded-lg font-mono text-xs">
                                        Demande transmise au RSSI
                                        {currentIncident.rssiRequestedAt && (
                                            <span className="text-amber-500/70">
                                                {' '}
                                                — {currentIncident.rssiRequestedAt}
                                            </span>
                                        )}
                                        . En attente d'exécution des contre-mesures.
                                    </div>
                                ) : (
                                    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                                        <p className="text-[11px] font-mono text-slate-500 max-w-md">
                                            Une fois l'investigation documentée, transmettez l'incident au RSSI pour
                                            exécution du protocole technique.
                                        </p>
                                        <button
                                            type="button"
                                            onClick={handleRequestRssi}
                                            className="shrink-0 font-mono text-xs font-bold px-5 py-2.5 rounded-lg border border-amber-500/50 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-colors uppercase tracking-wide"
                                        >
                                            Demander intervention RSSI
                                        </button>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Exécution remédiation — admin uniquement */}
                        {isAdmin && (
                            <div className="space-y-3 pt-2 border-t border-slate-800/60">
                                <span className="block text-slate-500 font-mono text-[10px] uppercase tracking-wider">
                                    Exécution remédiation RSSI
                                </span>
                                {currentIncident.rssiRequestedBy && (
                                    <p className="text-[10px] font-mono text-amber-500/80">
                                        Sollicité par {currentIncident.rssiRequestedBy}
                                        {currentIncident.rssiRequestedAt && ` — ${currentIncident.rssiRequestedAt}`}
                                    </p>
                                )}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    {RECOMMENDED_STEPS.map((step) => (
                                        <label
                                            key={step.key}
                                            className={`flex items-start gap-3 p-3 border rounded-lg transition-colors cursor-pointer ${
                                                playbookSteps[step.key]
                                                    ? 'bg-emerald-950/10 border-emerald-500/40 text-emerald-400'
                                                    : 'bg-[#111827] border-slate-800 hover:border-slate-700'
                                            }`}
                                        >
                                            <input
                                                type="checkbox"
                                                checked={playbookSteps[step.key]}
                                                onChange={(e) =>
                                                    handlePlaybookChange(step.key, e.target.checked)
                                                }
                                                className="mt-0.5 accent-emerald-500 cursor-pointer"
                                            />
                                            <div className="text-xs font-mono">
                                                <span className="block font-bold">{step.title}</span>
                                                <span className="text-[10px] text-slate-500">
                                                    {step.description(currentIncident)}
                                                </span>
                                            </div>
                                        </label>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>

                    {isAdmin && (
                        <div className="border-t border-slate-800/60 pt-5 flex flex-col md:flex-row items-center justify-between gap-4">
                            <div className="text-[11px] font-mono text-slate-500 text-center md:text-left">
                                {!allStepsCompleted
                                    ? "Cochez l'ensemble du protocole technique pour valider la remédiation globale."
                                    : 'Protocole entièrement appliqué. Prêt pour archivage.'}
                            </div>
                            <button
                                type="button"
                                onClick={() => handleResolveIncident(currentIncident.id)}
                                disabled={!allStepsCompleted}
                                className={`w-full md:w-auto font-mono text-xs font-bold px-6 py-3 rounded-lg transition-all text-center uppercase tracking-wide border ${
                                    allStepsCompleted
                                        ? 'bg-emerald-600 hover:bg-emerald-500 border-emerald-500 text-white cursor-pointer shadow-lg shadow-emerald-950/20'
                                        : 'bg-slate-900 border-slate-800/40 text-slate-600 cursor-not-allowed'
                                }`}
                            >
                                Menace neutralisée et close
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
