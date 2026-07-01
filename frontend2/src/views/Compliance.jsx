function isResolved(log) {
    const status = log.status || '';
    return status === 'TRAITÉ' || status === 'TRAITE' || status === 'FAUX_POSITIF';
}

function isDataPrivacyRelated(log) {
    const text = `${log.event || ''} ${log.payload || ''} ${log.service || ''}`.toLowerCase();
    return (
        text.includes('exfiltration') ||
        text.includes('données personnelles') ||
        text.includes('personal data') ||
        text.includes('fuite de') ||
        text.includes('breach') ||
        text.includes('rgpd') ||
        text.includes('violation de données')
    );
}

const STATUS_BADGE = {
    compliant: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400',
    warning: 'border-amber-500/20 bg-amber-500/10 text-amber-400',
    alert: 'border-red-500/20 bg-red-500/10 text-red-400',
};

export default function Compliance({ user, logs, setActiveView }) {
    const activeIncidentsCount = logs.filter((l) => l.escalated === true).length;
    const unresolvedCriticals = logs.filter(
        (l) => l.severity === 'CRITICAL' && !isResolved(l)
    ).length;
    const pendingRssiCount = logs.filter((l) => l.escalated && l.status === 'EN_ATTENTE_RSSI').length;

    const isoScore = Math.max(55, 94 - unresolvedCriticals * 5 - activeIncidentsCount * 2);
    const rgpdScore = Math.max(50, 91 - unresolvedCriticals * 6 - pendingRssiCount * 3);
    const overallCompliance = Math.round((isoScore + rgpdScore) / 2);
    const openActions = activeIncidentsCount + unresolvedCriticals;

    const dataViolations = logs.filter(
        (log) =>
            log.severity === 'CRITICAL' &&
            !isResolved(log) &&
            (log.escalated || isDataPrivacyRelated(log))
    );

    const isReader = user?.role === 'reader';
    const isAdmin = user?.role === 'administrator';
    const canViewCrisis = user?.role === 'analyst' || isAdmin;

    const controls = [
        {
            id: 'logging',
            label: 'A.12.4.1 — Journalisation',
            detail: `${logs.length} événements indexés dans le SIEM.`,
            status: logs.length > 0 ? 'Conforme' : 'À vérifier',
            tone: logs.length > 0 ? 'compliant' : 'warning',
        },
        {
            id: 'incidents',
            label: 'A.16.1 — Gestion des incidents',
            detail:
                activeIncidentsCount === 0
                    ? 'Aucune crise escaladée en cours.'
                    : `${activeIncidentsCount} incident(s) majeur(s) en cellule de crise.`,
            status: activeIncidentsCount === 0 ? 'Conforme' : 'Sous surveillance',
            tone: activeIncidentsCount === 0 ? 'compliant' : 'warning',
        },
        {
            id: 'privacy',
            label: 'Art. 33 RGPD — Notification de violation',
            detail:
                dataViolations.length === 0
                    ? 'Aucune alerte critique liée aux données personnelles.'
                    : `${dataViolations.length} alerte(s) à évaluer pour notification DPO.`,
            status: dataViolations.length === 0 ? 'Conforme' : 'Action requise',
            tone: dataViolations.length === 0 ? 'compliant' : 'alert',
        },
    ];

    const quickLinks = [
        canViewCrisis && {
            id: 'crisis',
            label: 'Crisis Room',
            description: `${activeIncidentsCount} incident(s) escaladé(s)`,
            highlight: activeIncidentsCount > 0,
        },
        isAdmin && {
            id: 'audit',
            label: 'Audit Trail',
            description: 'Traçabilité des actions opérateurs',
            highlight: false,
        },
        {
            id: 'reports',
            label: 'Rapports Cyber',
            description: "Export PDF d'audit de conformité",
            highlight: false,
        },
    ].filter(Boolean);

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="flex flex-col gap-4 border-b border-slate-800 pb-5 md:flex-row md:items-start md:justify-between">
                <div>
                    <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.3em] text-cyan-400">
                        <span className="h-2 w-2 rounded-full bg-cyan-500 shadow-[0_0_8px_rgba(6,182,212,0.4)]" />
                        <span>Conformité &amp; gouvernance</span>
                    </div>
                    <h1 className="text-3xl font-black text-white">Tableau de conformité</h1>
                    <p className="mt-1 max-w-2xl text-sm text-slate-400">
                        Vue RSSI et auditeur : posture réglementaire, obligations RGPD et pression de remédiation.
                        Les opérations quotidiennes restent sur le Dashboard et le triage des alertes.
                    </p>
                </div>
                <div className="rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3 text-sm text-slate-400 shadow-lg">
                    Rétention légale
                    <span className="ml-2 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 font-semibold text-emerald-400">
                        60 jours — OK
                    </span>
                </div>
            </div>

            {isReader && (
                <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 p-4 font-mono text-xs text-cyan-300">
                    <strong className="uppercase">Mode lecture :</strong> Vue synthèse pour le suivi de conformité.
                    Les actions de remédiation sont réservées aux analystes et administrateurs.
                </div>
            )}

            <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
                <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-400">
                                Posture globale
                            </p>
                            <p className="mt-2 text-4xl font-black text-white">{overallCompliance}%</p>
                        </div>
                        <div
                            className={`rounded-2xl border px-3 py-2 text-sm font-semibold ${
                                activeIncidentsCount === 0
                                    ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300'
                                    : 'border-amber-500/20 bg-amber-500/10 text-amber-300'
                            }`}
                        >
                            {activeIncidentsCount === 0 ? 'Stable' : 'Sous surveillance'}
                        </div>
                    </div>
                    <p className="mt-3 text-xs text-slate-500">
                        Score calculé à partir des alertes critiques non résolues ({unresolvedCriticals}) et des
                        incidents escaladés ({activeIncidentsCount}). Baisse automatique tant qu'une remédiation
                        est en cours.
                    </p>
                    <div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-950">
                        <div
                            className="h-full rounded-full bg-cyan-500 transition-all duration-700"
                            style={{ width: `${overallCompliance}%` }}
                        />
                    </div>
                    <div className="mt-4 grid gap-3 sm:grid-cols-3">
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                            <p className="text-[11px] uppercase tracking-[0.25em] text-slate-500">ISO 27001</p>
                            <p className="mt-1 text-xl font-bold text-white">{isoScore}%</p>
                            <p className="mt-1 text-[10px] text-slate-600">Incidents + criticité ouverte</p>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                            <p className="text-[11px] uppercase tracking-[0.25em] text-slate-500">RGPD</p>
                            <p className="mt-1 text-xl font-bold text-white">{rgpdScore}%</p>
                            <p className="mt-1 text-[10px] text-slate-600">Risque données + demandes RSSI</p>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                            <p className="text-[11px] uppercase tracking-[0.25em] text-slate-500">Actions ouvertes</p>
                            <p className="mt-1 text-xl font-bold text-white">{openActions}</p>
                            <p className="mt-1 text-[10px] text-slate-600">Critiques + crises actives</p>
                        </div>
                    </div>
                </div>

                <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
                    <p className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-400">
                        Modules liés
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                        Accès direct aux vues utilisées pour l'audit et la remédiation.
                    </p>
                    <div className="mt-4 space-y-2">
                        {quickLinks.map((link) => (
                            <button
                                key={link.id}
                                type="button"
                                onClick={() => setActiveView?.(link.id)}
                                className={`flex w-full items-center justify-between rounded-xl border p-3 text-left transition-colors hover:border-cyan-500/40 hover:bg-slate-950/80 ${
                                    link.highlight
                                        ? 'border-amber-500/30 bg-amber-500/5'
                                        : 'border-slate-800 bg-slate-950/60'
                                }`}
                            >
                                <div>
                                    <p className="text-sm font-semibold text-slate-200">{link.label}</p>
                                    <p className="mt-0.5 text-xs text-slate-500">{link.description}</p>
                                </div>
                                <span className="text-slate-500">→</span>
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
                <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
                    <div className="flex items-center justify-between">
                        <h3 className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-300">
                            Alertes données personnelles
                        </h3>
                        <span className="rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-1 text-[10px] font-semibold text-amber-400">
                            Art. 33 RGPD
                        </span>
                    </div>
                    <p className="mt-2 text-xs text-slate-500">
                        Alertes critiques non résolues, escaladées ou explicitement liées aux données personnelles.
                    </p>
                    <div className="mt-4 space-y-3">
                        {dataViolations.length === 0 ? (
                            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-500">
                                Aucune alerte critique n'affecte actuellement les flux de données personnelles.
                            </div>
                        ) : (
                            dataViolations.map((violation) => (
                                <div
                                    key={violation.id}
                                    className="rounded-xl border border-slate-800 bg-slate-950/60 p-4"
                                >
                                    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                                        <div>
                                            <div className="flex flex-wrap items-center gap-2">
                                                <span className="h-2.5 w-2.5 rounded-full bg-red-500" />
                                                <span className="text-sm font-semibold text-white">
                                                    {violation.id}
                                                </span>
                                                <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-cyan-400">
                                                    {violation.service}
                                                </span>
                                                {violation.escalated && (
                                                    <span className="rounded-full border border-red-500/20 bg-red-500/10 px-2 py-0.5 text-[10px] font-semibold text-red-400">
                                                        Escaladé
                                                    </span>
                                                )}
                                            </div>
                                            <p className="mt-2 text-sm text-slate-400">{violation.event}</p>
                                        </div>
                                        <div className="flex items-center gap-3">
                                            <span className="rounded-full border border-red-500/20 bg-red-500/10 px-2.5 py-1 text-[10px] font-semibold text-red-400">
                                                Évaluation DPO
                                            </span>
                                            <span className="text-xs text-slate-500">{violation.timestamp}</span>
                                        </div>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>

                <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
                    <h3 className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-300">
                        Contrôles clés
                    </h3>
                    <p className="mt-1 text-xs text-slate-500">
                        Statut dérivé des données live du SIEM, pas d'indicateurs figés.
                    </p>
                    <div className="mt-4 space-y-3">
                        {controls.map((control) => (
                            <div
                                key={control.id}
                                className="rounded-xl border border-slate-800 bg-slate-950/60 p-4"
                            >
                                <div className="flex items-start justify-between gap-3">
                                    <div>
                                        <p className="font-semibold text-slate-200">{control.label}</p>
                                        <p className="mt-1 text-sm text-slate-400">{control.detail}</p>
                                    </div>
                                    <span
                                        className={`shrink-0 rounded-full border px-2 py-1 text-[10px] font-semibold ${STATUS_BADGE[control.tone]}`}
                                    >
                                        {control.status}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}
