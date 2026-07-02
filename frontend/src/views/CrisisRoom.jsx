import { useState, useEffect, useRef } from 'react';
import { ShieldCheck } from 'lucide-react';
import { resolveAlert } from '../services/api';
import { Card, Badge, Button, EmptyState, ReadOnlyNotice } from '../components/ui/primitives';

const AUTO_REFRESH_INTERVAL_MS = 5000;

const CHECKLIST_ITEMS = [
    { key: 'blockIP', title: 'IP attaquante traitée', desc: 'Blocage confirmé (via Playbooks SOAR ou action externe).' },
    { key: 'isolateHost', title: 'Machine confinée', desc: 'Isolation confirmée (aucun agent EDR intégré au SIEM — action externe).' },
    { key: 'resetCredentials', title: 'Session révoquée', desc: 'Compte désactivé via Playbooks SOAR (disable_account, action réelle).' },
    { key: 'syslogExport', title: 'Rapport forensics', desc: 'Artefacts sauvegardés et dossier exporté.' },
];

/**
 * Salle de crise — suivi des incidents majeurs escaladés, rafraîchissement
 * automatique réel toutes les 5 secondes (exigence CDC).
 */
export default function CrisisRoom({ user, logs, setLogs, onRefresh }) {
    const activeIncidents = logs.filter((log) => log.escalated === true);

    const [lastRefreshAt, setLastRefreshAt] = useState(new Date());
    const refreshInFlight = useRef(false);

    useEffect(() => {
        if (!onRefresh) return undefined;
        const tick = async () => {
            if (refreshInFlight.current) return;
            refreshInFlight.current = true;
            try { await onRefresh(); setLastRefreshAt(new Date()); } finally { refreshInFlight.current = false; }
        };
        const intervalId = setInterval(tick, AUTO_REFRESH_INTERVAL_MS);
        return () => clearInterval(intervalId);
    }, [onRefresh]);

    const [selectedIncident, setSelectedIncident] = useState(null);
    const [playbookSteps, setPlaybookSteps] = useState({ blockIP: false, isolateHost: false, resetCredentials: false, syslogExport: false });

    const isReadOnly = user?.role !== 'administrator';
    const currentIncident = selectedIncident && activeIncidents.some((i) => i.id === selectedIncident.id)
        ? activeIncidents.find((i) => i.id === selectedIncident.id)
        : activeIncidents[0];

    const handleSelectIncident = (incident) => {
        setSelectedIncident(incident);
        setPlaybookSteps({ blockIP: false, isolateHost: false, resetCredentials: false, syslogExport: false });
    };

    const handleResolveIncident = async (incidentId) => {
        if (isReadOnly) return;
        const incident = logs.find((l) => l.id === incidentId);
        setLogs((prev) => prev.map((log) => (log.id === incidentId ? { ...log, escalated: false, status: 'TRAITÉ' } : log)));
        setSelectedIncident(null);
        setPlaybookSteps({ blockIP: false, isolateHost: false, resetCredentials: false, syslogExport: false });

        if (incident?._realId) {
            try {
                await resolveAlert(incident._realId, `Incident clôturé en salle de crise par ${user?.name || user?.user}`);
                onRefresh?.();
            } catch (err) {
                console.warn('resolveAlert failed:', err.message);
            }
        }
    };

    if (activeIncidents.length === 0) {
        return <EmptyState icon={ShieldCheck} title="Périmètre sécurisé" description="Aucun incident majeur n'est actif. Tous les flux sont nominaux." />;
    }

    const allStepsCompleted = Object.values(playbookSteps).every(Boolean);

    return (
        <div className="space-y-5">
            {isReadOnly && <ReadOnlyNotice role={user?.role} action="exécuter les contre-mesures d'incident majeur" />}

            <div className="flex flex-col items-start justify-between gap-4 border-b pb-5 md:flex-row md:items-center" style={{ borderColor: 'var(--border-subtle)' }}>
                <div>
                    <p className="mb-1 text-xs font-medium uppercase tracking-wide" style={{ color: '#f87171' }}>Salle de crise</p>
                    <h1 className="text-2xl font-semibold tracking-tight" style={{ color: 'var(--text-primary)' }}>Incidents majeurs</h1>
                </div>
                <div className="flex items-center gap-3">
                    <Badge tone="CRITICAL">{activeIncidents.length} menace(s) active(s)</Badge>
                    <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                        <span className="relative flex h-2 w-2">
                            <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-75" style={{ background: '#34d399' }} />
                            <span className="relative inline-flex h-2 w-2 rounded-full" style={{ background: '#34d399' }} />
                        </span>
                        Actualisation 5s · {lastRefreshAt.toLocaleTimeString('fr-FR')}
                    </div>
                </div>
            </div>

            <div className="flex flex-col gap-5 lg:flex-row">
                <div className="space-y-2.5 lg:w-1/3">
                    {activeIncidents.map((incident) => (
                        <button
                            key={incident.id}
                            onClick={() => handleSelectIncident(incident)}
                            className="w-full rounded-lg border p-3.5 text-left transition-colors"
                            style={{
                                borderColor: currentIncident.id === incident.id ? '#ef4444' : 'var(--border-subtle)',
                                background: currentIncident.id === incident.id ? 'rgba(239,68,68,0.08)' : 'var(--surface-2)',
                            }}
                        >
                            <div className="mb-1.5 flex items-center justify-between">
                                <Badge tone="CRITICAL">Priorité maximale</Badge>
                                <span className="text-[11px]" style={{ color: 'var(--text-muted)' }}>{incident.timestamp}</span>
                            </div>
                            <p className="truncate text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{incident.id}</p>
                            <p className="mt-0.5 text-xs" style={{ color: 'var(--text-muted)' }}>Source : {incident.source}</p>
                            <p className="mt-2 line-clamp-2 rounded-md p-2 text-xs" style={{ background: 'var(--surface-1)', color: 'var(--text-secondary)' }}>{incident.event}</p>
                        </button>
                    ))}
                </div>

                <Card className="lg:flex-1">
                    <div className="mb-4 flex flex-col justify-between gap-2 border-b pb-4 md:flex-row md:items-center" style={{ borderColor: 'var(--border-subtle)' }}>
                        <div>
                            <p className="text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Incident sélectionné</p>
                            <p className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>{currentIncident.id}</p>
                            <p className="mt-0.5 text-xs" style={{ color: 'var(--text-muted)' }}>Service : {currentIncident.service?.toUpperCase() || 'N/A'}</p>
                        </div>
                        <div className="rounded-lg border p-2 text-right" style={{ borderColor: 'var(--border-subtle)' }}>
                            <p className="text-[10px] uppercase" style={{ color: 'var(--text-muted)' }}>IP attaquante</p>
                            <p className="select-all text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{currentIncident.source}</p>
                        </div>
                    </div>

                    <div className="mb-4">
                        <p className="mb-1.5 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Preuve technique</p>
                        <pre className="max-h-40 overflow-auto rounded-lg border p-3.5 text-xs leading-relaxed" style={{ borderColor: 'var(--border-subtle)', background: 'var(--surface-1)', color: 'var(--text-secondary)' }}>
                            {currentIncident.payload || JSON.stringify({ event: currentIncident.event }, null, 2)}
                        </pre>
                    </div>

                    <div className="mb-5">
                        <p className="mb-2.5 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
                            Checklist avant clôture (attestation analyste)
                        </p>
                        <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
                            {CHECKLIST_ITEMS.map((item) => (
                                <label
                                    key={item.key}
                                    className="flex items-start gap-2.5 rounded-lg border p-3 transition-colors"
                                    style={{
                                        borderColor: playbookSteps[item.key] ? 'var(--accent)' : 'var(--border-subtle)',
                                        background: playbookSteps[item.key] ? 'var(--accent-soft)' : 'transparent',
                                        opacity: isReadOnly ? 0.5 : 1,
                                        cursor: isReadOnly ? 'not-allowed' : 'pointer',
                                    }}
                                >
                                    <input
                                        type="checkbox" disabled={isReadOnly} checked={playbookSteps[item.key]}
                                        onChange={(e) => setPlaybookSteps({ ...playbookSteps, [item.key]: e.target.checked })}
                                        className="mt-0.5"
                                    />
                                    <div className="text-xs">
                                        <p className="font-medium" style={{ color: 'var(--text-primary)' }}>{item.title}</p>
                                        <p className="mt-0.5" style={{ color: 'var(--text-muted)' }}>{item.desc}</p>
                                    </div>
                                </label>
                            ))}
                        </div>
                    </div>

                    <div className="flex flex-col items-center justify-between gap-3.5 border-t pt-4 md:flex-row" style={{ borderColor: 'var(--border-subtle)' }}>
                        <p className="text-xs text-center md:text-left" style={{ color: 'var(--text-muted)' }}>
                            {isReadOnly ? 'Autorisation insuffisante pour clôturer.'
                                : !allStepsCompleted ? 'Cochez l\'ensemble des points pour valider la clôture.'
                                    : 'Protocole entièrement appliqué.'}
                        </p>
                        <Button variant="primary" disabled={isReadOnly || !allStepsCompleted} onClick={() => handleResolveIncident(currentIncident.id)}>
                            {isReadOnly ? 'Droits insuffisants' : 'Clôturer l\'incident'}
                        </Button>
                    </div>
                </Card>
            </div>
        </div>
    );
}
