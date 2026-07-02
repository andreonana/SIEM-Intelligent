import { useState } from 'react';
import { Ban, Send, KeySquare, CircleCheck, X, ShieldAlert } from 'lucide-react';
import { runPlaybook, resolveAlert } from '../services/api';
import { PageHeader, Card, Badge, Button, EmptyState, ReadOnlyNotice } from '../components/ui/primitives';

// Ne reflète QUE les 3 playbooks réellement exposés par le backend
// (GET /api/soar/playbooks) — aucune contre-mesure fictive.
const PLAYBOOK_MAP = { 'CMD-01': 'block_ip', 'CMD-02': 'escalate_admin', 'CMD-03': 'disable_account' };

const COUNTERMEASURES = [
    { id: 'CMD-01', name: 'Bannissement IP', icon: Ban, desc: 'Bloque le trafic entrant depuis l\'IP source via le service firewall réel.' },
    { id: 'CMD-02', name: 'Escalade admin', icon: Send, desc: 'Notifie les administrateurs en urgence (email/Slack/Teams réels).' },
    { id: 'CMD-03', name: 'Révocation de session', icon: KeySquare, desc: 'Désactive un compte utilisateur — nécessite de saisir son identifiant (les alertes réseau ne portent pas de nom d\'utilisateur).' },
];

/** Console d'orchestration SOAR — déclenchement réel des playbooks de réponse aux incidents. */
export default function PlaybooksSOAR({ user, logs, setLogs, onRefresh }) {
    const [selectedAlert, setSelectedAlert] = useState(null);
    const [runningAction, setRunningAction] = useState(null);
    const [consoleLogs, setConsoleLogs] = useState([]);

    const isReader = user?.role === 'reader';

    const activeAlerts = logs.filter((log) => {
        const isAlert = log.severity === 'CRITICAL' || log.severity === 'HIGH' || log.severity === 'WARNING';
        const isNotProcessed = log.status !== 'FAUX_POSITIF' && log.status !== 'TRAITÉ';
        return isAlert && isNotProcessed;
    });

    const handleExecuteCountermeasure = async (cmd, alert) => {
        if (isReader) return;
        const playbookId = PLAYBOOK_MAP[cmd.id] || 'block_ip';
        const reason = alert.event || alert.description || 'Alerte SIEM';
        const alertId = alert._realId || alert.id;

        // Les alertes réseau (basées IP/host) ne portent aucun nom d'utilisateur :
        // demander une saisie réelle plutôt que d'envoyer "unknown" au backend,
        // ce qui provoquait systématiquement un échec "user_not_found".
        let username = null;
        if (playbookId === 'disable_account') {
            username = window.prompt('Nom d\'utilisateur du compte à désactiver :', '');
            if (!username) return;
        }

        setRunningAction({ cmdId: cmd.id, alertId: alert.id });
        setConsoleLogs([`Lancement : ${cmd.name}`]);

        const params = playbookId === 'disable_account'
            ? { username, reason, alert_id: alertId }
            : playbookId === 'escalate_admin'
                ? { reason, alert_id: alertId, severity: alert.severity }
                : { ip: alert.source || alert.source_ip || 'unknown', reason, alert_id: alertId };

        try {
            setConsoleLogs((prev) => [...prev, `Appel → /api/soar/playbooks/${playbookId}/run`]);
            const result = await runPlaybook(playbookId, params);
            const status = result?.result?.status;

            if (status === 'failure' || status === 'user_not_found') {
                setConsoleLogs((prev) => [...prev, `Échec : ${result.result.error || 'Le playbook a échoué.'}`]);
            } else {
                setConsoleLogs((prev) => [...prev, `Playbook exécuté : ${status}`]);
                if (result?.result?.channels_notified?.length > 0) {
                    setConsoleLogs((prev) => [...prev, `Canaux notifiés : ${result.result.channels_notified.join(', ')}`]);
                } else if (playbookId === 'escalate_admin') {
                    setConsoleLogs((prev) => [...prev, 'Aucun canal de notification configuré (SMTP/Slack/Teams).']);
                }
                setLogs((prev) => prev.map((log) => (log.id === alert.id ? { ...log, status: 'TRAITÉ', escalated: false } : log)));

                // Le dispatcher SOAR ne met à jour que soar_status (executed/failed),
                // jamais le statut de l'alerte elle-même : sans cet appel explicite,
                // le backend la considère toujours "open" et elle réapparaît au
                // prochain rafraîchissement automatique.
                if (alert._realId) {
                    try {
                        await resolveAlert(alert._realId, `Contre-mesure "${cmd.name}" exécutée par ${user?.name || user?.user}`);
                    } catch (err) {
                        console.warn('resolveAlert failed:', err.message);
                    }
                }
                if (onRefresh) setTimeout(onRefresh, 1000);
            }
        } catch (err) {
            setConsoleLogs((prev) => [...prev, `Erreur : ${err.message}`]);
        } finally {
            setTimeout(() => { setSelectedAlert(null); setRunningAction(null); }, 1800);
        }
    };

    return (
        <div className="space-y-5">
            <PageHeader
                eyebrow="Réponse automatisée"
                title="Playbooks SOAR"
                description="Sélectionnez une alerte active pour déclencher une contre-mesure réelle."
                actions={<Badge tone="WARNING">{activeAlerts.length} alerte(s) en file</Badge>}
            />

            <div className="grid grid-cols-1 items-start gap-5 lg:grid-cols-3">
                <Card padded={false} className="lg:col-span-1">
                    <p className="border-b p-4 text-xs font-medium uppercase tracking-wide" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                        Alertes actives
                    </p>
                    <div className="max-h-[480px] space-y-1.5 overflow-y-auto p-2.5">
                        {activeAlerts.length === 0 ? (
                            <EmptyState icon={CircleCheck} title="File vide" description="Toutes les alertes sont traitées." />
                        ) : (
                            activeAlerts.map((alert) => (
                                <button
                                    key={alert.id}
                                    onClick={() => !runningAction && setSelectedAlert(alert)}
                                    disabled={!!runningAction}
                                    className="w-full rounded-lg border p-3 text-left text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50"
                                    style={{
                                        borderColor: selectedAlert?.id === alert.id ? 'var(--accent)' : 'var(--border-subtle)',
                                        background: selectedAlert?.id === alert.id ? 'var(--accent-soft)' : 'transparent',
                                    }}
                                >
                                    <div className="mb-1.5 flex items-center justify-between">
                                        <Badge tone={alert.severity}>{alert.severity}</Badge>
                                        <span className="text-[11px]" style={{ color: 'var(--text-muted)' }}>{alert.status || 'NON_TRAITÉ'}</span>
                                    </div>
                                    <p className="truncate text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{alert.source}</p>
                                    <p className="mt-1 line-clamp-2 text-xs" style={{ color: 'var(--text-muted)' }}>{alert.event}</p>
                                </button>
                            ))
                        )}
                    </div>
                </Card>

                <div className="lg:col-span-2">
                    {!selectedAlert ? (
                        <Card>
                            <EmptyState title="Aucune alerte sélectionnée" description="Choisissez une alerte à gauche pour dérouler ses contre-mesures." />
                        </Card>
                    ) : (
                        <Card className="relative">
                            {selectedAlert.escalated && (
                                <div className="mb-4 flex items-center gap-2 rounded-lg border px-3.5 py-2.5" style={{ borderColor: 'rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)' }}>
                                    <ShieldAlert size={15} style={{ color: '#f87171' }} />
                                    <span className="text-xs font-medium" style={{ color: '#fca5a5' }}>Incident actif en salle de crise</span>
                                </div>
                            )}

                            <div className="mb-4 flex items-start justify-between border-b pb-4" style={{ borderColor: 'var(--border-subtle)' }}>
                                <div>
                                    <p className="text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Alerte en inspection</p>
                                    <p className="mt-0.5 text-base font-semibold" style={{ color: 'var(--text-primary)' }}>{selectedAlert.id}</p>
                                </div>
                                <button onClick={() => setSelectedAlert(null)} disabled={!!runningAction} className="rounded-md p-1.5" style={{ color: 'var(--text-muted)' }}>
                                    <X size={16} />
                                </button>
                            </div>

                            <div className="mb-4 grid grid-cols-2 gap-3 rounded-lg border p-3 text-xs" style={{ borderColor: 'var(--border-subtle)' }}>
                                <div><span style={{ color: 'var(--text-muted)' }}>Cible :</span> <span className="block select-all font-medium" style={{ color: 'var(--text-primary)' }}>{selectedAlert.source}</span></div>
                                <div><span style={{ color: 'var(--text-muted)' }}>Service :</span> <span className="block font-medium" style={{ color: 'var(--text-primary)' }}>{selectedAlert.service || 'N/A'}</span></div>
                            </div>

                            <p className="mb-4 rounded-lg border p-3 text-sm" style={{ borderColor: 'var(--border-subtle)', background: 'var(--surface-1)', color: 'var(--text-secondary)' }}>
                                {selectedAlert.event}
                            </p>

                            {isReader ? (
                                <ReadOnlyNotice role="Lecteur" action="exécuter un playbook" />
                            ) : (
                                <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                                    {COUNTERMEASURES.map((cmd) => {
                                        const Icon = cmd.icon;
                                        return (
                                            <div key={cmd.id} className="flex flex-col justify-between gap-3 rounded-lg border p-3.5" style={{ borderColor: 'var(--border-subtle)' }}>
                                                <div>
                                                    <Icon size={17} strokeWidth={1.75} style={{ color: 'var(--text-muted)' }} className="mb-2" />
                                                    <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{cmd.name}</p>
                                                    <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>{cmd.desc}</p>
                                                </div>
                                                <Button variant="primary" disabled={!!runningAction} onClick={() => handleExecuteCountermeasure(cmd, selectedAlert)}>
                                                    Appliquer
                                                </Button>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}

                            {runningAction?.alertId === selectedAlert.id && (
                                <div className="absolute inset-0 flex items-center justify-center rounded-2xl p-6" style={{ background: 'rgba(11,14,20,0.92)' }}>
                                    <div className="w-full max-w-sm rounded-xl border p-4" style={{ borderColor: 'var(--border-subtle)', background: 'var(--surface-2)' }}>
                                        <div className="mb-2.5 flex items-center justify-between border-b pb-2" style={{ borderColor: 'var(--border-subtle)' }}>
                                            <span className="text-xs font-medium" style={{ color: 'var(--accent)' }}>Orchestration en cours</span>
                                            <span className="h-2 w-2 animate-pulse rounded-full" style={{ background: 'var(--accent)' }} />
                                        </div>
                                        <div className="max-h-40 space-y-1.5 overflow-y-auto text-xs">
                                            {consoleLogs.map((log, i) => (
                                                <p key={i} style={{ color: log.includes('exécuté') ? '#34d399' : 'var(--text-secondary)' }}>{log}</p>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            )}
                        </Card>
                    )}
                </div>
            </div>
        </div>
    );
}
