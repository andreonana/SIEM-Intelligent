import { useState, useEffect, useCallback } from 'react';
import { Fingerprint, Search, ShieldAlert, X } from 'lucide-react';
import { getInvestigation, flagInvestigation, getInvestigationFlags } from '../services/api';
import { PageHeader, Card, Badge, Button, LoadingState, ErrorBanner, EmptyState } from '../components/ui/primitives';
import ForensicTimeline from '../components/investigation/ForensicTimeline';
import TimelineChart from '../components/charts/TimelineChart';
import PivotTable from '../components/investigation/PivotTable';

const SEV_TONE = { critical: 'CRITICAL', warning: 'WARNING', info: 'INFO' };
const inputStyle = { background: 'var(--surface-2)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' };

/**
 * Vue d'investigation forensique — reconstruit la chronologie réelle d'une
 * entité (IP source ou host) via GET /api/investigation/{entity_id}, avec
 * timeline visuelle, pivot par sévérité/type/hôte, et marquage suspect.
 * Peut être atteinte directement (saisie manuelle de l'entité) ou par pivot
 * depuis l'Explorateur de logs (initialEntityId).
 */
export default function InvestigationView({ user, initialEntityId = null, onConsumeInitialEntity }) {
    const [entityInput, setEntityInput] = useState(initialEntityId || '');
    const [entityId, setEntityId] = useState(null);
    const [timeline, setTimeline] = useState([]);
    const [flags, setFlags] = useState([]);
    const [selectedEvent, setSelectedEvent] = useState(null);
    const [status, setStatus] = useState('idle'); // idle | loading | ready | error
    const [error, setError] = useState(null);

    const load = useCallback(async (id) => {
        if (!id) return;
        setStatus('loading');
        setError(null);
        setSelectedEvent(null);
        try {
            const [investigation, flagList] = await Promise.all([
                getInvestigation(id),
                getInvestigationFlags(id).catch(() => []),
            ]);
            setTimeline(investigation.timeline || []);
            setFlags(flagList);
            setEntityId(id);
            setStatus('ready');
        } catch (err) {
            setError(err.message || "Impossible de charger l'investigation.");
            setStatus('error');
        }
    }, []);

    // Pivot depuis l'Explorateur de logs : charge automatiquement l'entité ciblée.
    useEffect(() => {
        if (initialEntityId) {
            setEntityInput(initialEntityId);
            load(initialEntityId);
            onConsumeInitialEntity?.();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [initialEntityId]);

    const handleSubmit = (e) => {
        e.preventDefault();
        if (entityInput.trim()) load(entityInput.trim());
    };

    const handleFlag = async () => {
        if (!entityId) return;
        const note = window.prompt(`Marquer "${entityId}" comme suspecte — note (optionnelle) :`, '');
        if (note === null) return;
        try {
            await flagInvestigation(entityId, note);
            const flagList = await getInvestigationFlags(entityId);
            setFlags(flagList);
        } catch (err) {
            alert(`Échec du marquage : ${err.message}`);
        }
    };

    return (
        <div className="space-y-5">
            <PageHeader
                eyebrow="Investigation"
                title="Investigation forensique"
                description="Chronologie réelle d'une entité (IP source ou hôte), reconstituée depuis Elasticsearch."
            />

            <Card>
                <form onSubmit={handleSubmit} className="flex flex-col gap-3 sm:flex-row sm:items-center">
                    <div className="relative flex-1">
                        <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-muted)' }} />
                        <input
                            type="text" value={entityInput} onChange={(e) => setEntityInput(e.target.value)}
                            placeholder="IP source ou hôte à investiguer (ex: 198.51.100.77)"
                            className="w-full rounded-lg border py-2.5 pl-9 pr-3 text-sm outline-none focus:border-[var(--accent)]"
                            style={inputStyle}
                        />
                    </div>
                    <Button type="submit" variant="primary" disabled={!entityInput.trim()}>
                        <Fingerprint size={15} /> Investiguer
                    </Button>
                </form>
            </Card>

            {status === 'idle' && (
                <EmptyState icon={Fingerprint} title="Saisissez une entité" description="Entrez une IP source ou un hôte, ou pivotez depuis l'Explorateur de logs." />
            )}
            {status === 'loading' && <LoadingState label="Reconstitution de la chronologie..." />}
            {status === 'error' && <ErrorBanner description={error} />}

            {status === 'ready' && (
                <>
                    <div className="flex flex-col items-start justify-between gap-3 sm:flex-row sm:items-center">
                        <div className="flex items-center gap-2.5">
                            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                                Entité : <span className="select-all font-semibold" style={{ color: 'var(--text-primary)' }}>{entityId}</span>
                            </p>
                            <Badge tone="INFO">{timeline.length} événement(s)</Badge>
                            {flags.length > 0 && <Badge tone="CRITICAL">{flags.length} marquage(s) suspect(s)</Badge>}
                        </div>
                        <Button variant="danger" onClick={handleFlag}>
                            <ShieldAlert size={15} /> Marquer suspect
                        </Button>
                    </div>

                    {flags.length > 0 && (
                        <Card>
                            <p className="mb-2.5 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Marquages existants</p>
                            <div className="space-y-1.5">
                                {flags.map((f) => (
                                    <div key={f.id} className="flex items-center justify-between rounded-md border px-3 py-2 text-xs" style={{ borderColor: 'var(--border-subtle)' }}>
                                        <span style={{ color: 'var(--text-primary)' }}>{f.flagged_by}</span>
                                        <span style={{ color: 'var(--text-secondary)' }}>{f.note || '—'}</span>
                                        <span style={{ color: 'var(--text-muted)' }}>{(f.flagged_at || '').replace('T', ' ').slice(0, 19)}</span>
                                    </div>
                                ))}
                            </div>
                        </Card>
                    )}

                    <TimelineChart events={timeline} selectedId={selectedEvent?.id} onSelect={setSelectedEvent} />

                    <div className="flex flex-col gap-5 lg:flex-row">
                        <div className={selectedEvent ? 'lg:w-3/5' : 'w-full'}>
                            <ForensicTimeline events={timeline} selectedId={selectedEvent?.id} onSelect={setSelectedEvent} />
                        </div>

                        {selectedEvent && (
                            <Card className="w-full lg:w-2/5">
                                <div className="mb-3.5 flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--border-subtle)' }}>
                                    <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Détail de l'événement</p>
                                    <button onClick={() => setSelectedEvent(null)} className="rounded-md p-1.5" style={{ color: 'var(--text-muted)' }}><X size={15} /></button>
                                </div>
                                <div className="space-y-3 text-xs">
                                    <div className="flex items-center gap-2">
                                        <Badge tone={SEV_TONE[selectedEvent.severity] || 'NEUTRAL'}>{selectedEvent.severity}</Badge>
                                        <span style={{ color: 'var(--text-muted)' }}>{(selectedEvent.timestamp || '').replace('T', ' ').slice(0, 19)}</span>
                                    </div>
                                    <div>
                                        <p className="mb-1 font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>IP source</p>
                                        <span className="select-all" style={{ color: 'var(--text-primary)' }}>{selectedEvent.source_ip || '—'}</span>
                                    </div>
                                    <div>
                                        <p className="mb-1 font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Hôte</p>
                                        <span style={{ color: 'var(--text-primary)' }}>{selectedEvent.host || '—'}</span>
                                    </div>
                                    <div>
                                        <p className="mb-1 font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Type de log</p>
                                        <span style={{ color: 'var(--text-primary)' }}>{selectedEvent.log_type || '—'}</span>
                                    </div>
                                    <div>
                                        <p className="mb-1 font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Message brut</p>
                                        <p className="rounded-lg border p-2.5 leading-relaxed" style={{ borderColor: 'var(--border-subtle)', background: 'var(--surface-1)', color: 'var(--text-secondary)' }}>
                                            {selectedEvent.raw_message}
                                        </p>
                                    </div>
                                </div>
                            </Card>
                        )}
                    </div>

                    <PivotTable events={timeline} />
                </>
            )}
        </div>
    );
}
