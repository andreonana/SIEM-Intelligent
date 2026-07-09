import { Card, Badge, EmptyState } from '../ui/primitives';

const SEV_TONE = { critical: 'CRITICAL', warning: 'WARNING', info: 'INFO' };

/**
 * Chronologie forensique réelle — liste ordonnée des événements d'une entité
 * (IP source ou host), retournée par GET /api/investigation/{entity_id}.
 * Chaque ligne est cliquable pour sélectionner l'événement (détail affiché
 * par le parent). Pas de données décoratives : tout provient d'Elasticsearch.
 */
export default function ForensicTimeline({ events = [], selectedId = null, onSelect }) {
    if (events.length === 0) {
        return <EmptyState title="Aucun événement" description="Aucune trace trouvée pour cette entité dans la fenêtre indexée." />;
    }

    return (
        <Card padded={false}>
            <div className="max-h-[480px] overflow-y-auto">
                <table className="w-full text-left text-sm">
                    <thead className="sticky top-0" style={{ background: 'var(--surface-2)' }}>
                        <tr className="border-b text-xs font-medium uppercase tracking-wide" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                            <th className="p-3">Horodatage</th>
                            <th className="p-3">Source</th>
                            <th className="p-3">Hôte</th>
                            <th className="p-3">Type</th>
                            <th className="p-3">Sévérité</th>
                            <th className="p-3">Message</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
                        {events.map((ev) => (
                            <tr
                                key={ev.id}
                                onClick={() => onSelect?.(ev)}
                                className="cursor-pointer transition-colors"
                                style={{ background: selectedId === ev.id ? 'var(--accent-soft)' : 'transparent' }}
                            >
                                <td className="whitespace-nowrap p-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                                    {(ev.timestamp || '').replace('T', ' ').slice(0, 19)}
                                </td>
                                <td className="p-3 text-xs font-medium" style={{ color: 'var(--text-primary)' }}>{ev.source_ip || '—'}</td>
                                <td className="p-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{ev.host || '—'}</td>
                                <td className="p-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{ev.log_type || '—'}</td>
                                <td className="p-3"><Badge tone={SEV_TONE[ev.severity] || 'NEUTRAL'}>{ev.severity || '—'}</Badge></td>
                                <td className="max-w-sm truncate p-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{ev.raw_message}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </Card>
    );
}
