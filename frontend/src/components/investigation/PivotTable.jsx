import { Card, Badge, EmptyState } from '../ui/primitives';

const SEV_TONE = { critical: 'CRITICAL', warning: 'WARNING', info: 'INFO' };

/** Agrège une clé donnée (severity, log_type, host...) sur les événements réels. */
function aggregate(events, key) {
    const counts = new Map();
    for (const ev of events) {
        const value = ev[key] || 'inconnu';
        counts.set(value, (counts.get(value) || 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

/**
 * Table de pivot d'investigation — croise les événements réels de la
 * chronologie par sévérité, type de log et hôte impliqué. Calculée
 * entièrement côté client à partir des données retournées par
 * GET /api/investigation/{entity_id} (aucune valeur inventée).
 */
export default function PivotTable({ events = [] }) {
    if (events.length === 0) {
        return <EmptyState title="Rien à pivoter" description="Aucun événement chargé pour cette entité." />;
    }

    const bySeverity = aggregate(events, 'severity');
    const byLogType = aggregate(events, 'log_type');
    const byHost = aggregate(events, 'host');

    const renderRows = (rows, badgeTone) => (
        <div className="space-y-1.5">
            {rows.map(([value, count]) => (
                <div key={value} className="flex items-center justify-between rounded-md border px-2.5 py-1.5 text-xs" style={{ borderColor: 'var(--border-subtle)' }}>
                    {badgeTone ? <Badge tone={badgeTone(value)}>{value}</Badge> : <span style={{ color: 'var(--text-primary)' }}>{value}</span>}
                    <span className="font-medium" style={{ color: 'var(--text-secondary)' }}>{count}</span>
                </div>
            ))}
        </div>
    );

    return (
        <Card>
            <p className="mb-4 text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Pivot — répartition des événements</p>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                <div>
                    <p className="mb-2 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Par sévérité</p>
                    {renderRows(bySeverity, (v) => SEV_TONE[v] || 'NEUTRAL')}
                </div>
                <div>
                    <p className="mb-2 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Par type de log</p>
                    {renderRows(byLogType)}
                </div>
                <div>
                    <p className="mb-2 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Par hôte impliqué</p>
                    {renderRows(byHost)}
                </div>
            </div>
        </Card>
    );
}
