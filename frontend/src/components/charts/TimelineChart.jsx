import { useMemo } from 'react';
import { Card, EmptyState } from '../ui/primitives';

const SEV_COLOR = {
    critical: 'var(--sev-critical)',
    warning: 'var(--sev-warning)',
    info: 'var(--sev-info)',
};

/**
 * Représentation visuelle réelle de la chronologie : chaque événement est
 * positionné sur un axe horizontal proportionnellement à son horodatage réel
 * (pas un graphique décoratif — la position, la couleur et le nombre de
 * points reflètent exactement les données d'Elasticsearch).
 */
export default function TimelineChart({ events = [], selectedId = null, onSelect }) {
    const { points, startLabel, endLabel } = useMemo(() => {
        if (events.length === 0) return { points: [], startLabel: null, endLabel: null };

        const times = events.map((ev) => new Date(ev.timestamp).getTime()).filter((t) => !Number.isNaN(t));
        if (times.length === 0) return { points: [], startLabel: null, endLabel: null };

        const min = Math.min(...times);
        const max = Math.max(...times);
        const span = max - min || 1;

        const pts = events.map((ev) => {
            const t = new Date(ev.timestamp).getTime();
            const percent = Number.isNaN(t) ? 0 : ((t - min) / span) * 100;
            return { ...ev, percent };
        });

        return {
            points: pts,
            startLabel: new Date(min).toLocaleString('fr-FR'),
            endLabel: new Date(max).toLocaleString('fr-FR'),
        };
    }, [events]);

    if (points.length === 0) {
        return <EmptyState title="Aucune donnée à représenter" />;
    }

    return (
        <Card>
            <p className="mb-4 text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Répartition temporelle</p>
            <div className="relative h-16">
                <div className="absolute left-0 right-0 top-1/2 h-px" style={{ background: 'var(--border-subtle)' }} />
                {points.map((pt) => (
                    <button
                        key={pt.id}
                        title={`${(pt.timestamp || '').replace('T', ' ').slice(0, 19)} — ${pt.source_ip || pt.host || ''} — ${pt.raw_message || ''}`}
                        onClick={() => onSelect?.(pt)}
                        className="absolute top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full transition-transform hover:scale-125"
                        style={{
                            left: `${pt.percent}%`,
                            width: pt.id === selectedId ? 14 : 10,
                            height: pt.id === selectedId ? 14 : 10,
                            background: SEV_COLOR[pt.severity] || 'var(--text-muted)',
                            border: pt.id === selectedId ? '2px solid var(--text-primary)' : 'none',
                        }}
                    />
                ))}
            </div>
            <div className="mt-2 flex justify-between text-[11px]" style={{ color: 'var(--text-muted)' }}>
                <span>{startLabel}</span>
                <span>{endLabel}</span>
            </div>
        </Card>
    );
}
