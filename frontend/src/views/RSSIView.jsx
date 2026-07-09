import { useState, useEffect } from 'react';
import { getUebaRiskScores, getAuditLogs } from '../services/api';
import { PageHeader, Card, Badge, StatCard, EmptyState } from '../components/ui/primitives';

/**
 * Vue RSSI — synthèse exécutive orientée décision : KPIs macro, posture
 * globale, incidents majeurs. Aucune donnée technique brute.
 */
export default function RSSIView({ user, logs = [], rules = [] }) {
    const [riskScores, setRiskScores] = useState([]);
    const [auditCount, setAuditCount] = useState(null);
    const [status, setStatus] = useState('loading');

    useEffect(() => {
        Promise.allSettled([getUebaRiskScores(), getAuditLogs({ page_size: 200 })])
            .then(([riskRes, auditRes]) => {
                if (riskRes.status === 'fulfilled') setRiskScores(riskRes.value);
                if (auditRes.status === 'fulfilled') setAuditCount(auditRes.value.length);
                setStatus('ready');
            });
    }, []);

    const criticalCount = logs.filter((l) => l.severity === 'CRITICAL').length;
    const openIncidents = logs.filter((l) => l.escalated === true).length;
    const unresolvedCount = logs.filter((l) => l.status !== 'TRAITÉ' && (l.severity === 'CRITICAL' || l.severity === 'HIGH' || l.severity === 'WARNING')).length;
    const activeRulesCount = rules.filter((r) => r.active).length;
    const highRiskEntities = riskScores.filter((r) => r.risk_level === 'critical' || r.risk_level === 'high').length;

    const majorIncidents = logs.filter((l) => l.severity === 'CRITICAL')
        .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || '')).slice(0, 5);

    const postureLevel = criticalCount === 0 && openIncidents === 0 ? 'STABLE' : criticalCount > 0 ? 'CRITIQUE' : 'SURVEILLANCE';
    const postureTone = postureLevel === 'STABLE' ? 'SUCCESS' : postureLevel === 'CRITIQUE' ? 'CRITICAL' : 'WARNING';

    return (
        <div className="space-y-5">
            <PageHeader
                eyebrow="Vue direction"
                title="Posture de sécurité"
                description={`${user?.name || user?.user} — synthèse exécutive sans détail technique.`}
                actions={<Badge tone={postureTone}>{postureLevel}</Badge>}
            />

            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                <StatCard label="Incidents majeurs actifs" value={openIncidents} tone="CRITICAL" />
                <StatCard label="Alertes non traitées" value={unresolvedCount} tone="WARNING" />
                <StatCard label="Entités à risque (UEBA)" value={status === 'loading' ? '…' : highRiskEntities} tone="INFO" />
                <StatCard label="Règles actives" value={`${activeRulesCount}/${rules.length}`} tone="SUCCESS" />
            </div>

            <Card>
                <p className="mb-4 text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Incidents majeurs récents</p>
                {majorIncidents.length === 0 ? (
                    <EmptyState title="Aucun incident critique actif" />
                ) : (
                    <div className="space-y-2">
                        {majorIncidents.map((inc) => (
                            <div key={inc.id} className="flex items-center justify-between gap-3 rounded-lg border px-3.5 py-2.5 text-sm" style={{ borderColor: 'rgba(239,68,68,0.25)', background: 'rgba(239,68,68,0.06)' }}>
                                <span className="truncate" style={{ color: 'var(--text-secondary)' }}>{inc.event}</span>
                                <span className="shrink-0 text-xs" style={{ color: 'var(--text-muted)' }}>{inc.timestamp}</span>
                            </div>
                        ))}
                    </div>
                )}
            </Card>

            <Card>
                <p className="mb-1.5 text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Traçabilité</p>
                <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                    {auditCount === null ? 'Chargement...' : `${auditCount} action(s) journalisée(s) (échantillon des 200 dernières entrées).`}
                </p>
            </Card>
        </div>
    );
}
