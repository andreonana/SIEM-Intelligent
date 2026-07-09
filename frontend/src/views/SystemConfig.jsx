import { useState, useEffect, useCallback } from 'react';
import { getSystemHealth } from '../services/api';
import { PageHeader, Card, Badge, LoadingState, ErrorBanner } from '../components/ui/primitives';

const TONE_MAP = { healthy: 'SUCCESS', degraded: 'WARNING', unavailable: 'CRITICAL', unknown: 'NEUTRAL' };
const OVERALL_LABEL = { healthy: 'Opérationnel', degraded: 'Dégradé', unavailable: 'Indisponible' };

/**
 * Supervision de l'infrastructure — branché sur GET /api/system/health :
 * cluster Elasticsearch réel, sondes TCP réelles, heartbeat indirect pour le
 * forwarder. Aucune métrique CPU/RAM/stockage : aucun endpoint ne les fournit.
 */
export default function SystemConfig() {
    const [health, setHealth] = useState(null);
    const [status, setStatus] = useState('loading');

    const load = useCallback(() => {
        getSystemHealth().then((data) => { setHealth(data); setStatus('ready'); }).catch(() => setStatus('error'));
    }, []);

    useEffect(() => {
        load();
        const interval = setInterval(load, 15000);
        return () => clearInterval(interval);
    }, [load]);

    return (
        <div className="space-y-5">
            <PageHeader
                eyebrow="Administration"
                title="Configuration système"
                description="Santé réelle de l'infrastructure (GET /api/system/health)."
                actions={status === 'ready' && health ? <Badge tone={TONE_MAP[health.overall]}>{OVERALL_LABEL[health.overall] || health.overall}</Badge> : null}
            />

            {status === 'loading' && <LoadingState label="Vérification en cours..." />}
            {status === 'error' && <ErrorBanner description="Impossible d'interroger /api/system/health." />}

            {status === 'ready' && health && (
                <Card padded={false}>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm">
                            <thead>
                                <tr className="border-b text-xs font-medium uppercase tracking-wide" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                                    <th className="p-3.5">Service</th>
                                    <th className="p-3.5">Statut</th>
                                    <th className="p-3.5">Détail</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
                                {health.services.map((svc) => (
                                    <tr key={svc.name}>
                                        <td className="p-3.5 font-medium" style={{ color: 'var(--text-primary)' }}>{svc.name}</td>
                                        <td className="p-3.5"><Badge tone={TONE_MAP[svc.status] || 'NEUTRAL'}>{svc.status}</Badge></td>
                                        <td className="p-3.5 text-xs" style={{ color: 'var(--text-muted)' }}>{svc.detail}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    <p className="border-t p-3 text-[11px]" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                        Dernière vérification : {new Date(health.checked_at).toLocaleString('fr-FR')} · rafraîchissement automatique toutes les 15 s
                    </p>
                </Card>
            )}

            <div className="rounded-lg border px-4 py-3 text-xs leading-relaxed" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                <strong style={{ color: 'var(--text-secondary)' }}>Limitation connue —</strong> aucune métrique serveur
                (CPU, RAM, stockage) n'est affichée : aucun endpoint backend ne les fournit. Le statut du forwarder
                est déduit indirectement (fraîcheur du dernier log reçu), faute de port réseau exposé.
            </div>
        </div>
    );
}
