import { useState, useEffect } from 'react';
import { getAuditLogs } from '../services/api';
import { PageHeader, Card, Badge, LoadingState, ErrorBanner, EmptyState } from '../components/ui/primitives';

/** Journal d'audit des actions utilisateurs — connexion, création de compte, traitement d'alerte, etc. */
export default function AuditTrail() {
    const [auditLogs, setAuditLogs] = useState([]);
    const [status, setStatus] = useState('loading');

    useEffect(() => {
        getAuditLogs({ page_size: 50 })
            .then((logs) => {
                setAuditLogs(logs.map((l, i) => ({
                    id: `AUDIT-${l.id || i}`,
                    timestamp: (l.timestamp || l.created_at || '').replace('T', ' ').slice(0, 19),
                    operator: l.username || 'système',
                    role: l.role || '—',
                    action: l.action || l.event_type || '—',
                    target: l.target || l.resource || '—',
                    status: l.result === 'success' ? 'SUCCESS' : l.result === 'failure' ? 'DENIED' : (l.result || 'INFO').toUpperCase(),
                    ip: l.ip_address || '—',
                })));
                setStatus('ready');
            })
            .catch(() => setStatus('error'));
    }, []);

    return (
        <div className="space-y-5">
            <PageHeader
                eyebrow="Administration"
                title="Journal d'audit"
                description="Traçabilité des actions utilisateurs."
                actions={<Badge tone="INFO">{auditLogs.length} entrée(s)</Badge>}
            />

            <div className="rounded-lg border px-4 py-3 text-xs leading-relaxed" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                Journal des connexions, créations de compte, modifications de rôle et traitements d'alerte.
                Stocké en base relationnelle — aucun mécanisme d'immuabilité (WORM) n'est actuellement implémenté.
            </div>

            {status === 'loading' && <LoadingState label="Chargement du journal..." />}
            {status === 'error' && <ErrorBanner description="Impossible de charger le journal d'audit." />}

            {status === 'ready' && (
                <Card padded={false}>
                    {auditLogs.length === 0 ? (
                        <EmptyState title="Aucune entrée d'audit disponible" />
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full text-left text-sm">
                                <thead>
                                    <tr className="border-b text-xs font-medium uppercase tracking-wide" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                                        <th className="p-3.5">Horodatage</th>
                                        <th className="p-3.5">Opérateur</th>
                                        <th className="p-3.5">Action</th>
                                        <th className="p-3.5">Cible</th>
                                        <th className="p-3.5">IP</th>
                                        <th className="p-3.5 text-right">Résultat</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
                                    {auditLogs.map((log) => (
                                        <tr key={log.id}>
                                            <td className="whitespace-nowrap p-3.5 text-xs" style={{ color: 'var(--text-muted)' }}>{log.timestamp}</td>
                                            <td className="p-3.5">
                                                <p className="font-medium" style={{ color: 'var(--text-primary)' }}>{log.operator}</p>
                                                <p className="text-[11px]" style={{ color: 'var(--text-muted)' }}>{log.role}</p>
                                            </td>
                                            <td className="p-3.5" style={{ color: 'var(--accent)' }}>{log.action}</td>
                                            <td className="max-w-xs truncate p-3.5" style={{ color: 'var(--text-secondary)' }} title={log.target}>{log.target}</td>
                                            <td className="p-3.5 text-xs" style={{ color: 'var(--text-muted)' }}>{log.ip}</td>
                                            <td className="p-3.5 text-right"><Badge tone={log.status === 'SUCCESS' ? 'SUCCESS' : 'CRITICAL'}>{log.status}</Badge></td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </Card>
            )}
        </div>
    );
}
