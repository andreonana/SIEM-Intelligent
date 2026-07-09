import { useState, useEffect } from 'react';
import { FileDown } from 'lucide-react';
import { getAuditLogs, getIntegrityBatches, exportAlertsCsv } from '../services/api';
import { PageHeader, Card, Badge, Button, StatCard, LoadingState, EmptyState } from '../components/ui/primitives';

/**
 * Vue Auditeur — comptages réels d'incidents, journal d'audit, preuve
 * d'intégrité SHA-256 et export pour dossier d'audit externe. Aucun score de
 * conformité ISO 27001/RGPD n'est calculé : aucune évaluation de ce type
 * n'est implémentée côté backend, un pourcentage inventé serait trompeur.
 */
export default function Compliance({ logs = [], dataStatus = 'ready' }) {
    const [auditEntries, setAuditEntries] = useState([]);
    const [integrityBatches, setIntegrityBatches] = useState(null);
    const [auxStatus, setAuxStatus] = useState('loading');
    const [exporting, setExporting] = useState(false);

    useEffect(() => {
        Promise.allSettled([getAuditLogs({ page_size: 10 }), getIntegrityBatches()])
            .then(([auditRes, integrityRes]) => {
                if (auditRes.status === 'fulfilled') setAuditEntries(auditRes.value);
                if (integrityRes.status === 'fulfilled') setIntegrityBatches(integrityRes.value);
                setAuxStatus('ready');
            });
    }, []);

    const activeIncidentsCount = logs.filter((l) => l.escalated === true).length;
    const unresolvedCriticals = logs.filter((l) => l.severity === 'CRITICAL' && l.status !== 'TRAITÉ').length;
    const dataRelatedEvents = logs.filter((log) =>
        log.service?.toLowerCase().includes('db') ||
        log.service?.toLowerCase().includes('auth') ||
        log.event?.toLowerCase().includes('exfiltration') ||
        log.event?.toLowerCase().includes('sql') ||
        log.event?.toLowerCase().includes('privilège'));

    const handleExportEvidence = async () => {
        setExporting(true);
        try {
            await exportAlertsCsv();
        } catch (err) {
            alert(`Échec de l'export : ${err.message}`);
        } finally {
            setExporting(false);
        }
    };

    if (dataStatus === 'loading') return <LoadingState label="Chargement..." />;

    return (
        <div className="space-y-5">
            <PageHeader
                eyebrow="Reporting & conformité"
                title="Vue auditeur"
                description="Comptages réels, journal d'audit et preuve d'intégrité."
                actions={<Button onClick={handleExportEvidence} disabled={exporting}><FileDown size={15} /> Exporter les alertes (CSV)</Button>}
            />

            <div className="rounded-lg border px-4 py-3 text-xs leading-relaxed" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                Cette vue ne calcule aucun score de conformité ISO 27001 ou RGPD chiffré : aucune évaluation de ce
                type n'est implémentée côté backend. Seuls des comptages et journaux réels sont affichés ci-dessous.
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                <StatCard label="Incidents ouverts" value={activeIncidentsCount} />
                <StatCard label="Critiques non résolues" value={unresolvedCriticals} tone="CRITICAL" />
                <StatCard label="Événements liés aux données" value={dataRelatedEvents.length} tone="INFO" />
            </div>

            <Card>
                <p className="mb-3 text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Preuve d'intégrité des logs (SHA-256)</p>
                {auxStatus === 'loading' ? (
                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Chargement...</p>
                ) : integrityBatches?.total ? (
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        <strong style={{ color: '#34d399' }}>{integrityBatches.total}</strong> lot(s) de logs horodatés et hachés,
                        vérifiables via <code style={{ color: 'var(--accent)' }}>/api/integrity/verify/{'{batch_id}'}</code>.
                    </p>
                ) : (
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucun lot avec preuve d'intégrité disponible.</p>
                )}
            </Card>

            <Card>
                <p className="mb-3 text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Dernières actions journalisées</p>
                {auxStatus === 'loading' ? (
                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Chargement...</p>
                ) : auditEntries.length === 0 ? (
                    <EmptyState title="Aucune entrée d'audit disponible" />
                ) : (
                    <div className="space-y-2">
                        {auditEntries.map((entry, i) => (
                            <div key={entry.id || i} className="flex items-center justify-between rounded-lg border px-3.5 py-2.5 text-xs" style={{ borderColor: 'var(--border-subtle)' }}>
                                <div className="flex items-center gap-2.5">
                                    <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{entry.username || 'système'}</span>
                                    <span style={{ color: 'var(--text-muted)' }}>{entry.action}</span>
                                </div>
                                <span style={{ color: 'var(--text-muted)' }}>{(entry.timestamp || '').replace('T', ' ').slice(0, 19)}</span>
                            </div>
                        ))}
                    </div>
                )}
            </Card>

            <Card>
                <div className="mb-3 flex items-center justify-between">
                    <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Événements liés aux données personnelles</p>
                    <Badge tone="WARNING">Filtre mot-clé</Badge>
                </div>
                {dataRelatedEvents.length === 0 ? (
                    <EmptyState title="Aucun événement de ce type" />
                ) : (
                    <div className="space-y-2.5">
                        {dataRelatedEvents.map((violation) => (
                            <div key={violation.id} className="flex flex-col gap-2 rounded-lg border p-3.5 sm:flex-row sm:items-center sm:justify-between" style={{ borderColor: 'var(--border-subtle)' }}>
                                <div>
                                    <div className="flex items-center gap-2">
                                        <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{violation.id}</span>
                                        <Badge tone="INFO">{violation.service}</Badge>
                                    </div>
                                    <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>{violation.event}</p>
                                </div>
                                <div className="flex items-center gap-2.5">
                                    <Badge tone={violation.status === 'TRAITÉ' ? 'SUCCESS' : 'CRITICAL'}>{violation.status === 'TRAITÉ' ? 'Traité' : 'Action requise'}</Badge>
                                    <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{violation.timestamp}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </Card>
        </div>
    );
}
