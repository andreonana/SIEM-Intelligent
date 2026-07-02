import { useState } from 'react';
import { Search, X, ShieldAlert, FileDown, FileSpreadsheet } from 'lucide-react';
import { acknowledgeAlert, resolveAlert, exportAlertsCsv, exportAlertsXlsx } from '../services/api';
import { PageHeader, Card, Badge, Button, EmptyState, ReadOnlyNotice } from '../components/ui/primitives';

/**
 * Console de triage des alertes. Dès qu'une alerte est qualifiée (traitée /
 * faux positif), elle disparaît de la file active pour désencombrer l'écran.
 */
export default function AlertTriage({ user, logs, setLogs, onRefresh }) {
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedAlert, setSelectedAlert] = useState(null);
    const [selectedAlertIds, setSelectedAlertIds] = useState([]);
    const [exporting, setExporting] = useState(false);

    const isReader = user?.role === 'reader';

    const handleExport = async (format) => {
        setExporting(true);
        try {
            if (format === 'csv') await exportAlertsCsv();
            else await exportAlertsXlsx();
        } catch (err) {
            alert(`Échec de l'export : ${err.message}`);
        } finally {
            setExporting(false);
        }
    };

    const alerts = logs.filter((log) => {
        const isAlert = log.severity === 'CRITICAL' || log.severity === 'HIGH' || log.severity === 'WARNING';
        const isNotProcessed = log.status !== 'FAUX_POSITIF' && log.status !== 'TRAITÉ';
        const matchesSearch =
            log.event.toLowerCase().includes(searchTerm.toLowerCase()) ||
            log.source.includes(searchTerm) ||
            log.service.toLowerCase().includes(searchTerm.toLowerCase());
        return isAlert && isNotProcessed && matchesSearch;
    });

    const handleSelectAlert = (id, e) => {
        e.stopPropagation();
        setSelectedAlertIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
    };

    const handleSelectAll = () => {
        const visibleIds = alerts.map((a) => a.id);
        const allVisibleSelected = visibleIds.every((id) => selectedAlertIds.includes(id));
        setSelectedAlertIds(allVisibleSelected
            ? selectedAlertIds.filter((id) => !visibleIds.includes(id))
            : Array.from(new Set([...selectedAlertIds, ...visibleIds])));
    };

    // Le backend n'a qu'un seul état de fermeture (resolved) : "Faux positif"
    // et "Traité" persistent tous deux via resolveAlert, avec une note qui
    // reflète la qualification choisie. Sans cet appel, la mise à jour reste
    // uniquement locale et l'alerte réapparaît au prochain rafraîchissement
    // automatique (le backend continue de la considérer "open").
    const qualificationNote = (newStatus) =>
        `Qualifiée ${newStatus === 'FAUX_POSITIF' ? 'faux positif' : 'traitée'} par ${user?.name || user?.user}`;

    const handleBulkUpdate = async (newStatus) => {
        if (isReader) return;
        const targets = logs.filter((log) => selectedAlertIds.includes(log.id) && log._realId);

        // Mise à jour optimiste immédiate pour la réactivité de l'UI...
        setLogs((prev) => prev.map((log) => (selectedAlertIds.includes(log.id) ? { ...log, status: newStatus, escalated: false } : log)));
        if (selectedAlert && selectedAlertIds.includes(selectedAlert.id)) setSelectedAlert(null);
        setSelectedAlertIds([]);

        // ...puis persistance réelle côté backend pour chaque alerte concernée.
        await Promise.allSettled(
            targets.map((alert) => resolveAlert(alert._realId, qualificationNote(newStatus))),
        );
        onRefresh && onRefresh();
    };

    const handleUpdateSingleStatus = (id, newStatus) => {
        if (isReader) return;
        setLogs((prev) => prev.map((log) => (log.id === id ? { ...log, status: newStatus, escalated: false } : log)));
        if (selectedAlert?.id === id) setSelectedAlert(null);

        const alert = logs.find((l) => l.id === id);
        if (alert?._realId) {
            resolveAlert(alert._realId, qualificationNote(newStatus))
                .then(() => onRefresh && onRefresh())
                .catch((err) => console.warn('resolveAlert failed:', err.message));
        }
    };

    const handleEscalate = (id) => {
        if (isReader) return;
        setLogs((prev) => prev.map((log) => (log.id === id ? { ...log, escalated: true, status: 'EN_COURS' } : log)));
        if (selectedAlert?.id === id) setSelectedAlert((prev) => ({ ...prev, escalated: true, status: 'EN_COURS' }));

        const alert = logs.find((l) => l.id === id);
        if (alert?._realId) {
            acknowledgeAlert(alert._realId)
                .then(() => onRefresh && onRefresh())
                .catch((err) => console.warn('acknowledgeAlert failed:', err.message));
        }
    };

    const allVisibleSelected = alerts.length > 0 && alerts.every((a) => selectedAlertIds.includes(a.id));

    return (
        <div className="space-y-5">
            <PageHeader
                eyebrow="Investigation"
                title="Triage des alertes"
                description="File des menaces actives — qualifiez ou escaladez chaque incident."
                actions={
                    <>
                        {isReader && <Badge tone="WARNING">Lecture seule</Badge>}
                        <Button onClick={() => handleExport('csv')} disabled={exporting}>
                            <FileDown size={15} /> CSV
                        </Button>
                        <Button onClick={() => handleExport('xlsx')} disabled={exporting}>
                            <FileSpreadsheet size={15} /> Excel
                        </Button>
                    </>
                }
            />

            <div className="relative">
                <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-muted)' }} />
                <input
                    type="text"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    placeholder="Filtrer par IP, service ou description..."
                    className="w-full rounded-lg border py-2.5 pl-10 pr-4 text-sm outline-none transition-colors focus:border-[var(--accent)]"
                    style={{ background: 'var(--surface-2)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }}
                />
            </div>

            {selectedAlertIds.length > 0 && !isReader && (
                <Card className="!py-0">
                    <div className="flex flex-col items-center justify-between gap-3 py-1 sm:flex-row">
                        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                            <strong style={{ color: 'var(--text-primary)' }}>{selectedAlertIds.length}</strong> alerte(s) sélectionnée(s)
                        </p>
                        <div className="flex gap-2">
                            <Button onClick={() => handleBulkUpdate('FAUX_POSITIF')}>Faux positif</Button>
                            <Button variant="primary" onClick={() => handleBulkUpdate('TRAITÉ')}>Clôturer</Button>
                        </div>
                    </div>
                </Card>
            )}

            <div className="flex flex-col gap-5 lg:flex-row lg:items-start">
                <Card padded={false} className={`overflow-hidden transition-all ${selectedAlert ? 'lg:w-3/5' : 'w-full'}`}>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm">
                            <thead>
                                <tr className="border-b text-xs font-medium uppercase tracking-wide" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                                    <th className="w-10 p-3.5 text-center">
                                        <input type="checkbox" checked={allVisibleSelected} onChange={handleSelectAll} disabled={isReader} />
                                    </th>
                                    <th className="p-3.5">Niveau</th>
                                    <th className="p-3.5">Source</th>
                                    <th className="p-3.5">Description</th>
                                    <th className="p-3.5 text-right">Statut</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
                                {alerts.length === 0 ? (
                                    <tr><td colSpan="5" className="p-0"><EmptyState title="Aucune alerte active" description="La file de menaces est vide." /></td></tr>
                                ) : (
                                    alerts.map((alert) => {
                                        const isChecked = selectedAlertIds.includes(alert.id);
                                        const isSelectedRow = selectedAlert?.id === alert.id;
                                        return (
                                            <tr
                                                key={alert.id}
                                                onClick={() => setSelectedAlert(alert)}
                                                className="cursor-pointer transition-colors"
                                                style={{ background: isSelectedRow ? 'var(--accent-soft)' : isChecked ? 'var(--surface-3)' : 'transparent' }}
                                            >
                                                <td className="p-3.5 text-center" onClick={(e) => handleSelectAlert(alert.id, e)}>
                                                    <input type="checkbox" checked={isChecked} disabled={isReader} readOnly />
                                                </td>
                                                <td className="p-3.5"><Badge tone={alert.severity}>{alert.severity}</Badge></td>
                                                <td className="p-3.5 font-medium" style={{ color: 'var(--text-primary)' }}>{alert.source}</td>
                                                <td className="max-w-xs truncate p-3.5" style={{ color: 'var(--text-secondary)' }}>{alert.event}</td>
                                                <td className="p-3.5 text-right">
                                                    {alert.escalated ? (
                                                        <Badge tone="CRITICAL">Salle de crise</Badge>
                                                    ) : (
                                                        <Badge tone={alert.status === 'EN_COURS' ? 'WARNING' : 'NEUTRAL'}>{alert.status || 'NON_TRAITÉ'}</Badge>
                                                    )}
                                                </td>
                                            </tr>
                                        );
                                    })
                                )}
                            </tbody>
                        </table>
                    </div>
                </Card>

                {selectedAlert && (
                    <Card className="w-full lg:sticky lg:top-4 lg:w-2/5">
                        <div className="mb-4 flex items-start justify-between border-b pb-3.5" style={{ borderColor: 'var(--border-subtle)' }}>
                            <div>
                                <p className="text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Détail de l'alerte</p>
                                <p className="mt-0.5 select-all text-base font-semibold" style={{ color: 'var(--text-primary)' }}>{selectedAlert.id}</p>
                                <p className="mt-0.5 text-xs" style={{ color: 'var(--text-muted)' }}>Service : {selectedAlert.service}</p>
                            </div>
                            <button onClick={() => setSelectedAlert(null)} className="rounded-md p-1.5" style={{ color: 'var(--text-muted)' }}>
                                <X size={16} />
                            </button>
                        </div>

                        <div className="space-y-3.5">
                            <div>
                                <p className="mb-1 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>IP source</p>
                                <span className="select-all rounded-md border px-2.5 py-1 text-sm font-medium" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }}>
                                    {selectedAlert.source}
                                </span>
                            </div>
                            <div>
                                <p className="mb-1 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Message</p>
                                <p className="rounded-lg border p-3 text-sm leading-relaxed" style={{ borderColor: 'var(--border-subtle)', background: 'var(--surface-1)', color: 'var(--text-secondary)' }}>
                                    {selectedAlert.event}
                                </p>
                            </div>
                            <div>
                                <p className="mb-1 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Métadonnées (JSON)</p>
                                <pre className="max-h-48 overflow-auto rounded-lg border p-3 text-xs leading-relaxed" style={{ borderColor: 'var(--border-subtle)', background: 'var(--surface-1)', color: 'var(--text-secondary)' }}>
                                    {selectedAlert.payload}
                                </pre>
                            </div>
                            {(selectedAlert.mitre_tactic_id || selectedAlert.mitre_technique_id) && (
                                <div className="rounded-lg border p-3 text-sm" style={{ borderColor: 'var(--border-subtle)' }}>
                                    <p className="mb-1 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>MITRE ATT&CK</p>
                                    {selectedAlert.mitre_tactic_id && <p style={{ color: 'var(--text-primary)' }}>{selectedAlert.mitre_tactic_id} — {selectedAlert.mitre_tactic_name}</p>}
                                    {selectedAlert.mitre_technique_id && <p style={{ color: 'var(--text-secondary)' }}>{selectedAlert.mitre_technique_id} — {selectedAlert.mitre_technique_name}</p>}
                                </div>
                            )}
                        </div>

                        <div className="mt-5 space-y-3 border-t pt-4" style={{ borderColor: 'var(--border-subtle)' }}>
                            {isReader ? (
                                <ReadOnlyNotice role="Lecteur" action="qualifier ou escalader une alerte" />
                            ) : !selectedAlert.escalated ? (
                                <>
                                    <div className="grid grid-cols-2 gap-2.5">
                                        <Button onClick={() => handleUpdateSingleStatus(selectedAlert.id, 'FAUX_POSITIF')}>Faux positif</Button>
                                        <Button onClick={() => handleUpdateSingleStatus(selectedAlert.id, 'TRAITÉ')}>Résolu</Button>
                                    </div>
                                    <Button
                                        variant="danger"
                                        className="w-full"
                                        onClick={() => handleEscalate(selectedAlert.id)}
                                    >
                                        <ShieldAlert size={15} /> Escalader en salle de crise
                                    </Button>
                                </>
                            ) : (
                                <Badge tone="CRITICAL" className="flex w-full justify-center py-2.5">Transmis à la salle de crise</Badge>
                            )}
                        </div>
                    </Card>
                )}
            </div>
        </div>
    );
}
