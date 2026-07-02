import { useState } from 'react';
import { Search, X, FileDown, FileSpreadsheet } from 'lucide-react';
import { exportLogsCsv, exportLogsXlsx } from '../services/api';
import { PageHeader, Card, Badge, Button, EmptyState } from '../components/ui/primitives';

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'WARNING', 'INFO'];
const STATUSES = [
    { value: 'ALL', label: 'Tous les états' },
    { value: 'NON_TRAITÉ', label: 'Non traités' },
    { value: 'TRAITÉ', label: 'Traités' },
    { value: 'FAUX_POSITIF', label: 'Faux positifs' },
    { value: 'ESCALADÉ', label: 'Escaladés' },
];

const inputStyle = { background: 'var(--surface-2)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' };

/** Vue dédiée à la recherche multi-critères et à l'investigation forensique sur les logs bruts. */
export default function LogExplorer({ user, logs, dataStatus = 'ready' }) {
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedSeverity, setSelectedSeverity] = useState('ALL');
    const [selectedStatus, setSelectedStatus] = useState('ALL');
    const [selectedLog, setSelectedLog] = useState(null);
    const [exporting, setExporting] = useState(false);

    const buildExportCriteria = () => {
        const criteria = { page_size: 5000 };
        if (selectedSeverity !== 'ALL') criteria.severity = selectedSeverity.toLowerCase();
        if (searchTerm) criteria.username = searchTerm;
        return criteria;
    };

    const handleExport = async (format) => {
        setExporting(true);
        try {
            const criteria = buildExportCriteria();
            if (format === 'csv') await exportLogsCsv(criteria);
            else await exportLogsXlsx(criteria);
        } catch (err) {
            alert(`Échec de l'export : ${err.message}`);
        } finally {
            setExporting(false);
        }
    };

    const filteredLogs = logs.filter((log) => {
        const matchesSearch =
            log.event.toLowerCase().includes(searchTerm.toLowerCase()) ||
            log.source.includes(searchTerm) ||
            log.service.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesSeverity = selectedSeverity === 'ALL' || log.severity === selectedSeverity;
        const logStatus = log.escalated ? 'ESCALADÉ' : (log.status || 'NON_TRAITÉ');
        const matchesStatus = selectedStatus === 'ALL' || logStatus === selectedStatus;
        return matchesSearch && matchesSeverity && matchesStatus;
    });

    return (
        <div className="space-y-5">
            <PageHeader
                eyebrow="Investigation"
                title="Explorateur de logs"
                description={`Analyste : ${user?.name || user?.user}`}
                actions={
                    <>
                        <Button onClick={() => handleExport('csv')} disabled={exporting}><FileDown size={15} /> CSV</Button>
                        <Button onClick={() => handleExport('xlsx')} disabled={exporting}><FileSpreadsheet size={15} /> Excel</Button>
                    </>
                }
            />

            <Card>
                <div className="flex flex-col gap-3.5 xl:flex-row xl:items-center xl:justify-between">
                    <div className="relative w-full xl:w-72">
                        <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-muted)' }} />
                        <input
                            type="text" value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)}
                            placeholder="Rechercher un mot-clé..."
                            className="w-full rounded-lg border py-2 pl-9 pr-3 text-sm outline-none focus:border-[var(--accent)]"
                            style={inputStyle}
                        />
                    </div>
                    <div className="flex flex-col items-center gap-3 sm:flex-row">
                        <div className="flex gap-1.5 overflow-x-auto">
                            {SEVERITIES.map((sev) => (
                                <button
                                    key={sev}
                                    onClick={() => setSelectedSeverity(sev)}
                                    className="whitespace-nowrap rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors"
                                    style={selectedSeverity === sev
                                        ? { background: 'var(--accent)', borderColor: 'var(--accent)', color: '#fff' }
                                        : { borderColor: 'var(--border-subtle)', color: 'var(--text-secondary)' }}
                                >
                                    {sev === 'ALL' ? 'Tous' : sev}
                                </button>
                            ))}
                        </div>
                        <select
                            value={selectedStatus} onChange={(e) => setSelectedStatus(e.target.value)}
                            className="w-full rounded-lg border px-3 py-1.5 text-xs sm:w-44"
                            style={inputStyle}
                        >
                            {STATUSES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
                        </select>
                    </div>
                </div>
            </Card>

            <div className="flex flex-col gap-5 lg:flex-row">
                <Card padded={false} className={`overflow-hidden ${selectedLog ? 'lg:w-2/3' : 'w-full'}`}>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm">
                            <thead>
                                <tr className="border-b text-xs font-medium uppercase tracking-wide" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                                    <th className="p-3.5">Horodatage</th>
                                    <th className="p-3.5">Sévérité</th>
                                    <th className="p-3.5">IP source</th>
                                    <th className="p-3.5">Événement</th>
                                    <th className="p-3.5 text-right">Statut</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
                                {dataStatus === 'loading' ? (
                                    <tr><td colSpan="5" className="p-8 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Chargement des logs...</td></tr>
                                ) : dataStatus === 'error' ? (
                                    <tr><td colSpan="5" className="p-0"><EmptyState title="Backend indisponible" /></td></tr>
                                ) : filteredLogs.length === 0 ? (
                                    <tr><td colSpan="5" className="p-0"><EmptyState title="Aucun log ne correspond aux filtres" /></td></tr>
                                ) : (
                                    filteredLogs.map((log) => (
                                        <tr
                                            key={log.id}
                                            onClick={() => setSelectedLog(log)}
                                            className="cursor-pointer transition-colors"
                                            style={{ background: selectedLog?.id === log.id ? 'var(--accent-soft)' : 'transparent' }}
                                        >
                                            <td className="whitespace-nowrap p-3.5 text-xs" style={{ color: 'var(--text-muted)' }}>{log.timestamp}</td>
                                            <td className="p-3.5">
                                                <Badge tone={log.severity}>{log.severity}</Badge>
                                            </td>
                                            <td className="p-3.5 font-medium" style={{ color: 'var(--text-primary)' }}>{log.source}</td>
                                            <td className="max-w-xs truncate p-3.5" style={{ color: 'var(--text-secondary)' }}>{log.event}</td>
                                            <td className="p-3.5 text-right">
                                                {log.escalated ? <Badge tone="CRITICAL">Escaladé</Badge> : <Badge tone="NEUTRAL">{log.status || 'NON_TRAITÉ'}</Badge>}
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </Card>

                {selectedLog && (
                    <Card className="w-full lg:w-1/3">
                        <div className="mb-3.5 flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--border-subtle)' }}>
                            <div>
                                <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{selectedLog.id}</p>
                                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Service : {selectedLog.service}</p>
                            </div>
                            <button onClick={() => setSelectedLog(null)} className="rounded-md p-1.5" style={{ color: 'var(--text-muted)' }}><X size={15} /></button>
                        </div>
                        <div className="space-y-3 text-xs">
                            <div>
                                <p className="mb-1 font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>IP source</p>
                                <span className="rounded-md border px-2 py-0.5 font-medium" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }}>{selectedLog.source}</span>
                            </div>
                            <div>
                                <p className="mb-1 font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Message syslog</p>
                                <p className="rounded-lg border p-2.5" style={{ borderColor: 'var(--border-subtle)', background: 'var(--surface-1)', color: 'var(--text-secondary)' }}>{selectedLog.event}</p>
                            </div>
                            <div>
                                <p className="mb-1 font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Payload</p>
                                <pre className="max-h-40 overflow-auto rounded-lg border p-2.5 leading-tight" style={{ borderColor: 'var(--border-subtle)', background: 'var(--surface-1)', color: 'var(--text-secondary)' }}>{selectedLog.payload}</pre>
                            </div>
                            {(selectedLog.mitre_tactic_id || selectedLog.mitre_technique_id) && (
                                <div className="rounded-lg border p-2.5" style={{ borderColor: 'var(--border-subtle)' }}>
                                    <p className="mb-1 font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>MITRE ATT&CK</p>
                                    {selectedLog.mitre_tactic_id && <p style={{ color: 'var(--text-primary)' }}>{selectedLog.mitre_tactic_id} — {selectedLog.mitre_tactic_name}</p>}
                                    {selectedLog.mitre_technique_id && <p style={{ color: 'var(--text-secondary)' }}>{selectedLog.mitre_technique_id} — {selectedLog.mitre_technique_name}</p>}
                                </div>
                            )}
                        </div>
                        <p className="mt-4 border-t pt-3 text-[11px]" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                            Pour qualifier ou escalader cet événement, utilisez le triage des alertes.
                        </p>
                    </Card>
                )}
            </div>
        </div>
    );
}
