import { useEffect, useState } from 'react';
import { Search, X, FileDown, FileSpreadsheet, Fingerprint, RotateCcw, ChevronLeft, ChevronRight } from 'lucide-react';
import { exportLogsCsv, exportLogsXlsx } from '../services/api';
import { PageHeader, Card, Badge, Button, EmptyState, LoadingState, ErrorBanner } from '../components/ui/primitives';
import useSearch from '../hooks/useSearch';

const LOG_TYPES = ['', 'auth', 'réseau', 'système', 'application'];
const SEVERITIES = ['', 'critical', 'warning', 'info'];
const SEV_TONE = { critical: 'CRITICAL', warning: 'WARNING', info: 'INFO' };
const inputStyle = { background: 'var(--surface-2)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' };

/**
 * Explorateur de logs — recherche multi-critères réelle branchée sur
 * POST /api/search (Elasticsearch). Aucun filtrage local : chaque critère
 * ou changement de page relance un vrai appel backend, qui reste l'unique
 * source de vérité (conforme CDC S2 Data).
 */
export default function LogExplorer({ user, onInvestigate }) {
    const {
        criteria, updateCriteria, resetCriteria, runSearch, goToPage,
        results, total, page, totalPages, status, error,
    } = useSearch();

    const [selectedLog, setSelectedLog] = useState(null);
    const [exporting, setExporting] = useState(false);

    // Recherche initiale (sans filtre) au montage, pour une interface immédiatement testable.
    useEffect(() => { runSearch(1); }, []); // eslint-disable-line react-hooks/exhaustive-deps

    const handleSubmit = (e) => {
        e.preventDefault();
        runSearch(1);
    };

    const handleReset = () => {
        resetCriteria();
        setSelectedLog(null);
        runSearch(1, {});
    };

    const buildExportCriteria = () => {
        const c = { page_size: 5000 };
        Object.entries(criteria).forEach(([k, v]) => { if (v) c[k] = v; });
        return c;
    };

    const handleExport = async (format) => {
        setExporting(true);
        try {
            const c = buildExportCriteria();
            if (format === 'csv') await exportLogsCsv(c);
            else await exportLogsXlsx(c);
        } catch (err) {
            alert(`Échec de l'export : ${err.message}`);
        } finally {
            setExporting(false);
        }
    };

    return (
        <div className="space-y-5">
            <PageHeader
                eyebrow="Investigation"
                title="Explorateur de logs"
                description={`Recherche multi-critères réelle (Elasticsearch) — ${user?.name || user?.user}`}
                actions={
                    <>
                        <Button onClick={() => handleExport('csv')} disabled={exporting}><FileDown size={15} /> CSV</Button>
                        <Button onClick={() => handleExport('xlsx')} disabled={exporting}><FileSpreadsheet size={15} /> Excel</Button>
                    </>
                }
            />

            <Card>
                <form onSubmit={handleSubmit} className="space-y-3.5">
                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
                        <div>
                            <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>IP source</label>
                            <input type="text" value={criteria.source_ip} onChange={(e) => updateCriteria({ source_ip: e.target.value })}
                                placeholder="198.51.100.77" className="w-full rounded-lg border px-3 py-2 text-sm outline-none focus:border-[var(--accent)]" style={inputStyle} />
                        </div>
                        <div>
                            <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Hôte</label>
                            <input type="text" value={criteria.host} onChange={(e) => updateCriteria({ host: e.target.value })}
                                placeholder="web-srv-01" className="w-full rounded-lg border px-3 py-2 text-sm outline-none focus:border-[var(--accent)]" style={inputStyle} />
                        </div>
                        <div>
                            <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Utilisateur / mot-clé</label>
                            <input type="text" value={criteria.username} onChange={(e) => updateCriteria({ username: e.target.value })}
                                placeholder="root, admin..." className="w-full rounded-lg border px-3 py-2 text-sm outline-none focus:border-[var(--accent)]" style={inputStyle} />
                        </div>
                        <div>
                            <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Type de log</label>
                            <select value={criteria.log_type} onChange={(e) => updateCriteria({ log_type: e.target.value })}
                                className="w-full rounded-lg border px-3 py-2 text-sm" style={inputStyle}>
                                {LOG_TYPES.map((t) => <option key={t} value={t}>{t || 'Tous'}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Criticité</label>
                            <select value={criteria.severity} onChange={(e) => updateCriteria({ severity: e.target.value })}
                                className="w-full rounded-lg border px-3 py-2 text-sm" style={inputStyle}>
                                {SEVERITIES.map((s) => <option key={s} value={s}>{s || 'Toutes'}</option>)}
                            </select>
                        </div>
                        <div className="flex items-end gap-2">
                            <Button type="submit" variant="primary" className="w-full"><Search size={15} /> Rechercher</Button>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                        <div>
                            <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Depuis</label>
                            <input type="datetime-local" value={criteria.start_date} onChange={(e) => updateCriteria({ start_date: e.target.value ? new Date(e.target.value).toISOString() : '' })}
                                className="w-full rounded-lg border px-3 py-2 text-sm" style={inputStyle} />
                        </div>
                        <div>
                            <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Jusqu'à</label>
                            <input type="datetime-local" value={criteria.end_date} onChange={(e) => updateCriteria({ end_date: e.target.value ? new Date(e.target.value).toISOString() : '' })}
                                className="w-full rounded-lg border px-3 py-2 text-sm" style={inputStyle} />
                        </div>
                        <div className="flex items-end">
                            <Button type="button" onClick={handleReset} className="w-full"><RotateCcw size={15} /> Réinitialiser</Button>
                        </div>
                    </div>
                </form>
            </Card>

            <div className="flex flex-col gap-5 lg:flex-row">
                <Card padded={false} className={`overflow-hidden ${selectedLog ? 'lg:w-3/5' : 'w-full'}`}>
                    <div className="flex items-center justify-between border-b p-3.5" style={{ borderColor: 'var(--border-subtle)' }}>
                        <p className="text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
                            {status === 'ready' ? `${total.toLocaleString()} résultat(s)` : 'Résultats'}
                        </p>
                        {status === 'ready' && totalPages > 1 && (
                            <div className="flex items-center gap-2">
                                <button onClick={() => goToPage(page - 1)} disabled={page <= 1} className="rounded-md p-1 disabled:opacity-30" style={{ color: 'var(--text-muted)' }}><ChevronLeft size={16} /></button>
                                <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>Page {page} / {totalPages}</span>
                                <button onClick={() => goToPage(page + 1)} disabled={page >= totalPages} className="rounded-md p-1 disabled:opacity-30" style={{ color: 'var(--text-muted)' }}><ChevronRight size={16} /></button>
                            </div>
                        )}
                    </div>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm">
                            <thead>
                                <tr className="border-b text-xs font-medium uppercase tracking-wide" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                                    <th className="p-3.5">Horodatage</th>
                                    <th className="p-3.5">Sévérité</th>
                                    <th className="p-3.5">IP source</th>
                                    <th className="p-3.5">Hôte</th>
                                    <th className="p-3.5">Type</th>
                                    <th className="p-3.5">Message</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
                                {status === 'loading' ? (
                                    <tr><td colSpan="6" className="p-0"><LoadingState label="Recherche en cours..." /></td></tr>
                                ) : status === 'error' ? (
                                    <tr><td colSpan="6" className="p-0"><ErrorBanner description={error} /></td></tr>
                                ) : results.length === 0 ? (
                                    <tr><td colSpan="6" className="p-0"><EmptyState title="Aucun log ne correspond aux critères" /></td></tr>
                                ) : (
                                    results.map((log) => (
                                        <tr
                                            key={log.id}
                                            onClick={() => setSelectedLog(log)}
                                            className="cursor-pointer transition-colors"
                                            style={{ background: selectedLog?.id === log.id ? 'var(--accent-soft)' : 'transparent' }}
                                        >
                                            <td className="whitespace-nowrap p-3.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                                                {(log.timestamp || log.received_at || '').replace('T', ' ').slice(0, 19)}
                                            </td>
                                            <td className="p-3.5"><Badge tone={SEV_TONE[log.severity] || 'NEUTRAL'}>{log.severity}</Badge></td>
                                            <td className="p-3.5 font-medium" style={{ color: 'var(--text-primary)' }}>{log.source_ip || '—'}</td>
                                            <td className="p-3.5" style={{ color: 'var(--text-secondary)' }}>{log.host || '—'}</td>
                                            <td className="p-3.5" style={{ color: 'var(--text-secondary)' }}>{log.log_type || '—'}</td>
                                            <td className="max-w-xs truncate p-3.5" style={{ color: 'var(--text-secondary)' }}>{log.raw_message}</td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </Card>

                {selectedLog && (
                    <Card className="w-full lg:w-2/5">
                        <div className="mb-3.5 flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--border-subtle)' }}>
                            <div>
                                <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Détail du log</p>
                                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                    {(selectedLog.timestamp || selectedLog.received_at || '').replace('T', ' ').slice(0, 19)}
                                </p>
                            </div>
                            <button onClick={() => setSelectedLog(null)} className="rounded-md p-1.5" style={{ color: 'var(--text-muted)' }}><X size={15} /></button>
                        </div>
                        <div className="space-y-3 text-xs">
                            <div>
                                <p className="mb-1 font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>IP source</p>
                                <span className="select-all rounded-md border px-2 py-0.5 font-medium" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }}>{selectedLog.source_ip || '—'}</span>
                            </div>
                            <div>
                                <p className="mb-1 font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Hôte</p>
                                <span style={{ color: 'var(--text-primary)' }}>{selectedLog.host || '—'}</span>
                            </div>
                            <div>
                                <p className="mb-1 font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Message brut</p>
                                <p className="rounded-lg border p-2.5 leading-relaxed" style={{ borderColor: 'var(--border-subtle)', background: 'var(--surface-1)', color: 'var(--text-secondary)' }}>{selectedLog.raw_message}</p>
                            </div>
                        </div>

                        <div className="mt-4 grid grid-cols-1 gap-2 border-t pt-4 sm:grid-cols-2" style={{ borderColor: 'var(--border-subtle)' }}>
                            <Button
                                disabled={!selectedLog.source_ip}
                                onClick={() => onInvestigate?.(selectedLog.source_ip)}
                            >
                                <Fingerprint size={15} /> Investiguer cette IP
                            </Button>
                            <Button
                                disabled={!selectedLog.host}
                                onClick={() => onInvestigate?.(selectedLog.host)}
                            >
                                <Fingerprint size={15} /> Investiguer cet hôte
                            </Button>
                        </div>
                    </Card>
                )}
            </div>
        </div>
    );
}
