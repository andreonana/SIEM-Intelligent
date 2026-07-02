import { useState, useEffect } from 'react';
import { FileDown } from 'lucide-react';
import { downloadPdfReport, getReportSummary } from '../services/api';
import { PageHeader, Card, Button, LoadingState, ErrorBanner, EmptyState } from '../components/ui/primitives';

const inputStyle = { background: 'var(--surface-1)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' };

/**
 * Génère et télécharge le rapport PDF réel produit par le backend (agrégation
 * Elasticsearch + SQL). L'aperçu affiché provient de la même donnée que le PDF.
 */
export default function CyberReports({ user }) {
    const [days, setDays] = useState(7);
    const [summary, setSummary] = useState(null);
    const [summaryStatus, setSummaryStatus] = useState('loading');
    const [isGenerating, setIsGenerating] = useState(false);
    const [downloadError, setDownloadError] = useState(null);

    useEffect(() => {
        setSummaryStatus('loading');
        getReportSummary(days)
            .then((res) => { setSummary(res.data); setSummaryStatus('ready'); })
            .catch(() => setSummaryStatus('error'));
    }, [days]);

    const handleDownload = async () => {
        setIsGenerating(true);
        setDownloadError(null);
        try {
            await downloadPdfReport(days);
        } catch (err) {
            setDownloadError(err.message || 'Échec du téléchargement du rapport PDF.');
        } finally {
            setIsGenerating(false);
        }
    };

    return (
        <div className="space-y-5">
            <PageHeader
                eyebrow="Reporting"
                title="Rapports"
                description="Rapport PDF généré par le backend à partir des données réelles sur la période sélectionnée."
            />

            <div className="grid gap-5 xl:grid-cols-[0.9fr_1.1fr]">
                <Card>
                    <p className="mb-3.5 text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Configuration</p>
                    <label className="mb-1.5 block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>Période</label>
                    <select value={days} onChange={(e) => setDays(Number(e.target.value))} className="w-full rounded-lg border p-2.5 text-sm" style={inputStyle}>
                        <option value={1}>Dernières 24 heures</option>
                        <option value={7}>7 derniers jours</option>
                        <option value={30}>30 derniers jours</option>
                    </select>

                    <Button variant="primary" className="mt-4 w-full" onClick={handleDownload} disabled={isGenerating}>
                        <FileDown size={15} /> {isGenerating ? 'Génération...' : 'Télécharger le rapport PDF'}
                    </Button>

                    {downloadError && <div className="mt-3"><ErrorBanner description={downloadError} /></div>}
                </Card>

                <Card>
                    <div className="mb-4 flex items-center justify-between border-b pb-3.5" style={{ borderColor: 'var(--border-subtle)' }}>
                        <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Aperçu des données ({days} j)</p>
                        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{user?.name || user?.user}</p>
                    </div>

                    {summaryStatus === 'loading' && <LoadingState label="Chargement des données..." />}
                    {summaryStatus === 'error' && <ErrorBanner description="Impossible de charger l'aperçu du rapport." />}

                    {summaryStatus === 'ready' && summary && (
                        <div className="space-y-4">
                            <div className="grid gap-3.5 sm:grid-cols-3">
                                <div className="rounded-lg border p-3.5" style={{ borderColor: 'var(--border-subtle)' }}>
                                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Logs ingérés</p>
                                    <p className="mt-1.5 text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>{summary.logs?.total ?? 0}</p>
                                </div>
                                <div className="rounded-lg border p-3.5" style={{ borderColor: 'var(--border-subtle)' }}>
                                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Alertes</p>
                                    <p className="mt-1.5 text-2xl font-semibold" style={{ color: '#f87171' }}>{summary.alerts?.total ?? 0}</p>
                                </div>
                                <div className="rounded-lg border p-3.5" style={{ borderColor: 'var(--border-subtle)' }}>
                                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Entités à risque</p>
                                    <p className="mt-1.5 text-2xl font-semibold" style={{ color: 'var(--accent)' }}>{summary.ueba?.high_risk_entities?.length ?? 0}</p>
                                </div>
                            </div>

                            <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border-subtle)' }}>
                                <p className="mb-2.5 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Alertes par sévérité</p>
                                {summary.alerts?.by_severity && Object.keys(summary.alerts.by_severity).length > 0 ? (
                                    <div className="space-y-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                                        {Object.entries(summary.alerts.by_severity).map(([sev, count]) => (
                                            <div key={sev} className="flex justify-between"><span>{sev}</span><span className="font-medium">{count}</span></div>
                                        ))}
                                    </div>
                                ) : <EmptyState title="Aucune alerte sur la période" />}
                            </div>

                            <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border-subtle)' }}>
                                <p className="mb-2.5 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Audit</p>
                                {summary.audit?.by_action && Object.keys(summary.audit.by_action).length > 0 ? (
                                    <div className="space-y-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                                        {Object.entries(summary.audit.by_action).map(([action, count]) => (
                                            <div key={action} className="flex justify-between"><span>{action}</span><span className="font-medium">{count}</span></div>
                                        ))}
                                    </div>
                                ) : <EmptyState title="Aucune action d'audit sur la période" />}
                            </div>
                        </div>
                    )}
                </Card>
            </div>
        </div>
    );
}
