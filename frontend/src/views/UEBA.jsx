import { useState, useEffect } from 'react';
import { Radar } from 'lucide-react';
import { getUebaRiskScores, getUebaAnomalies, runUebaAnalysis } from '../services/api';
import { PageHeader, Card, Badge, Button, StatCard, LoadingState, EmptyState, ReadOnlyNotice } from '../components/ui/primitives';

const RISK_TONE = { critical: 'CRITICAL', high: 'HIGH', medium: 'WARNING', low: 'SUCCESS' };
const SEVERITY_TONE = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'WARNING', LOW: 'SUCCESS' };

/** Analyse comportementale (UEBA) — score de risque dynamique par entité et anomalies détectées. */
export default function UEBA({ user }) {
    const [riskScores, setRiskScores] = useState([]);
    const [anomalies, setAnomalies] = useState([]);
    const [selectedEntity, setSelectedEntity] = useState(null);
    const [loading, setLoading] = useState(true);
    const [analyzing, setAnalyzing] = useState(false);

    const isAdmin = user?.role === 'administrator' || user?.role === 'analyst';

    const load = async () => {
        setLoading(true);
        try {
            const [scores, anoms] = await Promise.all([getUebaRiskScores(), getUebaAnomalies()]);
            setRiskScores(scores);
            setAnomalies(anoms);
        } catch (err) {
            console.warn('UEBA load failed:', err.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { load(); }, []);

    const handleRunAnalysis = async () => {
        if (!isAdmin) return;
        setAnalyzing(true);
        try {
            await runUebaAnalysis();
            await load();
        } catch (err) {
            alert(`Erreur : ${err.message}`);
        } finally {
            setAnalyzing(false);
        }
    };

    const criticalCount = riskScores.filter((r) => r.risk_level === 'critical').length;
    const highCount = riskScores.filter((r) => r.risk_level === 'high').length;
    const avgScore = riskScores.length ? Math.round(riskScores.reduce((s, r) => s + r.score, 0) / riskScores.length) : 0;
    const entityAnomalies = selectedEntity ? anomalies.filter((a) => a.entity_id === selectedEntity.entity_id) : [];

    return (
        <div className="space-y-5">
            <PageHeader
                eyebrow="Investigation"
                title="Analyse comportementale"
                description="Score de risque dynamique par entité et détection d'anomalies."
                actions={<Button variant="primary" onClick={handleRunAnalysis} disabled={!isAdmin || analyzing}>{analyzing ? 'Analyse en cours...' : 'Lancer une analyse'}</Button>}
            />

            {!isAdmin && <ReadOnlyNotice role={user?.role} action="déclencher une analyse UEBA" />}

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
                <StatCard label="Entités surveillées" value={riskScores.length} />
                <StatCard label="Risque critique" value={criticalCount} tone="CRITICAL" />
                <StatCard label="Risque élevé" value={highCount} tone="HIGH" />
                <StatCard label="Score moyen" value={`${avgScore}/100`} tone="INFO" />
            </div>

            {loading ? (
                <LoadingState label="Chargement des données comportementales..." />
            ) : riskScores.length === 0 ? (
                <EmptyState icon={Radar} title="Aucune anomalie comportementale détectée" description="Toutes les entités surveillées se comportent conformément à leur profil habituel." />
            ) : (
                <div className="flex flex-col gap-5 lg:flex-row">
                    <div className="space-y-2.5 lg:w-1/2">
                        {riskScores.slice().sort((a, b) => b.score - a.score).map((r) => (
                            <button
                                key={r.id}
                                onClick={() => setSelectedEntity(r)}
                                className="w-full rounded-lg border p-3.5 text-left transition-colors"
                                style={{
                                    borderColor: selectedEntity?.id === r.id ? 'var(--accent)' : 'var(--border-subtle)',
                                    background: selectedEntity?.id === r.id ? 'var(--accent-soft)' : 'var(--surface-2)',
                                }}
                            >
                                <div className="mb-1.5 flex items-center justify-between">
                                    <Badge tone={RISK_TONE[r.risk_level] || 'WARNING'}>{r.risk_level}</Badge>
                                    <span className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>{r.score}/100</span>
                                </div>
                                <p className="truncate text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{r.entity_id}</p>
                                <p className="mt-0.5 text-xs" style={{ color: 'var(--text-muted)' }}>{r.entity_type} · {r.anomaly_count} anomalie(s)</p>
                                <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full" style={{ background: 'var(--surface-3)' }}>
                                    <div className="h-full rounded-full" style={{
                                        width: `${Math.min(100, r.score)}%`,
                                        background: r.score >= 70 ? 'var(--sev-critical)' : r.score >= 40 ? 'var(--sev-high)' : r.score >= 20 ? 'var(--sev-warning)' : 'var(--sev-success)',
                                    }} />
                                </div>
                            </button>
                        ))}
                    </div>

                    <Card className="lg:flex-1">
                        {!selectedEntity ? (
                            <EmptyState title="Sélectionnez une entité" description="Consultez le détail des anomalies et la justification du score." />
                        ) : (
                            <div className="space-y-4">
                                <div className="flex items-center justify-between border-b pb-3.5" style={{ borderColor: 'var(--border-subtle)' }}>
                                    <div>
                                        <p className="text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Entité analysée</p>
                                        <p className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>{selectedEntity.entity_id}</p>
                                    </div>
                                    <Badge tone={RISK_TONE[selectedEntity.risk_level] || 'WARNING'}>{selectedEntity.risk_level} — {selectedEntity.score}/100</Badge>
                                </div>

                                <div>
                                    <p className="mb-1.5 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Justification du score</p>
                                    <pre className="whitespace-pre-wrap rounded-lg border p-3.5 text-xs leading-relaxed" style={{ borderColor: 'var(--border-subtle)', background: 'var(--surface-1)', color: 'var(--text-secondary)' }}>
                                        {selectedEntity.justification}
                                    </pre>
                                </div>

                                <div>
                                    <p className="mb-2 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
                                        Anomalies détectées ({entityAnomalies.length})
                                    </p>
                                    <div className="space-y-2">
                                        {entityAnomalies.map((a) => (
                                            <div key={a.id} className="rounded-lg border p-3" style={{ borderColor: 'var(--border-subtle)' }}>
                                                <div className="mb-1 flex items-center justify-between">
                                                    <Badge tone={SEVERITY_TONE[a.severity] || 'WARNING'}>{a.severity}</Badge>
                                                    <span className="text-[11px]" style={{ color: 'var(--text-muted)' }}>{(a.detected_at || '').replace('T', ' ').slice(0, 19)}</span>
                                                </div>
                                                <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{a.anomaly_type}</p>
                                                <p className="mt-0.5 text-xs" style={{ color: 'var(--text-muted)' }}>{a.description}</p>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        )}
                    </Card>
                </div>
            )}
        </div>
    );
}
