import { PlayCircle } from 'lucide-react';
import { toggleRule as apiToggleRule, runCorrelation } from '../services/api';
import { PageHeader, Card, Badge, Button, ReadOnlyNotice, EmptyState, LoadingState } from '../components/ui/primitives';

/** Gestion des règles de corrélation — activation/désactivation réelle, lancement manuel de corrélation. */
export default function RuleManagement({ user, rules = [], setRules, onRefresh, dataStatus = 'ready' }) {
    const isReadOnly = user?.role !== 'administrator';

    const toggleRule = async (ruleId) => {
        if (isReadOnly) return;
        const rule = rules.find((r) => r.id === ruleId);
        if (!rule) return;

        setRules?.((prev) => prev.map((r) => (r.id === ruleId ? { ...r, active: !r.active } : r)));

        if (rule._realId) {
            try {
                await apiToggleRule(rule._realId, !rule.active);
                onRefresh?.();
            } catch (err) {
                console.warn('Toggle rule failed:', err.message);
                setRules?.((prev) => prev.map((r) => (r.id === ruleId ? { ...r, active: rule.active } : r)));
            }
        }
    };

    const handleRunCorrelation = async () => {
        try {
            const result = await runCorrelation();
            alert(`Corrélation exécutée : ${result.alerts_created} nouvelle(s) alerte(s), ${result.rules_evaluated} règle(s) évaluée(s).`);
            onRefresh?.();
        } catch (err) {
            alert(`Erreur : ${err.message}`);
        }
    };

    return (
        <div className="space-y-5">
            <PageHeader
                eyebrow="Administration"
                title="Règles de corrélation"
                description="Moteur de détection en production."
                actions={
                    <>
                        <Badge tone="SUCCESS">{rules.filter((r) => r.active).length} / {rules.length} actives</Badge>
                        <Button variant="primary" onClick={handleRunCorrelation}><PlayCircle size={15} /> Lancer une corrélation</Button>
                    </>
                }
            />

            {isReadOnly && <ReadOnlyNotice role={user?.role || 'analyst'} action="modifier les règles de détection" />}

            <Card padded={false}>
                {dataStatus === 'loading' ? (
                    <LoadingState label="Chargement des règles..." />
                ) : rules.length === 0 ? (
                    <EmptyState title="Aucune règle disponible" />
                ) : (
                    <div className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
                        {rules.map((rule) => (
                            <div key={rule.id} className="flex flex-col items-start justify-between gap-3.5 p-4 sm:flex-row sm:items-center">
                                <div className="space-y-1.5">
                                    <div className="flex flex-wrap items-center gap-2">
                                        <span className="text-xs font-medium" style={{ color: 'var(--accent)' }}>{rule.id}</span>
                                        <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{rule.name}</p>
                                        <Badge tone="NEUTRAL">{rule.category}</Badge>
                                        <Badge tone={rule.severity}>{rule.severity}</Badge>
                                    </div>
                                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{rule.description}</p>
                                </div>
                                <div className="flex shrink-0 items-center gap-2.5 self-end sm:self-center">
                                    <span className="text-xs font-medium" style={{ color: rule.active ? '#34d399' : 'var(--text-muted)' }}>
                                        {rule.active ? 'Active' : 'Inactive'}
                                    </span>
                                    <button
                                        onClick={() => toggleRule(rule.id)}
                                        disabled={isReadOnly}
                                        className="relative h-5.5 w-10 rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-40"
                                        style={{ background: rule.active ? 'var(--accent)' : 'var(--surface-3)', height: 22 }}
                                    >
                                        <span
                                            className="absolute top-0.5 h-4 w-4 rounded-full bg-white transition-transform"
                                            style={{ transform: rule.active ? 'translateX(20px)' : 'translateX(2px)' }}
                                        />
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </Card>
        </div>
    );
}
