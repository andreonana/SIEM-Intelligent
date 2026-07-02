import { useState } from 'react';
import { jsPDF } from 'jspdf';
import { domToCanvas } from 'modern-screenshot';

const REPORT_TYPES = [
    {
        id: 'mensuel',
        label: 'Bilan mensuel',
        description: 'Synthèse C-level : posture, menaces et activité SOC.',
    },
    {
        id: 'incident',
        label: 'Post-incident',
        description: 'Dossier forensics sur l’alerte critique principale.',
    },
    {
        id: 'compliance',
        label: 'Audit conformité',
        description: 'Alignement ISO 27001 et traçabilité des contrôles.',
    },
];

function isResolved(log) {
    const status = log.status || '';
    return status === 'TRAITÉ' || status === 'TRAITE' || status === 'FAUX_POSITIF';
}

export default function CyberReports({ user, logs = [], rules = [] }) {
    const [isGenerating, setIsGenerating] = useState(false);
    const [selectedReportType, setSelectedReportType] = useState('mensuel');

    const totalLogs = logs.length;
    const criticalLogs = logs.filter((l) => l.severity === 'CRITICAL');
    const criticalCount = criticalLogs.length;
    const highCount = logs.filter((l) => l.severity === 'HIGH').length;
    const activeRulesCount = rules.filter((r) => r.active).length;
    const unresolvedCount = logs.filter((l) => !isResolved(l)).length;
    const escalatedCount = logs.filter((l) => l.escalated).length;
    const simulatedMTTR = Math.max(12, 14 + unresolvedCount * 3);

    const mainThreat =
        criticalCount > 0
            ? criticalLogs[0].event || criticalLogs[0].message || 'Alerte critique'
            : 'Aucune anomalie critique persistante';

    const generateDynamicContent = (type) => {
        switch (type) {
            case 'mensuel':
                return {
                    title: 'Bilan mensuel des opérations sécurité',
                    subtitle: `${totalLogs} événements analysés sur la période.`,
                    highlights: [
                        `${activeRulesCount} règles de corrélation actives`,
                        `${criticalCount} alerte(s) critique(s) · ${highCount} alerte(s) haute(s)`,
                        `Menace dominante : ${mainThreat}`,
                    ],
                    section1:
                        'La cellule CTU maintient une couverture de détection sur l’ensemble des périmètres surveillés. Les playbooks SOAR contribuent à la containment automatique des menaces récurrentes.',
                    section2:
                        'Ce document est destiné à la direction pour le suivi macroscopique de la posture cyber. Le détail opérationnel reste disponible dans le Dashboard et le triage des alertes.',
                };
            case 'incident':
                return {
                    title: 'Rapport technique post-incident',
                    subtitle: `Focus investigation : ${mainThreat}`,
                    highlights: [
                        `${unresolvedCount} log(s) encore à qualifier`,
                        `MTTR estimé : ~${simulatedMTTR} minutes`,
                        `${escalatedCount} incident(s) escaladé(s) en cellule de crise`,
                    ],
                    section1:
                        'Anomalie majeure détectée par le moteur de corrélation SMART SIEM. Les IoC associés sont documentés dans le Log Explorer et la Crisis Room.',
                    section2:
                        'Ce rapport consolide l’état d’avancement de l’investigation au moment de l’export. Il complète le dossier forensics géré par les analystes L2/L3.',
                };
            case 'compliance': {
                const totalPossibleRules = rules.length || 5;
                const complianceScore =
                    rules.length > 0
                        ? Math.round((activeRulesCount / totalPossibleRules) * 100)
                        : 80;
                return {
                    title: "Rapport d'audit de conformité",
                    subtitle: 'Évaluation ISO 27001 et traçabilité SIEM.',
                    highlights: [
                        `Score de couverture détection : ${complianceScore}%`,
                        `${activeRulesCount} / ${totalPossibleRules} règles actives`,
                        `Opérateur export : ${user?.name || 'Analyste SOC'}`,
                    ],
                    section1:
                        'Le score de conformité technique reflète l’activation des politiques de détection et la complétude des contrôles de journalisation.',
                    section2:
                        'Les actions opérateurs et changements de statut sont archivés dans l’Audit Trail pour répondre aux exigences d’auditabilité réglementaire.',
                };
            }
            default:
                return { title: '', subtitle: '', highlights: [], section1: '', section2: '' };
        }
    };

    const currentReport = generateDynamicContent(selectedReportType);
    const selectedMeta = REPORT_TYPES.find((r) => r.id === selectedReportType);

    const handleGenerateReport = async () => {
        setIsGenerating(true);
        const element = document.getElementById('report-pdf-content');

        try {
            const canvas = await domToCanvas(element, {
                scale: 2,
                backgroundColor: '#0f172a',
            });

            const imgData = canvas.toDataURL('image/jpeg', 0.98);
            const pdf = new jsPDF('p', 'mm', 'a4');
            const imgWidth = 186;
            const imgHeight = (canvas.height * imgWidth) / canvas.width;

            pdf.addImage(imgData, 'JPEG', 12, 12, imgWidth, imgHeight);
            const reportName =
                selectedReportType === 'mensuel'
                    ? 'bilan-mensuel-securite'
                    : selectedReportType === 'incident'
                      ? 'rapport-post-incident'
                      : 'rapport-audit-conformite';
            pdf.save(`${reportName}-${new Date().toISOString().slice(0, 10)}.pdf`);
        } catch (err) {
            console.error('Erreur lors de la génération du PDF:', err);
        } finally {
            setIsGenerating(false);
        }
    };

    return (
        <div className="mx-auto max-w-4xl space-y-8 animate-in fade-in duration-500">
            <div className="border-b border-slate-800 pb-6">
                <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.3em] text-amber-400">
                    <span className="h-2 w-2 rounded-full bg-amber-500" />
                    <span>Exports PDF</span>
                </div>
                <h1 className="text-3xl font-black text-white">Rapports Cyber</h1>
                <p className="mt-2 text-sm text-slate-400">
                    Choisissez un modèle, vérifiez l’aperçu, puis exportez en PDF.
                </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
                {REPORT_TYPES.map((type) => {
                    const isSelected = selectedReportType === type.id;
                    return (
                        <button
                            key={type.id}
                            type="button"
                            onClick={() => setSelectedReportType(type.id)}
                            className={`rounded-xl border p-4 text-left transition-all ${
                                isSelected
                                    ? 'border-amber-500/50 bg-amber-500/10 shadow-lg shadow-amber-950/10'
                                    : 'border-slate-800 bg-slate-900/50 hover:border-slate-700'
                            }`}
                        >
                            <p
                                className={`text-sm font-bold ${isSelected ? 'text-amber-300' : 'text-white'}`}
                            >
                                {type.label}
                            </p>
                            <p className="mt-1 text-xs text-slate-500">{type.description}</p>
                        </button>
                    );
                })}
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 shadow-lg">
                <div className="flex flex-col gap-3 border-b border-slate-800 px-6 py-4 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                        <p className="text-[10px] font-semibold uppercase tracking-[0.25em] text-slate-500">
                            Aperçu — {selectedMeta?.label}
                        </p>
                        <p className="mt-1 text-xs text-slate-400">
                            {user?.name || 'Analyste SOC'} · {new Date().toLocaleDateString('fr-FR')}
                        </p>
                    </div>
                    <button
                        type="button"
                        onClick={handleGenerateReport}
                        disabled={isGenerating}
                        className={`rounded-lg border px-5 py-2.5 text-xs font-bold uppercase tracking-wide transition-all ${
                            isGenerating
                                ? 'cursor-wait border-slate-800 bg-slate-900 text-slate-500'
                                : 'border-amber-500/40 bg-amber-600 text-white hover:bg-amber-500'
                        }`}
                    >
                        {isGenerating ? 'Génération…' : 'Exporter PDF'}
                    </button>
                </div>

                <div className="p-6">
                    <div
                        id="report-pdf-content"
                        className="space-y-5 rounded-xl border border-slate-800 bg-[#020617] p-6"
                        style={{ backgroundColor: '#020617', color: '#cbd5e1' }}
                    >
                        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 text-[10px] uppercase tracking-[0.2em] text-slate-500">
                            <span>SMART SIEM — Cellule CTU</span>
                            <span>SOC-2026-RPT</span>
                        </div>

                        <div>
                            <h2 className="text-lg font-bold uppercase tracking-wide text-slate-100">
                                {currentReport.title}
                            </h2>
                            <p className="mt-1 text-sm text-slate-400">{currentReport.subtitle}</p>
                        </div>

                        <ul className="space-y-2">
                            {currentReport.highlights.map((item) => (
                                <li
                                    key={item}
                                    className="flex items-start gap-2 text-sm text-slate-300"
                                >
                                    <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-500" />
                                    {item}
                                </li>
                            ))}
                        </ul>

                        <div className="space-y-3 border-t border-slate-800/80 pt-4 text-sm leading-relaxed text-slate-400">
                            <p>{currentReport.section1}</p>
                            <p>{currentReport.section2}</p>
                        </div>

                        <div className="flex flex-col gap-1 border-t border-slate-800/80 pt-3 text-[10px] uppercase tracking-[0.2em] text-slate-600 sm:flex-row sm:justify-between">
                            <span>Classification : Restricté — usage interne</span>
                            <span>{totalLogs} logs · {criticalCount} critiques</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
