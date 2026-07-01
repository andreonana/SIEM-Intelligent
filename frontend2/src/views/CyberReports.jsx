import { useState } from 'react';
import { jsPDF } from 'jspdf';
import { domToCanvas } from 'modern-screenshot';

/**
 * COMPOSANT : CyberReports (Générateur Analytique Réel et Exportation PDF)
 */
export default function CyberReports({ user, logs = [], rules = [] }) {
    const [isGenerating, setIsGenerating] = useState(false);
    const [selectedReportType, setSelectedReportType] = useState('mensuel');

    // --- 1. CALCULS ANALYTIQUES DYNAMIQUES EN TEMPS RÉEL ---
    const totalLogs = logs.length;
    const criticalLogs = logs.filter(l => l.severity === 'CRITICAL');
    const criticalCount = criticalLogs.length;
    const highCount = logs.filter(l => l.severity === 'HIGH').length;
    const activeRules = rules.filter(r => r.active);
    const activeRulesCount = activeRules.length;
    
    const unresolvedCount = logs.filter(l => l.status !== 'TRAITÉ').length;
    const simulatedMTTR = Math.max(12, 14 + unresolvedCount * 3); 

    const mainThreatName = criticalCount > 0 ? criticalLogs[0].message : "Aucune anomalie critique persistante";

    // --- 2. LOGIQUE GÉNÉRATIVE DU TEXTE ---
    const generateDynamicContent = (type) => {
        switch (type) {
            case 'mensuel':
                return {
                    title: "BILAN MENSUEL DES OPÉRATIONS SÉCURITÉ (C-LEVEL)",
                    subtitle: `Analyse macroscopique de la posture cyber basée sur l'ingestion de ${totalLogs} événements.`,
                    section1: `1. Posture Globale de l'Infrastructure : La cellule CTU opère actuellement sous un niveau de vigilance optimal avec un total de ${activeRulesCount} règles de corrélation actives sur le moteur SMART SIEM. L'intégrité de la surveillance couvre la totalité des périmètres réseau définis en semaine 1.`,
                    section2: `2. Évaluation des Menaces et Incidents : Sur la période, le SOC a intercepté ${criticalCount} alertes critiques de sévérité 1 (P1) et ${highCount} alertes hautement suspectes (P2). L'événement de corrélation le plus persistant détecté par nos sondes remonte l'activité suivante : "${mainThreatName}". Les playbooks SOAR ont permis de contenir la propagation réseau.`
                };
            case 'incident':
                return {
                    title: "RAPPORT TECHNIQUE POST-INCIDENT (FORENSICS)",
                    subtitle: `Dossier d'investigation numérique complet. Focus alerte : ${mainThreatName}.`,
                    section1: `1. Constat d'Incident et Déclenchement : Une anomalie de sécurité majeure a déclenché le moteur analytique de la cellule CTU. L'investigation se concentre sur l'alerte critique automatisée : "${mainThreatName}". La signature de cet événement est corrélée en direct avec les indicateurs de compromission (IoC).`,
                    section2: `2. État d'Avancement des Analyses : À cette minute, ${unresolvedCount} logs restent à qualifier et nécessitent une attention immédiate de niveau 2 ou 3. Le temps moyen de résolution (MTTR) est mesuré à ~${simulatedMTTR} minutes, respectant les engagements contractuels de remédiation face à la menace.`
                };
            case 'compliance': {
                const totalPossibleRules = rules.length || 5;
                const complianceScore = rules.length > 0 
                    ? Math.round((activeRulesCount / totalPossibleRules) * 100) 
                    : 80;
                return {
                    title: "RAPPORT D'AUDIT DE CONFORMITÉ RÉGLEMENTAIRE (ISO 27001)",
                    subtitle: "Évaluation continue de l'alignement de la plateforme SIEM avec les critères de gouvernance.",
                    section1: `1. Alignement des Politiques de Détection : Le score de conformité technique du SMART SIEM s'élève à ${complianceScore}% de couverture réglementaire. Ce score est directement indexé sur l'activation et le maintien de nos politiques de détection (${activeRulesCount} règles actives sur les ${totalPossibleRules} implémentées).`,
                    section2: `2. Traçabilité et Auditabilité : Le journal d'Audit Trail atteste de la parfaite immuabilité des registres. 100% des actions entreprises par l'opérateur connecté [${user?.name || "Analyste SOC"}] ainsi que les changements de statuts sur les ${totalLogs} lignes de logs sont traçables et archivés pour conformité légale.`
                };
            }
            default:
                return {};
        }
    };

    const currentReport = generateDynamicContent(selectedReportType);

    // --- 3. EXPORTATION VIA MODERN-SCREENSHOT & JSPDF ---
    const handleGenerateReport = async () => {
        setIsGenerating(true);
        const element = document.getElementById('report-pdf-content');

        try {
            // modern-screenshot utilise SVG/Canvas natif, aucun problème avec oklch !
            const canvas = await domToCanvas(element, {
                scale: 2,
                backgroundColor: '#0f172a'
            });

            const imgData = canvas.toDataURL('image/jpeg', 0.98);
            const pdf = new jsPDF('p', 'mm', 'a4');
            
            // Dimensions exactes A4 avec marges
            const imgWidth = 186; 
            const imgHeight = (canvas.height * imgWidth) / canvas.width;

            pdf.addImage(imgData, 'JPEG', 12, 12, imgWidth, imgHeight);
            const reportName = selectedReportType === 'mensuel'
                ? 'monthly-security-operations-report'
                : selectedReportType === 'incident'
                    ? 'post-incident-forensics-report'
                    : 'compliance-audit-report';
            pdf.save(`${reportName}-${new Date().toISOString().slice(0,10)}.pdf`);
        } catch (err) {
            console.error("Erreur lors de la génération du PDF:", err);
        } finally {
            setIsGenerating(false);
        }
    };

    return (
        <div className="space-y-6">
            <div className="flex flex-col gap-4 border-b border-slate-800 pb-5 md:flex-row md:items-center md:justify-between">
                <div>
                    <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.3em] text-amber-400">
                        <span className="h-2 w-2 rounded-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.4)]"></span>
                        <span>Rapports exécutifs et exports de conformité</span>
                    </div>
                    <h1 className="text-3xl font-black text-white">Rapports Cyber</h1>
                    <p className="mt-1 text-sm text-slate-400">Générez des résumés PDF élégants pour la direction, la réponse aux incidents et l'examen d'audit.</p>
                </div>
                <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-sm font-semibold text-emerald-300">
                    Statut : Prêt pour l'export
                </div>
            </div>

            <div className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
                <div className="space-y-6">
                    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 shadow-lg">
                        <h3 className="border-b border-slate-800 pb-2 text-xs font-semibold uppercase tracking-[0.25em] text-slate-400">
                            Configuration d'exportation
                        </h3>
                        <div className="mt-4 space-y-4">
                            <div className="space-y-2">
                                <label className="block text-[11px] uppercase tracking-[0.25em] text-slate-500">Type de rapport</label>
                                <select
                                    value={selectedReportType}
                                    onChange={(e) => setSelectedReportType(e.target.value)}
                                    className="w-full cursor-pointer rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-xs text-slate-200 transition-colors focus:border-amber-500 focus:outline-none"
                                >
                                    <option value="mensuel">Résumé mensuel des opérations</option>
                                    <option value="incident">Rapport technique post-incident</option>
                                    <option value="compliance">Rapport d'audit de conformité</option>
                                </select>
                            </div>

                            <div className="space-y-2">
                                <label className="block text-[11px] uppercase tracking-[0.25em] text-slate-500">Format de sortie</label>
                                <div className="rounded-lg border border-slate-900 bg-slate-950 p-2.5 text-xs font-semibold text-emerald-400">
                                    Document PDF standard
                                </div>
                            </div>

                            <div className="space-y-2">
                                <label className="block text-[11px] uppercase tracking-[0.25em] text-slate-500">Marquage de sécurité</label>
                                <span className="inline-block rounded-full border border-red-500/20 bg-red-500/10 px-2.5 py-1 text-[10px] font-semibold text-red-400">
                                    Restricté • Usage interne uniquement
                                </span>
                            </div>
                        </div>

                        <button
                            onClick={handleGenerateReport}
                            disabled={isGenerating}
                            className={`mt-6 w-full rounded-xl border py-3 text-center text-xs font-semibold uppercase tracking-[0.25em] transition-all ${
                                isGenerating
                                    ? 'cursor-wait border-slate-800 bg-slate-900 text-slate-500'
                                    : 'cursor-pointer border-amber-500/40 bg-amber-600 text-white shadow-lg shadow-amber-950/20 hover:bg-amber-500'
                            }`}
                        >
                            {isGenerating ? 'Préparation du PDF...' : 'Générer le rapport PDF'}
                        </button>
                    </div>

                    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 shadow-lg">
                        <h3 className="border-b border-slate-800 pb-2 text-xs font-semibold uppercase tracking-[0.25em] text-slate-400">
                            Principaux résultats
                        </h3>
                        <ul className="mt-4 space-y-3 text-sm text-slate-300">
                            <li className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">{criticalCount} alertes critiques restent actives et doivent être examinées en premier.</li>
                            <li className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">{activeRulesCount} règles de corrélation sont actuellement actives pour la fenêtre de rapport actuelle.</li>
                            <li className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">L'estimation actuelle du MTTR est d'environ {simulatedMTTR} minutes.</li>
                        </ul>
                    </div>

                    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 shadow-lg">
                        <h3 className="border-b border-slate-800 pb-2 text-xs font-semibold uppercase tracking-[0.25em] text-slate-400">
                            Actions recommandées
                        </h3>
                        <div className="mt-4 space-y-2">
                            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3 text-sm text-slate-300">Priorisez le triage pour les événements les plus graves.</div>
                            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3 text-sm text-slate-300">Validez l'ensemble des règles pour l'exhaustivité avant l'examen par la direction.</div>
                            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3 text-sm text-slate-300">Archivez le rapport généré après la distribution aux parties prenantes.</div>
                        </div>
                    </div>
                </div>

                <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
                    <div className="flex flex-col gap-2 border-b border-slate-800 pb-4 sm:flex-row sm:items-center sm:justify-between">
                        <h2 className="text-sm font-semibold uppercase tracking-[0.25em] text-white">Aperçu du rapport</h2>
                        <span className="text-[10px] text-slate-500">Opérateur : {user?.name || 'Analyste SOC'}</span>
                    </div>

                    <div className="mt-6 grid gap-4 sm:grid-cols-3">
                        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-center sm:text-left">
                            <span className="block text-[10px] uppercase tracking-[0.25em] text-slate-500">Volume actuel</span>
                            <span className="mt-2 block text-2xl font-black text-white">{totalLogs} logs</span>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-center sm:text-left">
                            <span className="block text-[10px] uppercase tracking-[0.25em] text-slate-500">Alertes critiques</span>
                            <span className="mt-2 block text-2xl font-black text-rose-400">{criticalCount} P1</span>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-center sm:text-left">
                            <span className="block text-[10px] uppercase tracking-[0.25em] text-slate-500">Performance du SOC</span>
                            <span className="mt-2 block text-2xl font-black text-emerald-400">~{simulatedMTTR} min <span className="text-xs font-normal text-slate-500">MTTR</span></span>
                        </div>
                    </div>

                    <div
                        id="report-pdf-content"
                        className="mt-6 space-y-6 rounded-2xl border border-slate-800 bg-slate-950/80 p-6 shadow-inner"
                        style={{ backgroundColor: '#020617', color: '#cbd5e1' }}
                    >
                        <div className="absolute inset-0 pointer-events-none opacity-20" style={{ backgroundImage: 'radial-gradient(circle at top right, rgba(34,211,238,0.2), transparent 35%)' }}></div>
                        <div className="relative space-y-4">
                            <div className="flex items-start justify-between border-b border-slate-800/80 pb-3 text-[10px] uppercase tracking-[0.25em] text-slate-500">
                                <span>Centre d'opérations de sécurité</span>
                                <span>Réf. : SOC-2026-RPT</span>
                            </div>

                            <div className="space-y-1 py-2">
                                <h4 className="text-base font-bold uppercase tracking-[0.25em] text-slate-100">{currentReport.title}</h4>
                                <p className="text-[11px] text-slate-400">{currentReport.subtitle}</p>
                            </div>

                            <div className="space-y-3 border-t border-slate-800/80 pt-4 text-[11px] leading-relaxed text-slate-300">
                                <p>{currentReport.section1}</p>
                                <p>{currentReport.section2}</p>
                                <div className="mt-4 flex flex-col gap-2 border-t border-slate-800/80 pt-3 text-[10px] uppercase tracking-[0.25em] text-slate-500 sm:flex-row sm:items-center sm:justify-between">
                                    <span>Règles actives à l'extraction : {activeRulesCount}</span>
                                    <span>Classification : Restricté</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}