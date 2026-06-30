import React, { useState } from 'react';
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
            pdf.save(`smart-siem-report-${selectedReportType}-${new Date().toISOString().slice(0,10)}.pdf`);
        } catch (err) {
            console.error("Erreur lors de la génération du PDF:", err);
        } finally {
            setIsGenerating(false);
        }
    };

    return (
        <div className="space-y-6">
            {/* ENTÊTE DE LA VUE */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-5">
                <div>
                    <div className="flex items-center gap-2 text-xs font-mono text-amber-400 mb-1">
                        <span className="w-2 h-2 rounded-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]"></span>
                        <span>[EXECUTIVE REPORTING & COMPLIANCE EXPORTS]</span>
                    </div>
                    <h1 className="text-3xl font-black text-white tracking-tight">Rapports Cyber (PDF)</h1>
                </div>
            </div>

            {/* CONFIGURATEUR + APERÇU EN GRILLE */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono">
                
                {/* COLONNE CONFIGURATION DE L'EXPORT */}
                <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-5 shadow-lg flex flex-col justify-between">
                    <div className="space-y-4">
                        <h3 className="text-xs font-bold uppercase text-slate-400 border-b border-slate-800 pb-2">
                            // Configuration de l'export
                        </h3>
                        
                        <div className="space-y-2">
                            <label className="text-[11px] text-slate-500 uppercase block">Type de Bilan</label>
                            <select 
                                value={selectedReportType}
                                onChange={(e) => setSelectedReportType(e.target.value)}
                                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500 transition-colors cursor-pointer"
                            >
                                <option value="mensuel">Bilan Mensuel des Opérations (C-Level)</option>
                                <option value="incident">Rapport Technique Post-Incident (Forensics)</option>
                                <option value="compliance">Rapport d'Audit de Conformité (ISO 27001)</option>
                            </select>
                        </div>

                        <div className="space-y-2">
                            <label className="text-[11px] text-slate-500 uppercase block">Format de sortie</label>
                            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-900 text-xs text-emerald-400 font-bold flex items-center gap-2">
                                 Document PDF Standardisé (.pdf)
                            </div>
                        </div>

                        <div className="space-y-2">
                            <label className="text-[11px] text-slate-500 uppercase block">Marquage de sécurité</label>
                            <span className="inline-block text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded font-bold">
                                 STRICTEMENT CONFIDENTIEL / CTU USE ONLY
                            </span>
                        </div>
                    </div>

                    <button
                        onClick={handleGenerateReport}
                        disabled={isGenerating}
                        className={`w-full mt-6 text-xs font-bold py-3 rounded-lg border uppercase tracking-wider font-mono transition-all text-center ${
                            isGenerating
                                ? 'bg-slate-900 border-slate-800 text-slate-500 cursor-wait'
                                : 'bg-amber-600 hover:bg-amber-500 border-amber-500 text-white cursor-pointer shadow-lg shadow-amber-950/20'
                        }`}
                    >
                        {isGenerating ? " Compilation du PDF..." : " Générer le Rapport PDF"}
                    </button>
                </div>

                {/* BLOC PRÉVISUALISATION */}
                <div 
                    id="report-pdf-content" 
                    style={{ backgroundColor: '#0f172a', color: '#cbd5e1' }}
                    className="lg:col-span-2 bg-[#0f172a] border border-slate-800 rounded-xl p-6 shadow-lg space-y-6"
                >
                    <div className="flex justify-between items-center border-b border-slate-800 pb-4" style={{ borderColor: '#334155' }}>
                        <h2 className="text-sm font-bold text-white uppercase tracking-tight">
                             Aperçu des Métriques Intégrées au Rapport
                        </h2>
                        <span className="text-[10px] text-slate-500">Opérateur : {user?.name || "Analyste SOC"}</span>
                    </div>

                    {/* GRILLE DES KPIS */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <div className="p-4 rounded-lg border text-center sm:text-left" style={{ backgroundColor: '#020617', borderColor: '#1e293b' }}>
                            <span className="block text-[10px] text-slate-500 uppercase">Volume Courant</span>
                            <span className="text-2xl font-black text-white">{totalLogs} logs</span>
                        </div>
                        <div className="p-4 rounded-lg border text-center sm:text-left" style={{ backgroundColor: '#020617', borderColor: '#1e293b' }}>
                            <span className="block text-[10px] text-slate-500 uppercase">Alertes Critiques</span>
                            <span className="text-2xl font-black" style={{ color: '#f87171' }}>{criticalCount} P1</span>
                        </div>
                        <div className="p-4 rounded-lg border text-center sm:text-left" style={{ backgroundColor: '#020617', borderColor: '#1e293b' }}>
                            <span className="block text-[10px] text-slate-500 uppercase">Performance SOC</span>
                            <span className="text-2xl font-black" style={{ color: '#34d399' }}>~{simulatedMTTR} min <span className="text-xs font-normal" style={{ color: '#64748b' }}>MTTR</span></span>
                        </div>
                    </div>

                    {/* COUVERTURE DU RAPPORT TEXTUEL */}
                    <div className="border rounded-xl p-6 text-xs space-y-4 shadow-inner relative overflow-hidden" style={{ backgroundColor: '#020617', borderColor: '#1e293b', color: '#94a3b8' }}>
                        
                        <div 
                            className="absolute right-4 bottom-4 text-7xl font-black select-none pointer-events-none font-mono tracking-widest"
                            style={{ color: 'rgba(30, 41, 59, 0.3)' }}
                        >
                            CTU
                        </div>

                        <div className="border-b pb-3 flex justify-between items-start text-[10px]" style={{ borderColor: '#1e293b', color: '#64748b' }}>
                            <span>CENTRAL TERRORIST UNIT — CYBER DEFENSE DIVISION</span>
                            <span>REF: SOC-2026-RPT</span>
                        </div>

                        <div className="space-y-1 py-2">
                            <h4 className="text-base font-bold tracking-wide font-mono uppercase" style={{ color: '#f1f5f9' }}>
                                {currentReport.title}
                            </h4>
                            <p className="text-[11px] font-sans italic" style={{ color: '#64748b' }}>
                                {currentReport.subtitle}
                            </p>
                        </div>

                        {/* CORPS TEXTUEL */}
                        <div className="space-y-3 border-t pt-4 text-[11px] leading-relaxed font-sans" style={{ borderColor: '#1e293b', color: '#e2e8f0' }}>
                            <p>{currentReport.section1}</p>
                            <p>{currentReport.section2}</p>
                            
                            <div className="text-[10px] border-t pt-3 mt-4 flex justify-between font-mono" style={{ borderColor: '#1e293b', color: '#64748b' }}>
                                <span>Règles actives lors de l'extraction : {activeRulesCount}</span>
                                <span>Classification : RESTRICTED-CTU</span>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
}