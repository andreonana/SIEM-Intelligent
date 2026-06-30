import React from 'react';

/**
 * COMPOSANT : Compliance (Tableau de bord de Conformité RGPD & ISO 27001)
 * @param {Object} user - L'utilisateur connecté transmis par App.jsx
 * @param {Array} logs - L'état global des logs (source de vérité dynamique)
 */
export default function Compliance({ user, logs }) {
    // 1. CALCUL DYNAMIQUE DU SCORE ISO 27001
    // On pénalise le score si des incidents critiques ou majeurs ne sont pas encore traités
    const activeIncidentsCount = logs.filter(l => l.escalated === true).length;
    const unresolvedCriticals = logs.filter(l => l.severity === 'CRITICAL' && l.status !== 'TRAITÉ').length;
    
    // Formules de scores vivantes (s'adaptent aux actions de l'utilisateur dans l'app)
    const isoScore = Math.max(55, 94 - (unresolvedCriticals * 5) - (activeIncidentsCount * 2));
    const rgpdScore = Math.max(50, 91 - (unresolvedCriticals * 6));

    // 2. FILTRAGE DES INCIDENTS RGPD (Art. 33 : Fuites de données ou accès illégitimes aux DB)
    // Aligné avec la structure des logs de tes fichiers mocks
    const dataViolations = logs.filter(log => 
        log.service?.toLowerCase().includes('db') || 
        log.service?.toLowerCase().includes('auth') ||
        log.event?.toLowerCase().includes('exfiltration') ||
        log.event?.toLowerCase().includes('sql') ||
        log.event?.toLowerCase().includes('privilège')
    );

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            
            {/* ENTÊTE COMPLIANCE */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-5">
                <div>
                    <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
                        <span className="w-2 h-2 rounded-full bg-cyan-500 shadow-[0_0_8px_rgba(6,182,212,0.5)]"></span>
                        <span>[REGULATORY COMPLIANCE & AUDIT ASSURANCE]</span>
                    </div>
                    <h1 className="text-3xl font-black text-white tracking-tight">Tableau de Bord de Conformité</h1>
                </div>
                <div className="bg-slate-900 border border-slate-800/80 px-4 py-2 rounded-xl text-xs font-mono text-slate-400">
                    Rétention légale : <span className="font-bold text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded ml-1">365 Jours (OK)</span>
                </div>
            </div>

            {/* GRILLE DES SCORES (JAUGES DYNAMIQUES) */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                
                {/* BLOC ISO 27001 */}
                <div className="bg-[#0f172a] border border-slate-800 p-6 rounded-xl space-y-4 shadow-lg">
                    <div className="flex justify-between items-center">
                        <h3 className="font-bold text-white font-mono text-sm">ISO/IEC 27001:2022</h3>
                        <span className="text-[10px] font-mono bg-cyan-500/10 text-cyan-400 px-2 py-0.5 rounded border border-cyan-500/20">SMSI</span>
                    </div>
                    <div className="flex items-baseline gap-2 font-mono">
                        <span className="text-4xl font-black text-white">{isoScore}%</span>
                        <span className="text-xs text-slate-500">de conformité</span>
                    </div>
                    <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-900">
                        <div className="bg-cyan-500 h-full transition-all duration-700" style={{ width: `${isoScore}%` }}></div>
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono leading-relaxed">
                        Mesure des contrôles de sécurité : Journalisation (A.12.4), Gestion des accès (A.9) et Continuité d'activité.
                    </p>
                </div>

                {/* BLOC RGPD */}
                <div className="bg-[#0f172a] border border-slate-800 p-6 rounded-xl space-y-4 shadow-lg">
                    <div className="flex justify-between items-center">
                        <h3 className="font-bold text-white font-mono text-sm">RGPD (Règlement UE)</h3>
                        <span className="text-[10px] font-mono bg-purple-500/10 text-purple-400 px-2 py-0.5 rounded border border-purple-500/20">Vie Privée</span>
                    </div>
                    <div className="flex items-baseline gap-2 font-mono">
                        <span className="text-4xl font-black text-white">{rgpdScore}%</span>
                        <span className="text-xs text-slate-500">objectifs atteints</span>
                    </div>
                    <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-900">
                        <div className="bg-purple-500 h-full transition-all duration-700" style={{ width: `${rgpdScore}%` }}></div>
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono leading-relaxed">
                        Évaluation de la protection dès la conception, registre des traitements (Art. 30) et réactivité face aux violations.
                    </p>
                </div>

                {/* BLOC INTEGRITÉ DES LOGS */}
                <div className="bg-[#0f172a] border border-slate-800 p-6 rounded-xl shadow-lg md:col-span-2 lg:col-span-1 flex flex-col justify-between">
                    <div className="flex justify-between items-center mb-2">
                        <h3 className="font-bold text-white font-mono text-sm">Intégrité de la Chaîne</h3>
                        <span className="text-[10px] font-mono bg-emerald-500/10 text-emerald-400 px-2 py-0.5 rounded border border-emerald-500/20">SecOps</span>
                    </div>
                    <div className="space-y-2 font-mono text-xs">
                        <div className="flex justify-between p-1.5 bg-slate-950/40 border border-slate-900 rounded">
                            <span className="text-slate-500">Hachage Journalier</span>
                            <span className="text-emerald-400 font-bold">VALIDE (SHA-256)</span>
                        </div>
                        <div className="flex justify-between p-1.5 bg-slate-950/40 border border-slate-900 rounded">
                            <span className="text-slate-500">Ruptures de Séquence</span>
                            <span className="text-emerald-400 font-bold">0 DÉTECTÉE</span>
                        </div>
                        <div className="flex justify-between p-1.5 bg-slate-950/40 border border-slate-900 rounded">
                            <span className="text-slate-500">Audit Interne</span>
                            <span className="text-slate-400">Effectué il y a 2j</span>
                        </div>
                    </div>
                </div>

            </div>

            {/* EXPACE REVIENT : COMPTE À REBOURS LÉGAL RGPD (72 HEURES CHRONO) */}
            <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
                <div className="bg-slate-900/40 p-4 border-b border-slate-800 flex justify-between items-center font-mono">
                    <span className="text-xs font-bold text-purple-400 uppercase tracking-wider flex items-center gap-2">
                         Suivi des alertes impactant des Données Personnelles (Art. 33 RGPD)
                    </span>
                    <span className="text-[10px] text-slate-500 hidden md:inline">Notification obligatoire CNIL sous 72h max</span>
                </div>
                
                <div className="divide-y divide-slate-800/60">
                    {dataViolations.length === 0 ? (
                        <div className="p-8 text-center text-slate-500 font-mono italic text-xs">
                            Aucun incident critique n'affecte actuellement les bases de données ou les flux de données personnelles.
                        </div>
                    ) : (
                        dataViolations.map((violation) => (
                            <div key={violation.id} className="p-4 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 hover:bg-slate-900/20 transition-all font-mono">
                                <div className="space-y-1 w-full md:w-2/3">
                                    <div className="flex items-center gap-2">
                                        <span className={`w-2 h-2 rounded-full ${violation.status === 'TRAITÉ' ? 'bg-emerald-500' : 'bg-red-500 animate-pulse'}`}></span>
                                        <span className="text-white font-bold text-xs">{violation.id}</span>
                                        <span className="text-[9px] text-cyan-400 bg-cyan-500/10 px-1.5 py-0.2 rounded border border-cyan-500/20 uppercase">
                                            {violation.service}
                                        </span>
                                    </div>
                                    <p className="text-xs text-slate-400 truncate bg-slate-950/40 p-1.5 rounded border border-slate-900/60 font-sans">
                                        {violation.event}
                                    </p>
                                </div>
                                <div className="flex items-center justify-between md:justify-end gap-4 w-full md:w-auto text-xs">
                                    <span className={`px-2 py-0.5 rounded font-bold text-[10px] border ${
                                        violation.status === 'TRAITÉ' 
                                            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' 
                                            : 'bg-red-500/10 border-red-500/30 text-red-400 animate-pulse'
                                    }`}>
                                        {violation.status === 'TRAITÉ' ? '✅ RISQUE ÉCARTÉ' : '⏳ ACTIONS REQUISES (72H)'}
                                    </span>
                                    <span className="text-slate-500 text-[11px] whitespace-nowrap bg-slate-950 px-2 py-1 rounded border border-slate-900">
                                        {violation.timestamp}
                                    </span>
                                </div>
                            </div>
                        ))
                    )}
                </div>
            </div>

            {/* CHECKLISTS COMPLIANCE REPRÉSENTATIVES */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 font-mono">
                
                {/* SÉCURITÉ ISO 27001 */}
                <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
                    <h4 className="font-bold text-slate-200 border-b border-slate-800 pb-2 text-xs uppercase text-cyan-400">// Objectifs de Contrôle ISO 27001</h4>
                    <div className="space-y-3 text-xs">
                        <label className="flex items-start gap-3 text-slate-300">
                            <input type="checkbox" defaultChecked disabled className="mt-0.5 accent-cyan-500" />
                            <div>
                                <span className="block font-bold text-slate-200">A.12.4.1 — Journalisation des événements</span>
                                <span className="text-slate-500 font-sans text-[11px]">Enregistrement continu des accès utilisateurs, erreurs et incidents SecOps.</span>
                            </div>
                        </label>
                        <label className="flex items-start gap-3 text-slate-300">
                            <input type="checkbox" defaultChecked={activeIncidentsCount === 0} disabled className="mt-0.5 accent-cyan-500" />
                            <div>
                                <span className="block font-bold text-slate-200">A.12.4.2 — Protection des journaux d'événements</span>
                                <span className="text-slate-500 font-sans text-[11px]">Verrouillage des fichiers logs contre les modifications et falsifications d'attaquants.</span>
                            </div>
                        </label>
                        <label className="flex items-start gap-3 text-slate-300">
                            <input type="checkbox" defaultChecked className="mt-0.5 accent-cyan-500" />
                            <div>
                                <span className="block font-bold text-slate-200">A.9.1.1 — Politique de contrôle d'accès</span>
                                <span className="text-slate-500 font-sans text-[11px]">Mise en œuvre stricte du cloisonnement et filtrage réseau (Firewall/EDR).</span>
                            </div>
                        </label>
                    </div>
                </div>

                {/* PROTOCOLE RGPD */}
                <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
                    <h4 className="font-bold text-slate-200 border-b border-slate-800 pb-2 text-xs uppercase text-purple-400">// Principes RGPD Opérationnels</h4>
                    <div className="space-y-2 text-xs">
                        <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-900 flex justify-between items-center">
                            <div>
                                <span className="block font-bold text-slate-200">Registre des Traitements (Art. 30)</span>
                                <span className="text-[11px] text-slate-500 font-sans">Cartographie des flux de données de la CTU.</span>
                            </div>
                            <span className="text-[9px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 font-bold">À JOUR</span>
                        </div>
                        <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-900 flex justify-between items-center">
                            <div>
                                <span className="block font-bold text-slate-200">Chiffrement au repos & transit</span>
                                <span className="text-[11px] text-slate-500 font-sans">Utilisation globale des protocoles TLS 1.3 et AES-256.</span>
                            </div>
                            <span className="text-[9px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 font-bold">ACTIF</span>
                        </div>
                        <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-900 flex justify-between items-center">
                            <div>
                                <span className="block font-bold text-slate-200">Analyse d'Impact (AIPD)</span>
                                <span className="text-[11px] text-slate-500 font-sans">Obligatoire pour les bases de données sensibles (RH / Prod).</span>
                            </div>
                            <span className="text-[9px] text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20 font-bold">EN COURS</span>
                        </div>
                    </div>
                </div>

            </div>

        </div>
    );
}