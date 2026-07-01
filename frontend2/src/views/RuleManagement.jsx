

/**
 * COMPOSANT : RuleManagement (Moteur de Corrélation SIEM & Règles de Détection)
 * @param {Object} user - L'utilisateur connecté transmis par App.jsx (ex: role: 'administrator')
 * @param {Array} rules - Les règles globales provenant du mock centralisé transmis par App.jsx
 * @param {Function} setRules - Fonction de mise à jour de l'état global transmise par App.jsx
 */
export default function RuleManagement({ user, rules = [], setRules }) {

    // 🔒 CONTRÔLE D'ACCÈS INTERNE (RBAC) : Aligné sur votre fichier Login.jsx
    // Seul Bill Buchanan (administrator) possède les privilèges d'écriture.
    const isReadOnly = user?.role !== 'administrator';

    // Fonction modifiée pour mettre à jour l'état central partagé (App.jsx)
    const toggleRule = (ruleId) => {
        if (isReadOnly) return; // Sécurité anti-contournement
        
        if (setRules) {
            setRules(prevRules => prevRules.map(rule => {
                if (rule.id === ruleId) {
                    return { ...rule, active: !rule.active };
                }
                return rule;
            }));
        }
    };

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 font-mono text-sm">
            
            {/* ENTÊTE DU COMPOSANT */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-5">
                <div>
                    <div className="flex items-center gap-2 text-xs text-emerald-400 mb-1">
                        <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(52,211,153,0.5)]"></span>
                        <span>SIEM correlation engine</span>
                    </div>
                    <h1 className="text-3xl font-black text-white tracking-tight">Gestion des règles de détection</h1>
                </div>
                <div className="bg-slate-900 border border-slate-800 px-4 py-2 rounded-xl text-xs text-slate-400">
                    Règles Actives : <span className="font-bold text-emerald-400 ml-1">{rules.filter(r => r.active).length} / {rules.length}</span>
                </div>
            </div>

            {/* MESSAGE D'ALERTE DROITS RBAC */}
            {isReadOnly && (
                <div className="bg-amber-500/10 border border-amber-500/30 text-amber-400 p-4 rounded-xl text-xs flex items-center gap-3">
                    <span className="text-sm">•</span>
                    <div>
                        <strong className="uppercase">Mode consultation uniquement :</strong> Votre rôle actuel (<strong>{user?.role || "analyst"}</strong>) ne possède pas les privilèges d'écriture requis pour altérer la politique de détection globale du SIEM. Modifications réservées à l'administrateur système.
                    </div>
                </div>
            )}

            {/* LISTE DES RÈGLES DE DÉTECTION */}
            <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
                <div className="bg-slate-900/40 p-4 border-b border-slate-800">
                    <h3 className="text-xs font-bold uppercase text-slate-300">Règles de corrélation en production</h3>
                </div>

                <div className="divide-y divide-slate-800/60">
                    {rules.map((rule) => (
                        <div key={rule.id} className="p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 hover:bg-slate-900/20 transition-all">
                            
                            {/* Descriptif technique de la règle */}
                            <div className="space-y-1 w-full sm:w-3/4">
                                <div className="flex flex-wrap items-center gap-2">
                                    <span className="text-emerald-400 font-bold text-xs">{rule.id}</span>
                                    <h4 className="text-white font-bold text-sm">{rule.name}</h4>
                                    <span className="text-[10px] bg-slate-950 text-slate-400 border border-slate-800 px-1.5 py-0.5 rounded uppercase">
                                        {rule.category}
                                    </span>
                                    <span className={`text-[9px] px-1.5 py-0.2 rounded font-black ${
                                        rule.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                    }`}>
                                        {rule.severity}
                                    </span>
                                </div>
                                <p className="text-xs text-slate-400 font-sans leading-relaxed">
                                    {rule.description}
                                </p>
                            </div>

                            {/* Commutateur On/Off (Toggle Switch) */}
                            <div className="flex items-center gap-3 self-end sm:self-center">
                                <span className={`text-[10px] font-bold ${rule.active ? 'text-emerald-400' : 'text-slate-600'}`}>
                                    {rule.active ? 'ACTIVE' : 'INACTIVE'}
                                </span>
                                <button
                                    onClick={() => toggleRule(rule.id)}
                                    disabled={isReadOnly}
                                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none border ${
                                        isReadOnly 
                                            ? 'bg-slate-900 border-slate-800 opacity-40 cursor-not-allowed' 
                                            : rule.active 
                                                ? 'bg-emerald-600 border-emerald-500 cursor-pointer' 
                                                : 'bg-slate-950 border-slate-800 cursor-pointer'
                                    }`}
                                >
                                    <span
                                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                                            rule.active ? 'translate-x-6' : 'translate-x-1'
                                        }`}
                                    />
                                </button>
                            </div>

                        </div>
                    ))}
                </div>
            </div>

        </div>
    );
}