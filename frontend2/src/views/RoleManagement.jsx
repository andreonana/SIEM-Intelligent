import { useState } from 'react';

const generateTempPassword = () => {
    const randomString = Math.floor(100000 + Math.random() * 900000).toString();
    return `CTU-TEMP-${randomString}!`;
};

/**
 * COMPOSANT : RoleManagement (Gestion avancée des utilisateurs, RBAC & Mots de passe)
 * @param {Object} user - L'utilisateur actuellement connecté transmis par App.jsx
 */
export default function RoleManagement({ user }) {
    // 1. ÉTAT LOCAL : Liste dynamique des opérateurs (Simule le stockage sécurisé)
    const [operators, setOperators] = useState([
        { id: 'OP-01', username: 'bill', name: 'Bill Buchanan', role: 'Directeur de la CTU', level: 'administrator', status: 'Active', password: '••••••••' },
        { id: 'OP-02', username: 'chloe', name: "Chloe O'Brian", role: 'Analyste Cyber Senior', level: 'analyst', status: 'Active', password: '••••••••' },
        { id: 'OP-03', username: 'edgar', name: 'Edgar Stiles', role: 'Technicien Réseau', level: 'reader', status: 'Active', password: '••••••••' }
    ]);

    const roleTitles = {
        administrator: 'Directeur / Administrateur',
        analyst: 'Analyste Cyber L2',
        reader: 'Opérateur de Surveillance L1'
    };

    // États du formulaire
    const [newName, setNewName] = useState('');
    const [newUsername, setNewUsername] = useState('');
    const [newLevel, setNewLevel] = useState('reader');

    const isAdmin = user?.role === 'administrator';

    // 2. LOGIQUE : Création d'utilisateur avec Génération de Mot de Passe Temporaire (Scénario 1)
    const handleCreateUser = (e) => {
        e.preventDefault();
        if (!isAdmin) {
            alert("❌ [RBAC ERROR] Seul l'administrateur peut enrôler de nouveaux profils.");
            return;
        }
        if (!newUsername || !newName) {
            alert("⚠️ Veuillez remplir tous les champs.");
            return;
        }

        // 🔐 SIMULATION SCÉNARIO 1 : Génération d'un token/mot de passe temporaire fort unique
        const tempPassword = generateTempPassword();

        const nextId = `OP-0${operators.length + 1}`;
        const newOp = {
            id: nextId,
            username: newUsername.toLowerCase().trim(),
            name: newName.trim(),
            role: roleTitles[newLevel],
            level: newLevel,
            status: 'Active',
            password: '••••••••' // Stocké immédiatement masqué pour simuler le chiffrement (hachage) en BDD
        };

        setOperators([...operators, newOp]);
        setNewUsername('');
        setNewName('');

        // 📢 Fenêtre critique montrant le secret généré à transmettre à l'employé avant masquage
        alert(
            `🟢 [PROVISIONING SUCCESS] Profil créé pour ${newOp.name}!\n\n` +
            `🔑 MOT DE PASSE TEMPORAIRE GÉNÉRÉ :\n👉 ${tempPassword}\n\n` +
            `💡 À transmette de main à main. L'utilisateur devra obligatoirement réinitialiser ce secret lors de sa première connexion.`
        );
    };

    const handleRoleChange = (operatorId, newRoleLevel) => {
        if (!isAdmin) {
            alert("❌ [RBAC ERROR] Modification des jetons d'accès refusée.");
            return;
        }
        setOperators(prev => prev.map(op => {
            if (op.id === operatorId) {
                return { ...op, level: newRoleLevel, role: roleTitles[newRoleLevel] };
            }
            return op;
        }));
    };

    const handleDeleteUser = (operatorId, operatorName) => {
        if (!isAdmin) {
            alert("❌ [RBAC ERROR] Droits de révocations insuffisants.");
            return;
        }
        if (operatorId === 'OP-01') {
            alert("❌ Action impossible : Le compte racine de l'administrateur principal ne peut pas être purgé.");
            return;
        }
        if (confirm(`⚠️ Confirmation : Supprimer définitivement le compte SIEM de ${operatorName} ?`)) {
            setOperators(prev => prev.filter(op => op.id !== operatorId));
        }
    };

    const toggleStatus = (operatorId) => {
        if (!isAdmin) return;
        setOperators(prev => prev.map(op => {
            if (op.id === operatorId) {
                return { ...op, status: op.status === 'Active' ? 'Suspended' : 'Active' };
            }
            return op;
        }));
    };

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 font-mono text-sm">
            
            {/* ENTÊTE */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-5">
                <div>
                    <div className="flex items-center gap-2 text-xs text-indigo-400 mb-1">
                        <span className="w-2 h-2 rounded-full bg-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.5)]"></span>
                        <span>[IDENTITY & ACCESS MANAGEMENT / RBAC ENGINE]</span>
                    </div>
                    <h1 className="text-3xl font-black text-white tracking-tight">Gestion des habilitations (IAM)</h1>
                </div>
            </div>

            {/* BANNIÈRE DROITS */}
            <div className={`p-4 rounded-xl text-xs border ${
                isAdmin ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
            }`}>
                 <span className="font-bold uppercase">{isAdmin ? "Session Administrateur active :" : "Session Restreinte :"}</span> Connecté en tant que <strong>{user?.name}</strong>. 
                {isAdmin ? " Mode écriture activé. Vous pouvez provisionner, modifier et purger des clés d'accès." : " Consultation seule. Actions administratives verrouillées."}
            </div>

            {/* BLOCK PRINCIPAL GRID */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                
                {/* GAUCHE : TABLEAU DES OPÉRATEURS */}
                <div className="xl:col-span-2 bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg flex flex-col justify-between">
                    <div>
                        <div className="bg-slate-900/40 p-4 border-b border-slate-800">
                            <h3 className="text-xs font-bold uppercase text-slate-300">Registre actif des clés et privilèges</h3>
                        </div>
                        
                        <div className="overflow-x-auto">
                            <table className="w-full text-left text-xs border-collapse">
                                <thead>
                                    <tr className="border-b border-slate-800 text-slate-500 uppercase font-bold bg-slate-950/20">
                                        <th className="p-3.5">ID</th>
                                        <th className="p-3.5">Opérateur / Alias</th>
                                        <th className="p-3.5">Secret (Haché)</th>
                                        <th className="p-3.5">Niveau Habilitation</th>
                                        <th className="p-3.5">État</th>
                                        <th className="p-3.5 text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800/60">
                                    {operators.map((op) => (
                                        <tr key={op.id} className="hover:bg-slate-900/20 transition-all text-slate-300">
                                            <td className="p-3.5 font-bold text-indigo-400">{op.id}</td>
                                            <td className="p-3.5">
                                                <span className="text-white font-bold block">{op.name}</span>
                                                <span className="text-slate-500 text-[11px]">@{op.username}</span>
                                            </td>
                                            
                                            {/* SECRET MASQUÉ SYMBOLISANT LA SÉCURITÉ DE L'ALGORITHME */}
                                            <td className="p-3.5 text-slate-500 tracking-widest text-xs font-sans">
                                                {op.password}
                                            </td>
                                            
                                            <td className="p-3.5">
                                                {isAdmin && op.id !== 'OP-01' ? (
                                                    <select
                                                        value={op.level}
                                                        onChange={(e) => handleRoleChange(op.id, e.target.value)}
                                                        className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 focus:outline-none focus:border-indigo-500 font-mono text-xs cursor-pointer"
                                                    >
                                                        <option value="administrator">administrator (Full)</option>
                                                        <option value="analyst">analyst (Mitigation)</option>
                                                        <option value="reader">reader (Read-Only)</option>
                                                    </select>
                                                ) : (
                                                    <span className="text-slate-400 bg-slate-950 px-2 py-1 rounded border border-slate-900 text-[11px]">
                                                        {op.level}
                                                    </span>
                                                )}
                                            </td>

                                            <td className="p-3.5">
                                                <button
                                                    disabled={!isAdmin || op.id === 'OP-01'}
                                                    onClick={() => toggleStatus(op.id)}
                                                    className={`px-2 py-0.5 rounded text-[10px] font-black tracking-wide border ${
                                                        op.status === 'Active' 
                                                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                                                            : 'bg-red-500/10 text-red-400 border-red-500/20'
                                                    } ${isAdmin && op.id !== 'OP-01' ? 'cursor-pointer hover:bg-slate-800' : ''}`}
                                                >
                                                    {op.status}
                                                </button>
                                            </td>

                                            <td className="p-3.5 text-right">
                                                <button 
                                                    onClick={() => handleDeleteUser(op.id, op.name)}
                                                    disabled={!isAdmin || op.id === 'OP-01'}
                                                    className={`text-[11px] px-2.5 py-1 rounded border font-bold transition-all ${
                                                        !isAdmin || op.id === 'OP-01'
                                                            ? 'bg-slate-900 text-slate-600 border-slate-800/40 cursor-not-allowed' 
                                                            : 'bg-red-950/40 text-red-400 border-red-900/40 hover:bg-red-500 hover:text-white cursor-pointer'
                                                    }`}
                                                >
                                                    Révoquer
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                {/* DROITE : FORMULAIRE PROVISIONNING */}
                <div className="space-y-4">
                    <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 shadow-lg">
                        <div className="border-b border-slate-800 pb-2 mb-4">
                            <h3 className="text-xs font-bold uppercase text-slate-300">
                                Enrôler un nouvel opérateur
                            </h3>
                            <span className="text-[10px] text-indigo-400 block mt-0.5">(Scénario 1 : Mot de passe temporaire)</span>
                        </div>
                        <form onSubmit={handleCreateUser} className="space-y-4">
                            <div>
                                <label className="block text-[11px] text-slate-500 uppercase font-bold mb-1.5">Nom Complet :</label>
                                <input 
                                    type="text"
                                    value={newName}
                                    onChange={(e) => setNewName(e.target.value)}
                                    disabled={!isAdmin}
                                    placeholder="ex: Jack Bauer"
                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-indigo-500 disabled:opacity-50"
                                />
                            </div>
                            <div>
                                <label className="block text-[11px] text-slate-500 uppercase font-bold mb-1.5">Identifiant (Username) :</label>
                                <input 
                                    type="text"
                                    value={newUsername}
                                    onChange={(e) => setNewUsername(e.target.value)}
                                    disabled={!isAdmin}
                                    placeholder="ex: jbauer"
                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-indigo-500 disabled:opacity-50"
                                />
                            </div>
                            <div>
                                <label className="block text-[11px] text-slate-500 uppercase font-bold mb-1.5">Privilège initial :</label>
                                <select 
                                    value={newLevel}
                                    onChange={(e) => setNewLevel(e.target.value)}
                                    disabled={!isAdmin}
                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-indigo-500 disabled:opacity-50 cursor-pointer"
                                >
                                    <option value="reader">reader (Lecture seule L1)</option>
                                    <option value="analyst">analyst (Soutien & Mitigation L2)</option>
                                    <option value="administrator">administrator (Full Root L3)</option>
                                </select>
                            </div>
                            <button
                                type="submit"
                                disabled={!isAdmin}
                                className={`w-full font-bold text-xs py-2.5 rounded-lg border transition-all uppercase tracking-wider ${
                                    isAdmin 
                                        ? 'bg-emerald-600 border-emerald-500 text-white hover:bg-emerald-500 cursor-pointer shadow-md shadow-emerald-950/50' 
                                        : 'bg-slate-900 border-slate-800 text-slate-600 cursor-not-allowed'
                                    }`}
                            >
                                Générer les accès temporaires
                            </button>
                        </form>
                    </div>
                </div>

            </div>
        </div>
    );
}