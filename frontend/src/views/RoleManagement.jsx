import { useState, useEffect } from 'react';
import { Trash2 } from 'lucide-react';
import { getUsers, createUser, deleteUser, updateUserRole, updateUserActive } from '../services/api';
import { PageHeader, Card, Badge, Button, LoadingState, ErrorBanner, EmptyState, ReadOnlyNotice } from '../components/ui/primitives';

/** Génère un mot de passe temporaire fort, réellement envoyé au backend à la création. */
const generateTempPassword = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%';
    let pwd = '';
    for (let i = 0; i < 16; i++) pwd += chars[Math.floor(Math.random() * chars.length)];
    return pwd;
};

const inputStyle = { background: 'var(--surface-1)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' };

/** Gestion des utilisateurs et des rôles RBAC — réel, via l'API backend. */
export default function RoleManagement({ user, onRefresh }) {
    const [operators, setOperators] = useState([]);
    const [status, setStatus] = useState('loading');
    const [newName, setNewName] = useState('');
    const [newLevel, setNewLevel] = useState('reader');

    const isAdmin = user?.role === 'administrator';

    const load = () => {
        setStatus((s) => (s === 'ready' ? 'ready' : 'loading'));
        getUsers()
            .then((users) => {
                setOperators(users.map((u) => ({ id: u.id, username: u.username, role: u.role, isActive: u.is_active })));
                setStatus('ready');
            })
            .catch(() => setStatus('error'));
    };

    useEffect(() => { load(); }, []);

    const handleCreateUser = async (e) => {
        e.preventDefault();
        if (!isAdmin || !newName) return;
        const tempPassword = generateTempPassword();
        try {
            await createUser({ username: newName.toLowerCase().trim(), password: tempPassword, role: newLevel });
            setNewName('');
            load();
            onRefresh?.();
            alert(`Compte créé pour ${newName}.\n\nMot de passe temporaire (à transmettre de façon sécurisée) :\n${tempPassword}\n\nCe mot de passe a été haché côté backend et ne sera plus affiché.`);
        } catch (err) {
            alert(`Échec de la création : ${err.message}`);
        }
    };

    const handleRoleChange = async (operatorId, newRoleLevel) => {
        if (!isAdmin) return;
        try {
            await updateUserRole(operatorId, newRoleLevel);
            setOperators((prev) => prev.map((op) => (op.id === operatorId ? { ...op, role: newRoleLevel } : op)));
        } catch (err) {
            alert(`Échec de la modification du rôle : ${err.message}`);
        }
    };

    // Le backend fait une désactivation logique (is_active=false), pas une
    // suppression réelle — le compte est conservé pour la traçabilité d'audit.
    // Le retirer de la liste locale serait trompeur : il réapparaîtrait au
    // prochain chargement (toujours présent, juste inactif).
    const handleDeleteUser = async (operatorId, username) => {
        if (!isAdmin) return;
        if (!confirm(`Désactiver le compte ${username} ? (le compte est conservé pour l'audit, pas supprimé)`)) return;
        try {
            await deleteUser(operatorId);
            setOperators((prev) => prev.map((op) => (op.id === operatorId ? { ...op, isActive: false } : op)));
        } catch (err) {
            alert(`Échec de la désactivation : ${err.message}`);
        }
    };

    const toggleStatus = async (operatorId, currentActive) => {
        if (!isAdmin) return;
        try {
            await updateUserActive(operatorId, !currentActive);
            setOperators((prev) => prev.map((op) => (op.id === operatorId ? { ...op, isActive: !currentActive } : op)));
        } catch (err) {
            alert(`Échec du changement de statut : ${err.message}`);
        }
    };

    return (
        <div className="space-y-5">
            <PageHeader eyebrow="Administration" title="Utilisateurs & rôles" description="Gestion des accès RBAC." />

            {!isAdmin && <ReadOnlyNotice role={user?.role} action="gérer les utilisateurs" />}

            {status === 'loading' && <LoadingState label="Chargement des utilisateurs..." />}
            {status === 'error' && <ErrorBanner description="Impossible de charger la liste des utilisateurs." />}

            {status === 'ready' && (
                <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
                    <Card padded={false} className="xl:col-span-2">
                        <p className="border-b p-4 text-xs font-medium uppercase tracking-wide" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                            {operators.length} utilisateur(s)
                        </p>
                        {operators.length === 0 ? (
                            <EmptyState title="Aucun utilisateur" />
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="w-full text-left text-sm">
                                    <thead>
                                        <tr className="border-b text-xs font-medium uppercase tracking-wide" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
                                            <th className="p-3.5">Utilisateur</th>
                                            <th className="p-3.5">Rôle</th>
                                            <th className="p-3.5">État</th>
                                            <th className="p-3.5 text-right">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
                                        {operators.map((op) => (
                                            <tr key={op.id}>
                                                <td className="p-3.5 font-medium" style={{ color: 'var(--text-primary)' }}>@{op.username}</td>
                                                <td className="p-3.5">
                                                    {isAdmin ? (
                                                        <select value={op.role} onChange={(e) => handleRoleChange(op.id, e.target.value)}
                                                            className="rounded-md border px-2 py-1 text-xs" style={inputStyle}>
                                                            <option value="administrator">administrator</option>
                                                            <option value="analyst">analyst</option>
                                                            <option value="reader">reader</option>
                                                        </select>
                                                    ) : (
                                                        <Badge tone="NEUTRAL">{op.role}</Badge>
                                                    )}
                                                </td>
                                                <td className="p-3.5">
                                                    <button onClick={() => toggleStatus(op.id, op.isActive)} disabled={!isAdmin}>
                                                        <Badge tone={op.isActive ? 'SUCCESS' : 'CRITICAL'}>{op.isActive ? 'Actif' : 'Suspendu'}</Badge>
                                                    </button>
                                                </td>
                                                <td className="p-3.5 text-right">
                                                    <button
                                                        onClick={() => handleDeleteUser(op.id, op.username)}
                                                        disabled={!isAdmin}
                                                        title="Désactiver le compte (conservé pour l'audit, non supprimé)"
                                                        className="rounded-md p-1.5 transition-colors disabled:opacity-30"
                                                        style={{ color: '#f87171' }}
                                                    >
                                                        <Trash2 size={15} />
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </Card>

                    <Card>
                        <p className="mb-4 text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Créer un utilisateur</p>
                        <form onSubmit={handleCreateUser} className="space-y-3.5">
                            <div>
                                <label className="mb-1.5 block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>Nom d'utilisateur</label>
                                <input
                                    type="text" value={newName} onChange={(e) => setNewName(e.target.value)}
                                    disabled={!isAdmin} placeholder="ex: jbauer"
                                    className="w-full rounded-lg border px-3 py-2 text-sm outline-none focus:border-[var(--accent)] disabled:opacity-50"
                                    style={inputStyle}
                                />
                            </div>
                            <div>
                                <label className="mb-1.5 block text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>Rôle initial</label>
                                <select value={newLevel} onChange={(e) => setNewLevel(e.target.value)} disabled={!isAdmin}
                                    className="w-full rounded-lg border px-3 py-2 text-sm disabled:opacity-50" style={inputStyle}>
                                    <option value="reader">reader</option>
                                    <option value="analyst">analyst</option>
                                    <option value="administrator">administrator</option>
                                </select>
                            </div>
                            <Button type="submit" variant="primary" disabled={!isAdmin} className="w-full">Créer le compte</Button>
                        </form>
                    </Card>
                </div>
            )}
        </div>
    );
}
