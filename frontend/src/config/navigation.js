/**
 * Définition centrale de la navigation et des permissions RBAC.
 * Source unique de vérité utilisée à la fois par la Sidebar (affichage du
 * menu) et par App.jsx (garde-fou empêchant l'accès à une vue non autorisée
 * pour le rôle courant, même si activeView est modifié par un autre biais).
 *
 * Principe d'exclusivité : chaque rôle a SA propre interface, sans
 * recouvrement avec celle d'un autre rôle. L'administrateur est le seul
 * à cumuler l'accès complet à l'ensemble des interfaces (priorité totale).
 *
 *   reader (Auditeur)        → Vue Auditeur (conformité) — exclusif
 *   analyst (Analyste)       → Dashboard technique + toolkit opérationnel — exclusif
 *   administrator (RSSI+Admin) → Vue RSSI + administration système — exclusif
 *   administrator hérite en plus de TOUTES les interfaces reader/analyst.
 */

const READER_EXCLUSIVE = ['compliance'];
const ANALYST_EXCLUSIVE = ['dashboard', 'logs', 'alerts', 'playbooks', 'ueba', 'crisis', 'rules', 'reports'];
const ADMIN_EXCLUSIVE = ['rssi', 'roles', 'audit', 'sysconfig'];

/** Calcule les rôles autorisés pour un identifiant de vue donné selon le
 *  principe d'exclusivité ci-dessus (l'administrateur hérite toujours de tout). */
function allowedRolesFor(viewId) {
  const roles = [];
  if (READER_EXCLUSIVE.includes(viewId)) roles.push('reader');
  if (ANALYST_EXCLUSIVE.includes(viewId)) roles.push('analyst');
  if (ADMIN_EXCLUSIVE.includes(viewId)) roles.push('administrator');
  if (!roles.includes('administrator')) roles.push('administrator'); // priorité d'accès complet
  return roles;
}

export const MENU_SECTIONS = [
  {
    title: 'Vue d\'ensemble',
    items: [
      { id: 'dashboard', name: 'Dashboard analyste', allowedRoles: allowedRolesFor('dashboard') },
      { id: 'rssi', name: 'Vue RSSI', allowedRoles: allowedRolesFor('rssi') },
    ],
  },
  {
    title: 'Investigation',
    items: [
      { id: 'logs', name: 'Explorateur de logs', allowedRoles: allowedRolesFor('logs') },
      { id: 'alerts', name: 'Triage des alertes', allowedRoles: allowedRolesFor('alerts') },
      { id: 'playbooks', name: 'Playbooks SOAR', allowedRoles: allowedRolesFor('playbooks') },
      { id: 'ueba', name: 'Analyse comportementale', allowedRoles: allowedRolesFor('ueba') },
    ],
  },
  {
    title: 'Reporting & conformité',
    items: [
      { id: 'crisis', name: 'Salle de crise', allowedRoles: allowedRolesFor('crisis') },
      { id: 'compliance', name: 'Vue auditeur', allowedRoles: allowedRolesFor('compliance') },
      { id: 'reports', name: 'Rapports', allowedRoles: allowedRolesFor('reports') },
    ],
  },
  {
    title: 'Administration',
    items: [
      { id: 'roles', name: 'Utilisateurs & rôles', allowedRoles: allowedRolesFor('roles') },
      { id: 'rules', name: 'Règles de corrélation', allowedRoles: allowedRolesFor('rules') },
      { id: 'audit', name: 'Journal d\'audit', allowedRoles: allowedRolesFor('audit') },
      { id: 'sysconfig', name: 'Configuration système', allowedRoles: allowedRolesFor('sysconfig') },
    ],
  },
];

const ALL_ITEMS = MENU_SECTIONS.flatMap((section) => section.items);

/**
 * Interface d'atterrissage exclusive par rôle à la connexion :
 *   - reader        → Vue auditeur (conformité) — leur seule et unique interface
 *   - analyst        → Dashboard technique — leur poste de travail principal
 *   - administrator → Vue RSSI — synthèse exécutive, point d'entrée vers l'accès complet
 */
export function getHomeViewForRole(role) {
  if (role === 'reader') return 'compliance';
  if (role === 'administrator') return 'rssi';
  return 'dashboard';
}

/** Vérifie si un rôle donné a le droit d'accéder à une vue donnée. */
export function isViewAllowedForRole(viewId, role) {
  const item = ALL_ITEMS.find((i) => i.id === viewId);
  if (!item) return false;
  return item.allowedRoles.includes(role);
}
