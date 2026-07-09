import { Globe2 } from 'lucide-react';
import { Card, Badge, EmptyState } from './ui/primitives';

/**
 * Classement des IP sources les plus actives, calculé depuis de vraies données.
 * Priorité à l'agrégation serveur (`sourceMap`, Elasticsearch date_histogram sur 24h) ;
 * fallback sur un comptage client à partir des logs chargés si le serveur est indisponible.
 * Aucune géolocalisation n'est effectuée : le backend ne fournit pas de service de
 * résolution IP → pays/ville, donc aucune carte géographique n'est affichée pour
 * éviter d'inventer des données.
 */
export default function WorldAttackMap({ logs = [], sourceMap = null }) {
  let topIps;

  if (sourceMap) {
    const total = sourceMap.reduce((s, c) => s + c.count, 0) || 1;
    topIps = sourceMap
      .map((s) => ({ ip: s.ip, count: s.count, critical: 0, warning: 0, percentage: Math.round((s.count / total) * 100) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  } else {
    const counts = {};
    for (const log of logs) {
      const ip = log.source;
      if (!ip || ip === 'N/A') continue;
      if (!counts[ip]) counts[ip] = { count: 0, critical: 0, warning: 0 };
      counts[ip].count += 1;
      if (log.severity === 'CRITICAL') counts[ip].critical += 1;
      else if (log.severity === 'WARNING' || log.severity === 'HIGH') counts[ip].warning += 1;
    }
    const total = Object.values(counts).reduce((s, c) => s + c.count, 0) || 1;
    topIps = Object.entries(counts)
      .map(([ip, c]) => ({ ip, ...c, percentage: Math.round((c.count / total) * 100) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }

  return (
    <Card>
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <Globe2 size={17} strokeWidth={1.75} style={{ color: 'var(--text-muted)' }} />
          <div>
            <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Adresses IP sources les plus actives</p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              {sourceMap ? 'Agrégation Elasticsearch (dernières 24h)' : 'Comptage local depuis les logs chargés'}
            </p>
          </div>
        </div>
        <Badge tone="INFO">
          {sourceMap ? `${sourceMap.reduce((s, c) => s + c.count, 0)} logs` : `${logs.length} logs`}
        </Badge>
      </div>

      {topIps.length === 0 ? (
        <EmptyState title="Aucune donnée disponible" />
      ) : (
        <div className="space-y-2.5">
          {topIps.map((zone, index) => {
            const status = zone.critical > 0 ? 'CRITICAL' : zone.warning > 0 ? 'WARNING' : 'INFO';
            const barColor = status === 'CRITICAL' ? 'var(--sev-critical)' : status === 'WARNING' ? 'var(--sev-warning)' : 'var(--accent)';
            return (
              <div key={zone.ip} className="rounded-lg border px-3.5 py-3" style={{ borderColor: 'var(--border-subtle)' }}>
                <div className="mb-2 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span style={{ color: 'var(--text-muted)' }}>#{index + 1}</span>
                    <span className="select-all font-medium" style={{ color: 'var(--text-primary)' }}>{zone.ip}</span>
                  </div>
                  <span style={{ color: 'var(--text-secondary)' }}>{zone.count} logs · {zone.percentage}%</span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full" style={{ background: 'var(--surface-3)' }}>
                  <div className="h-full rounded-full transition-all duration-500" style={{ width: `${zone.percentage}%`, background: barColor }} />
                </div>
              </div>
            );
          })}
        </div>
      )}

      <p className="mt-4 border-t pt-3 text-[11px]" style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
        Aucune géolocalisation n'est effectuée (non disponible côté backend).
      </p>
    </Card>
  );
}
