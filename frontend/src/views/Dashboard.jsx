import { useState, useEffect, useCallback } from 'react';
import { AlertTriangle, ShieldAlert, CheckCircle2, Activity } from 'lucide-react';
import WorldAttackMap from '../components/WorldAttackMap';
import { getDashboardData } from '../services/api';
import { PageHeader, StatCard, Card, Badge, LoadingState, ErrorBanner, EmptyState } from '../components/ui/primitives';

/** Fallback client : regroupe les logs chargés par heure si l'agrégation serveur est indisponible. */
function computeHourlyVolume(logs) {
  const buckets = Array.from({ length: 24 }, () => 0);
  for (const log of logs) {
    if (!log.timestamp) continue;
    const hour = new Date(log.timestamp.replace(' ', 'T')).getHours();
    if (!Number.isNaN(hour)) buckets[hour] += 1;
  }
  return buckets;
}

export default function Dashboard({ user, logs = [], dataStatus = 'ready', dataError = null }) {
  const [serverData, setServerData] = useState(null);
  const [serverStatus, setServerStatus] = useState('loading');

  const loadServerDashboard = useCallback(() => {
    getDashboardData()
      .then((data) => { setServerData(data); setServerStatus('ready'); })
      .catch(() => setServerStatus('error'));
  }, []);

  useEffect(() => {
    loadServerDashboard();
    const interval = setInterval(loadServerDashboard, 30000);
    return () => clearInterval(interval);
  }, [loadServerDashboard]);

  const criticalCount = logs.filter((a) => a.severity === 'CRITICAL').length;
  const warningCount = logs.filter((a) => a.severity === 'WARNING' || a.severity === 'HIGH').length;
  const openIncidents = logs.filter((a) => a.escalated === true).length;
  const resolvedCount = logs.filter((a) => a.status === 'TRAITÉ').length;

  const hourlyFromServer = serverData?.logs_per_hour?.length
    ? serverData.logs_per_hour.map((b) => ({ hour: new Date(b.hour).getHours(), count: b.count }))
    : null;
  const hourlyVolume = hourlyFromServer
    ? Array.from({ length: 24 }, (_, h) => hourlyFromServer.find((b) => b.hour === h)?.count ?? 0)
    : computeHourlyVolume(logs);
  const maxHourly = Math.max(1, ...hourlyVolume);

  const topAlerts = serverData?.top_alerts?.length
    ? serverData.top_alerts.map((a) => ({
        id: `ALT-${a.id}`, severity: a.severity, event: a.description || a.rule_name,
        timestamp: (a.detected_at || '').replace('T', ' ').slice(0, 19),
      }))
    : logs.filter((l) => ['CRITICAL', 'WARNING', 'HIGH'].includes(l.severity))
        .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || '')).slice(0, 5);

  const sourceMap = serverData?.source_map?.length
    ? serverData.source_map.map((s) => ({ ip: s.source_ip, count: s.count }))
    : null;

  if (dataStatus === 'loading') return <LoadingState label="Chargement des données..." />;
  if (dataStatus === 'error') return <ErrorBanner description={dataError || 'Impossible de contacter le backend.'} />;

  const posture = criticalCount > 0 ? 'CRITICAL' : warningCount > 0 ? 'WARNING' : 'SUCCESS';
  const postureLabel = criticalCount > 0 ? 'Critique' : warningCount > 0 ? 'Vigilance' : 'Nominal';

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Vue analyste"
        title="Centre d'opérations"
        description={`Connecté en tant que ${user?.name || user?.user} · ${serverStatus === 'ready' ? 'agrégation temps réel active' : 'chargement de l\'agrégation serveur...'}`}
        actions={<Badge tone={posture}>Posture {postureLabel}</Badge>}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Événements indexés" value={(serverData?.total_logs ?? logs.length).toLocaleString()} tone="INFO" hint="Elasticsearch" icon={Activity} />
        <StatCard label="Alertes critiques" value={criticalCount} tone="CRITICAL" hint={criticalCount > 0 ? 'Action requise' : 'Aucune'} />
        <StatCard label="Alertes actives" value={serverData?.total_alerts_active ?? openIncidents} tone="WARNING" hint="Non résolues" />
        <StatCard label="Résolues" value={resolvedCount} tone="SUCCESS" hint="Remédiation appliquée" />
      </div>

      <WorldAttackMap logs={logs} sourceMap={sourceMap} />

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Volume par heure</p>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                {hourlyFromServer ? 'Agrégation Elasticsearch (24h)' : 'Calculé depuis les logs chargés'}
              </p>
            </div>
          </div>
          {logs.length === 0 && !hourlyFromServer ? (
            <EmptyState title="Aucune donnée disponible" />
          ) : (
            <div className="flex items-end justify-between gap-1 px-1" style={{ height: 140 }}>
              {hourlyVolume.map((value, hour) => (
                <div key={hour} className="group flex flex-1 flex-col items-center gap-1.5">
                  <span className="text-[10px] font-medium opacity-0 transition-opacity group-hover:opacity-100" style={{ color: 'var(--text-secondary)' }}>{value}</span>
                  <div className="w-full rounded-t" style={{ height: `${Math.max(3, (value / maxHourly) * 100)}px`, background: value > 0 ? 'var(--accent)' : 'var(--surface-3)' }} />
                  <span className="text-[9px]" style={{ color: 'var(--text-muted)' }}>{hour}</span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card>
          <p className="mb-4 text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Répartition des menaces</p>
          <div className="space-y-3">
            {[
              { label: 'Critique', value: criticalCount, tone: 'CRITICAL', Icon: ShieldAlert },
              { label: 'Avertissement', value: warningCount, tone: 'WARNING', Icon: AlertTriangle },
              { label: 'Résolues', value: resolvedCount, tone: 'SUCCESS', Icon: CheckCircle2 },
            ].map(({ label, value, tone, Icon }) => (
              <div key={label} className="flex items-center justify-between rounded-lg border px-3 py-2.5" style={{ borderColor: 'var(--border-subtle)' }}>
                <div className="flex items-center gap-2.5">
                  <Icon size={16} strokeWidth={1.75} style={{ color: 'var(--text-muted)' }} />
                  <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{label}</span>
                </div>
                <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{value}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card>
        <p className="mb-4 text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Alertes prioritaires</p>
        {topAlerts.length === 0 ? (
          <EmptyState title="Aucune alerte active" description="Le périmètre surveillé est actuellement stable." />
        ) : (
          <div className="space-y-2">
            {topAlerts.map((a) => (
              <div key={a.id} className="flex items-center justify-between gap-3 rounded-lg border px-3.5 py-2.5" style={{ borderColor: 'var(--border-subtle)' }}>
                <div className="flex min-w-0 items-center gap-3">
                  <Badge tone={a.severity}>{a.severity}</Badge>
                  <span className="truncate text-sm" style={{ color: 'var(--text-secondary)' }}>{a.event}</span>
                </div>
                <span className="shrink-0 text-xs" style={{ color: 'var(--text-muted)' }}>{a.timestamp}</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
