import { useMemo, useState } from 'react';
import WorldAttackMap from '../components/WorldAttackMap';
import alertsData from '../mocks/alerts_mock.json';
import fallbackLogs from '../mocks/logs_mock.json';



const timeline = [
  { time: '00h', value: 12, label: 'Nominal' },
  { time: '04h', value: 45, label: 'Pic DDoS' },
  { time: '08h', value: 18, label: 'Sondes mixtes' },
  { time: '12h', value: 9, label: 'Calme' },
  { time: '16h', value: 15, label: 'Bruit auth' },
  { time: '20h', value: 22, label: 'Modere' },
];

const ingestionHealth = [
  { name: 'Collecteur Syslog', status: 'En ligne', color: 'emerald' },
  { name: 'Flux Filebeat', status: 'En ligne', color: 'emerald' },
  { name: 'Collecteur WAF', status: 'Retarde', color: 'amber' },
  { name: 'Telemetrie DNS', status: 'En ligne', color: 'emerald' },
];

const mitreCoverage = [
  { name: 'Acces initial', value: 38, color: 'bg-red-500' },
  { name: 'Acces aux identifiants', value: 24, color: 'bg-amber-500' },
  { name: 'Decouverte', value: 18, color: 'bg-cyan-500' },
  { name: 'Exfiltration', value: 11, color: 'bg-violet-500' },
  { name: 'Impact', value: 9, color: 'bg-rose-500' },
];

function Panel({ title, children, className = '' }) {
  return (
    <section className={`rounded-xl border border-slate-800/80 bg-slate-950/65 p-4 shadow-lg ${className}`}>
      <h3 className="mb-4 border-b border-slate-800/70 pb-3 text-xs font-black uppercase tracking-[0.24em] text-slate-200">
        {title}
      </h3>
      {children}
    </section>
  );
}

function Metric({ label, value, trend, tone = 'cyan' }) {
  const tones = {
    cyan: 'text-cyan-400 border-cyan-500/20 bg-cyan-500/10',
    red: 'text-red-400 border-red-500/20 bg-red-500/10',
    amber: 'text-amber-400 border-amber-500/20 bg-amber-500/10',
    emerald: 'text-emerald-400 border-emerald-500/20 bg-emerald-500/10',
    violet: 'text-violet-400 border-violet-500/20 bg-violet-500/10',
  };

  return (
    <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-4">
      <div className="flex items-start justify-between gap-3">
        <span className="text-[11px] font-bold uppercase tracking-[0.22em] text-slate-500">{label}</span>
        <span className={`rounded border px-2 py-0.5 text-[10px] font-black ${tones[tone]}`}>{trend}</span>
      </div>
      <div className={`mt-3 text-3xl font-black ${tones[tone].split(' ')[0]}`}>{value}</div>
    </div>
  );
}

export default function Dashboard({ user, logs = fallbackLogs }) {
  const [timePeriod, setTimePeriod] = useState('24h');

  const operationalLogs = logs.length ? logs : fallbackLogs;
  const criticalCount = alertsData.filter((alert) => alert.severity === 'CRITICAL').length;
  const openIncidents = alertsData.filter((alert) => alert.escalated).length;
  const resolvedToday = alertsData.filter((alert) => alert.status === 'TRAITÉ' || alert.status === 'TRAITÃ‰').length;
  const blockedIps = operationalLogs.filter(
    (log) => log.severity === 'CRITICAL' || log.payload?.toLowerCase().includes('blocked')
  ).length;
  const totalEvents = 142840;

  const threatSources = useMemo(() => {
    return operationalLogs
      .filter((log) => log.severity !== 'INFO')
      .slice(0, 5)
      .map((log) => ({
        ip: log.source,
        service: log.service,
        severity: log.severity,
        event: log.event,
      }));
  }, [operationalLogs]);

  const activeIncidents = alertsData
    .filter((alert) => alert.status !== 'TRAITÉ' && alert.status !== 'TRAITÃ‰' && alert.status !== 'FAUX_POSITIF')
    .slice(0, 4);

  const automatedActions = operationalLogs.slice(0, 4).map((log) => ({
    time: log.timestamp?.slice(11, 16) || '--:--',
    action: log.severity === 'INFO' ? 'Evenement de telemetrie valide' : `Confinement de ${log.source}`,
    detail: log.service,
  }));

  return (
    <div className="max-h-[85vh] space-y-5 overflow-y-auto pr-2 text-slate-200 animate-in fade-in duration-300">
      <div className="flex flex-col gap-4 rounded-xl border border-slate-800/80 bg-slate-950/70 p-4 shadow-lg lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2 text-[11px] font-bold uppercase tracking-[0.22em] text-slate-500">
            <span>SMART SIEM</span>
            <span className="text-slate-700">/</span>
            <span>Vue globale</span>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <h2 className="text-2xl font-black tracking-tight text-white">Tableau de bord des operations SOC</h2>
            <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-[10px] font-black uppercase tracking-wider text-amber-400">
              Niveau de menace : Eleve
            </span>
          </div>
          <p className="mt-2 font-sans text-sm text-slate-400">
            Operateur : <strong className="text-emerald-400">{user?.name || "Chloe O'Brian"}</strong>
            <span className="mx-2 text-slate-600">|</span>
            Environnement : Production
            <span className="mx-2 text-slate-600">|</span>
            Derniere synchro : 14:32:08
          </p>
        </div>

        <div className="flex w-fit rounded-lg border border-slate-800 bg-slate-900/80 p-1 text-xs">
          {['1h', '6h', '24h', '7d'].map((period) => (
            <button
              key={period}
              type="button"
              onClick={() => setTimePeriod(period)}
              className={`rounded-md px-3 py-2 font-black uppercase tracking-wider transition-all ${
                timePeriod === period
                  ? 'bg-cyan-500 text-slate-950'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-100'
              }`}
            >
              {period}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <Metric label="Evenements totaux" value={totalEvents.toLocaleString()} trend="+12%" tone="cyan" />
        <Metric label="IP bloquees" value={blockedIps} trend="+6" tone="violet" />
        <Metric label="Alertes critiques" value={criticalCount} trend="+28%" tone="red" />
        <Metric label="Incidents ouverts" value={openIncidents} trend="-5%" tone="amber" />
        <Metric label="Resolus aujourd'hui" value={resolvedToday} trend="+18%" tone="emerald" />
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <WorldAttackMap />
        </div>

        <div className="space-y-5">
          <Panel title="Sources de menace principales">
            <div className="space-y-3">
              {threatSources.map((source, index) => (
                <div key={`${source.ip}-${index}`} className="grid grid-cols-[auto_1fr_auto] items-center gap-3 text-xs">
                  <span className="text-slate-600">#{index + 1}</span>
                  <div className="min-w-0">
                    <div className="truncate font-bold text-slate-100">{source.ip}</div>
                    <div className="truncate font-sans text-[11px] text-slate-500">{source.event}</div>
                  </div>
                  <span
                    className={`rounded border px-2 py-1 text-[9px] font-black ${
                      source.severity === 'CRITICAL'
                        ? 'border-red-500/30 bg-red-500/10 text-red-400'
                        : 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                    }`}
                  >
                    {source.severity}
                  </span>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Incidents actifs">
            <div className="space-y-2">
              {activeIncidents.map((incident) => (
                <div key={incident.id} className="flex items-center justify-between gap-3 rounded-lg bg-slate-900/70 px-3 py-2 text-xs">
                  <div className="min-w-0">
                    <div className="font-black text-slate-100">{incident.id}</div>
                    <div className="truncate font-sans text-[11px] text-slate-500">{incident.service}</div>
                  </div>
                  <span className="rounded-full bg-red-500/10 px-2 py-1 text-[9px] font-black uppercase text-red-400">
                    {incident.severity}
                  </span>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>

      <Panel title="Chronologie des attaques">
        <div className="flex h-52 items-end justify-between gap-3 px-1 pb-2">
          {timeline.map((bar) => (
            <div key={bar.time} className="flex h-full flex-1 flex-col justify-end gap-2">
              <div className="flex flex-1 items-end rounded-t-lg border border-slate-800/70 bg-slate-900/50 px-1.5 pt-2">
                <div
                  className="w-full rounded-t-md bg-cyan-500 shadow-[0_0_18px_rgba(6,182,212,0.18)]"
                  style={{ height: `${Math.max((bar.value / 45) * 100, 8)}%` }}
                  title={`${bar.value}k - ${bar.label}`}
                />
              </div>
              <div className="text-center">
                <div className="text-[10px] font-bold text-slate-400">{bar.time}</div>
                <div className="hidden truncate font-sans text-[10px] text-slate-600 sm:block">{bar.label}</div>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <Panel title="Couverture MITRE">
          <div className="space-y-3">
            {mitreCoverage.map((item) => (
              <div key={item.name}>
                <div className="mb-1 flex justify-between text-xs">
                  <span className="font-sans text-slate-400">{item.name}</span>
                  <span className="font-bold text-slate-200">{item.value}%</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                  <div className={`h-full rounded-full ${item.color}`} style={{ width: `${item.value}%` }} />
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Sante de l'ingestion">
          <div className="space-y-3">
            {ingestionHealth.map((item) => (
              <div key={item.name} className="flex items-center justify-between rounded-lg bg-slate-900/60 px-3 py-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${item.color === 'emerald' ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                  <span className="font-sans text-slate-300">{item.name}</span>
                </div>
                <span className={item.color === 'emerald' ? 'font-bold text-emerald-400' : 'font-bold text-amber-400'}>
                  {item.status}
                </span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Actions automatisees recentes">
          <div className="space-y-3">
            {automatedActions.map((item, index) => (
              <div key={`${item.time}-${index}`} className="grid grid-cols-[44px_1fr] gap-3 text-xs">
                <span className="font-bold text-slate-500">{item.time}</span>
                <div>
                  <div className="font-bold text-slate-100">{item.action}</div>
                  <div className="font-sans text-[11px] text-slate-500">{item.detail}</div>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
