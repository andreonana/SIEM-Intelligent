import { useMemo, useState } from 'react';

const severities = ['ALL', 'CRITICAL', 'WARNING', 'INFO'];
const statuses = ['ALL', 'NON_TRAITE', 'EN_COURS', 'TRAITE', 'FAUX_POSITIF', 'ESCALADE'];
const timeRanges = ['15m', '1h', '24h', '7d'];

const savedHunts = [
  { name: 'Force brute SSH', query: 'ssh brute force', severity: 'CRITICAL', service: 'ALL' },
  { name: 'Injection SQL', query: 'sql injection', severity: 'CRITICAL', service: 'Nginx-WAF' },
  { name: 'DNS suspect', query: 'dns crypto', severity: 'WARNING', service: 'Core-DNS' },
  { name: 'Balayage de ports', query: 'port scanning', severity: 'WARNING', service: 'Internal-Firewall' },
];

const severityLabels = {
  ALL: 'TOUS',
  CRITICAL: 'CRITIQUE',
  WARNING: 'AVERTISSEMENT',
  INFO: 'INFO',
};

const statusLabels = {
  ALL: 'TOUS',
  NON_TRAITE: 'NON TRAITE',
  EN_COURS: 'EN COURS',
  TRAITE: 'TRAITE',
  FAUX_POSITIF: 'FAUX POSITIF',
  ESCALADE: 'ESCALADE',
};

function normalizeStatus(log) {
  if (log.escalated) return 'ESCALADE';
  if (log.status === 'TRAITE' || log.status === 'TRAITÉ' || log.status === 'TRAITÃ‰') return 'TRAITE';
  if (log.status === 'FAUX_POSITIF') return 'FAUX_POSITIF';
  if (log.status === 'EN_COURS') return 'EN_COURS';
  return 'NON_TRAITE';
}

function getSeverityClass(severity) {
  if (severity === 'CRITICAL') return 'border-red-500/30 bg-red-500/10 text-red-400';
  if (severity === 'WARNING') return 'border-amber-500/30 bg-amber-500/10 text-amber-400';
  return 'border-blue-500/30 bg-blue-500/10 text-blue-400';
}

function getStatusClass(status) {
  if (status === 'ESCALADE') return 'border-red-500/30 bg-red-500/10 text-red-400';
  if (status === 'EN_COURS') return 'border-amber-500/30 bg-amber-500/10 text-amber-400';
  if (status === 'TRAITE') return 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400';
  if (status === 'FAUX_POSITIF') return 'border-slate-600 bg-slate-800 text-slate-400';
  return 'border-slate-700 bg-slate-950/70 text-slate-400';
}

function matchesQuery(log, query) {
  const terms = query
    .toLowerCase()
    .split(/\s+/)
    .map((term) => term.trim())
    .filter(Boolean);

  if (terms.length === 0) return true;

  const haystack = [
    log.id,
    log.timestamp,
    log.source,
    log.destination,
    log.service,
    log.event,
    log.payload,
    log.severity,
    normalizeStatus(log),
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  return terms.every((term) => haystack.includes(term));
}

function Metric({ label, value, tone = 'text-slate-100' }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2">
      <span className="block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">{label}</span>
      <strong className={`mt-1 block text-lg ${tone}`}>{value}</strong>
    </div>
  );
}

export default function LogExplorer({ user, logs = [] }) {
  const [query, setQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedStatus, setSelectedStatus] = useState('ALL');
  const [selectedService, setSelectedService] = useState('ALL');
  const [timeRange, setTimeRange] = useState('24h');
  const [viewMode, setViewMode] = useState('table');
  const [selectedLog, setSelectedLog] = useState(logs[0] || null);
  const [showMoreFilters, setShowMoreFilters] = useState(false);

  const services = useMemo(() => {
    return ['ALL', ...Array.from(new Set(logs.map((log) => log.service).filter(Boolean)))];
  }, [logs]);

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const status = normalizeStatus(log);
      const matchesSeverity = selectedSeverity === 'ALL' || log.severity === selectedSeverity;
      const matchesStatus = selectedStatus === 'ALL' || status === selectedStatus;
      const matchesService = selectedService === 'ALL' || log.service === selectedService;

      return matchesQuery(log, query) && matchesSeverity && matchesStatus && matchesService;
    });
  }, [logs, query, selectedSeverity, selectedStatus, selectedService]);

  const selectedIndex = selectedLog ? filteredLogs.findIndex((log) => log.id === selectedLog.id) : -1;
  const previousLog = selectedIndex > 0 ? filteredLogs[selectedIndex - 1] : null;
  const nextLog = selectedIndex >= 0 && selectedIndex < filteredLogs.length - 1 ? filteredLogs[selectedIndex + 1] : null;

  const summary = useMemo(() => {
    const uniqueSources = new Set(filteredLogs.map((log) => log.source)).size;
    return {
      results: filteredLogs.length,
      critical: filteredLogs.filter((log) => log.severity === 'CRITICAL').length,
      warning: filteredLogs.filter((log) => log.severity === 'WARNING').length,
      info: filteredLogs.filter((log) => log.severity === 'INFO').length,
      uniqueSources,
    };
  }, [filteredLogs]);

  const applySavedHunt = (hunt) => {
    setQuery(hunt.query);
    setSelectedSeverity(hunt.severity);
    setSelectedService(hunt.service);
    setSelectedStatus('ALL');
    setSelectedLog(null);
  };

  const clearFilters = () => {
    setQuery('');
    setSelectedSeverity('ALL');
    setSelectedStatus('ALL');
    setSelectedService('ALL');
    setTimeRange('24h');
    setSelectedLog(null);
  };

  const pivotTo = (field, value) => {
    setQuery(String(value || ''));
    if (field === 'service') setSelectedService(value);
    if (field === 'severity') setSelectedSeverity(value);
  };

  return (
    <div className="max-h-[85vh] space-y-5 overflow-y-auto pr-2 text-slate-200 animate-in fade-in duration-300">
      <div className="flex flex-col gap-4 border-b border-slate-800/70 pb-5 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <span className="text-xs font-bold uppercase tracking-[0.3em] text-cyan-400">
            Poste forensic / Chasse aux menaces
          </span>
          <h1 className="mt-2 text-3xl font-black text-white">Explorateur de logs</h1>
          <p className="mt-2 font-sans text-sm text-slate-400">
            Operateur : <strong className="text-cyan-400">{user?.name || "Chloe O'Brian"}</strong>
          </p>
        </div>

        <div className="flex flex-wrap gap-2 text-xs">
          <button
            type="button"
            className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 font-bold text-slate-300 hover:border-cyan-500/40 hover:text-cyan-400"
          >
            Exporter les preuves
          </button>
          <span className="rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 font-bold text-emerald-400">
            Flux en direct
          </span>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800/80 bg-slate-950/70 p-4 shadow-lg">
        <div className="flex flex-col gap-3 xl:flex-row">
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Rechercher dans les logs : source:185.220.101.4, force brute ssh, bloque, dns..."
            className="min-h-11 flex-1 rounded-lg border border-slate-800 bg-slate-900/80 px-4 py-2.5 font-mono text-sm text-white outline-none transition-colors placeholder:text-slate-600 hover:border-slate-700 focus:border-cyan-500"
          />

          <div className="flex rounded-lg border border-slate-800 bg-slate-900/80 p-1 text-xs">
            {timeRanges.map((range) => (
              <button
                key={range}
                type="button"
                onClick={() => setTimeRange(range)}
                className={`rounded-md px-3 py-2 font-black uppercase tracking-wider transition-all ${
                  timeRange === range ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-100'
                }`}
              >
                {range}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          {[
            { label: 'critique', query: 'critical' },
            { label: 'avertissement', query: 'warning' },
            { label: 'auth', query: 'auth' },
            { label: 'waf', query: 'waf' },
            { label: 'dns', query: 'dns' },
            { label: 'bloque', query: 'blocked' },
          ].map((chip) => (
            <button
              key={chip.label}
              type="button"
              onClick={() => setQuery(chip.query)}
              className="rounded-full border border-slate-800 bg-slate-900 px-3 py-1 text-xs font-bold uppercase tracking-wider text-slate-400 transition-colors hover:border-cyan-500/40 hover:text-cyan-400"
            >
              {chip.label}
            </button>
          ))}

          <div className="mx-1 hidden h-6 w-px bg-slate-800 sm:block" />

          {severities.map((severity) => (
            <button
              key={severity}
              type="button"
              onClick={() => setSelectedSeverity(severity)}
              className={`rounded-full border px-3 py-1 text-xs font-black uppercase tracking-wider transition-colors ${
                selectedSeverity === severity
                  ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-400'
                  : 'border-slate-800 bg-slate-900 px-3 py-1 text-slate-400 hover:border-slate-700 hover:text-slate-100'
              }`}
            >
              {severityLabels[severity]}
            </button>
          ))}

          <button
            type="button"
            onClick={() => setShowMoreFilters((current) => !current)}
            className={`rounded-full border px-3 py-1 text-xs font-black uppercase tracking-wider transition-colors ${
              showMoreFilters
                ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-400'
                : 'border-slate-800 bg-slate-900 text-slate-400 hover:border-slate-700 hover:text-slate-100'
            }`}
          >
            Plus de filtres
          </button>

          <button
            type="button"
            onClick={clearFilters}
            className="rounded-full border border-slate-800 bg-slate-900 px-3 py-1 text-xs font-black uppercase tracking-wider text-slate-500 transition-colors hover:border-red-500/30 hover:text-red-400"
          >
            Reinitialiser
          </button>
        </div>

        {showMoreFilters && (
          <div className="mt-4 grid gap-3 rounded-xl border border-slate-800 bg-slate-900/50 p-3 md:grid-cols-3">
            <label className="space-y-1.5">
              <span className="block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Statut</span>
              <select
                value={selectedStatus}
                onChange={(event) => setSelectedStatus(event.target.value)}
                className="w-full rounded-lg border border-slate-800 bg-slate-950/80 p-2.5 text-xs font-bold text-slate-300 outline-none focus:border-cyan-500"
              >
                {statuses.map((status) => (
                  <option key={status} value={status}>
                    {statusLabels[status]}
                  </option>
                ))}
              </select>
            </label>

            <label className="space-y-1.5">
              <span className="block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Service</span>
              <select
                value={selectedService}
                onChange={(event) => setSelectedService(event.target.value)}
                className="w-full rounded-lg border border-slate-800 bg-slate-950/80 p-2.5 text-xs font-bold text-slate-300 outline-none focus:border-cyan-500"
              >
                {services.map((service) => (
                  <option key={service} value={service}>
                    {service}
                  </option>
                ))}
              </select>
            </label>

            <label className="space-y-1.5">
              <span className="block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Requetes enregistrees</span>
              <select
                value=""
                onChange={(event) => {
                  const hunt = savedHunts.find((item) => item.name === event.target.value);
                  if (hunt) applySavedHunt(hunt);
                }}
                className="w-full rounded-lg border border-slate-800 bg-slate-950/80 p-2.5 text-xs font-bold text-slate-300 outline-none focus:border-cyan-500"
              >
                <option value="">Choisir une requete...</option>
                {savedHunts.map((hunt) => (
                  <option key={hunt.name} value={hunt.name}>
                    {hunt.name}
                  </option>
                ))}
              </select>
            </label>
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Metric label="Resultats" value={summary.results} tone="text-white" />
        <Metric label="Critiques" value={summary.critical} tone="text-red-400" />
        <Metric label="Avertissements" value={summary.warning} tone="text-amber-400" />
        <Metric label="Info" value={summary.info} tone="text-blue-400" />
        <Metric label="Sources uniques" value={summary.uniqueSources} tone="text-cyan-400" />
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <main className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-950/65">
          <div className="flex flex-col gap-3 border-b border-slate-800 bg-slate-950/80 p-4 md:flex-row md:items-center md:justify-between">
            <div>
              <h2 className="text-xs font-black uppercase tracking-[0.24em] text-slate-200">Resultats des logs</h2>
              <p className="mt-1 font-sans text-xs text-slate-500">Periode : {timeRange} / {summary.results} evenements correspondants</p>
            </div>

            <div className="flex rounded-lg border border-slate-800 bg-slate-900 p-1 text-xs">
              {[
                { id: 'table', label: 'tableau' },
                { id: 'timeline', label: 'chronologie' },
              ].map((mode) => (
                <button
                  key={mode.id}
                  type="button"
                  onClick={() => setViewMode(mode.id)}
                  className={`rounded-md px-3 py-1.5 font-black uppercase ${
                    viewMode === mode.id ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                  }`}
                >
                  {mode.label}
                </button>
              ))}
            </div>
          </div>

          {viewMode === 'table' ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[860px] border-collapse text-left">
                <thead>
                  <tr className="border-b border-slate-800 text-[10px] uppercase tracking-[0.22em] text-slate-500">
                    <th className="p-3">Heure</th>
                    <th className="p-3">Gravite</th>
                    <th className="p-3">Source</th>
                    <th className="p-3">Destination</th>
                    <th className="p-3">Service</th>
                    <th className="p-3">Evenement</th>
                    <th className="p-3 text-right">Statut</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-xs">
                  {filteredLogs.length === 0 ? (
                    <tr>
                      <td colSpan="7" className="p-8 text-center text-slate-500">Aucun evenement brut trouve pour les filtres actuels.</td>
                    </tr>
                  ) : (
                    filteredLogs.map((log) => {
                      const status = normalizeStatus(log);
                      return (
                        <tr
                          key={log.id}
                          onClick={() => setSelectedLog(log)}
                          className={`cursor-pointer transition-colors hover:bg-slate-900 ${
                            selectedLog?.id === log.id ? 'bg-slate-900/90' : ''
                          }`}
                        >
                          <td className="whitespace-nowrap p-3 text-slate-400">{log.timestamp}</td>
                          <td className="p-3">
                            <span className={`rounded border px-2 py-0.5 text-[10px] font-black ${getSeverityClass(log.severity)}`}>
                              {log.severity}
                            </span>
                          </td>
                          <td className="p-3 font-bold text-cyan-400">{log.source}</td>
                          <td className="p-3 text-slate-400">{log.destination || 'N/A'}</td>
                          <td className="p-3 text-slate-300">{log.service}</td>
                          <td className="max-w-sm truncate p-3 font-sans text-slate-300">{log.event}</td>
                          <td className="p-3 text-right">
                            <span className={`rounded border px-2 py-1 text-[10px] font-black ${getStatusClass(status)}`}>
                              {status}
                            </span>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="space-y-3 p-4">
              {filteredLogs.length === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-800 py-10 text-center text-slate-500">
                  Aucun evenement trouve dans la chronologie.
                </div>
              ) : (
                filteredLogs.map((log) => (
                  <button
                    key={log.id}
                    type="button"
                    onClick={() => setSelectedLog(log)}
                    className={`grid w-full grid-cols-[96px_1fr] gap-4 rounded-lg border p-3 text-left transition-colors ${
                      selectedLog?.id === log.id
                        ? 'border-cyan-500/40 bg-cyan-500/10'
                        : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
                    }`}
                  >
                    <div className="text-xs font-bold text-slate-500">{log.timestamp?.slice(11, 16)}</div>
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded border px-2 py-0.5 text-[10px] font-black ${getSeverityClass(log.severity)}`}>
                          {log.severity}
                        </span>
                        <span className="font-mono text-xs font-bold text-cyan-400">{log.source}</span>
                        <span className="font-sans text-xs text-slate-500">{log.service}</span>
                      </div>
                      <p className="mt-2 font-sans text-sm text-slate-300">{log.event}</p>
                    </div>
                  </button>
                ))
              )}
            </div>
          )}
        </main>

        <aside className="rounded-xl border border-slate-800/80 bg-slate-950/65 p-4">
          {selectedLog ? (
            <div className="space-y-5">
              <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <span className="text-[10px] font-bold uppercase tracking-[0.22em] text-cyan-400">Resume des preuves</span>
                  <h2 className="mt-1 text-lg font-black text-white">{selectedLog.id}</h2>
                  <p className="mt-1 text-[11px] uppercase tracking-[0.2em] text-slate-500">{selectedLog.service}</p>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedLog(null)}
                  className="rounded-lg border border-slate-800 bg-slate-900 px-2 py-1 text-xs font-bold text-slate-400 hover:text-white"
                >
                  Fermer
                </button>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-500">Source</span>
                  <strong className="mt-1 block select-all text-cyan-400">{selectedLog.source}</strong>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-500">Destination</span>
                  <strong className="mt-1 block text-slate-200">{selectedLog.destination || 'N/A'}</strong>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-500">Gravite</span>
                  <strong className="mt-1 block text-slate-200">{selectedLog.severity}</strong>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-500">Statut</span>
                  <strong className="mt-1 block text-slate-200">{normalizeStatus(selectedLog)}</strong>
                </div>
              </div>

              <div>
                <span className="mb-2 block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Message Syslog</span>
                <p className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 font-sans text-sm leading-6 text-slate-200">
                  {selectedLog.event}
                </p>
              </div>

              <div>
                <span className="mb-2 block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Metadonnees</span>
                <pre className="max-h-36 overflow-x-auto whitespace-pre-wrap rounded-lg border border-slate-900 bg-slate-950 p-3 text-[11px] leading-tight text-amber-400">
                  {selectedLog.payload || 'Aucune charge utile disponible'}
                </pre>
              </div>

              <div className="space-y-2">
                <span className="block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Contexte chronologique</span>
                <button
                  type="button"
                  disabled={!previousLog}
                  onClick={() => previousLog && setSelectedLog(previousLog)}
                  className="w-full rounded-lg border border-slate-800 bg-slate-900/60 p-2 text-left text-xs text-slate-400 disabled:opacity-40"
                >
                  Precedent : {previousLog?.id || 'Aucun'}
                </button>
                <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 p-2 text-xs font-bold text-cyan-400">
                  Actuel : {selectedLog.id}
                </div>
                <button
                  type="button"
                  disabled={!nextLog}
                  onClick={() => nextLog && setSelectedLog(nextLog)}
                  className="w-full rounded-lg border border-slate-800 bg-slate-900/60 p-2 text-left text-xs text-slate-400 disabled:opacity-40"
                >
                  Suivant : {nextLog?.id || 'Aucun'}
                </button>
              </div>

              <div className="space-y-2 border-t border-slate-800 pt-4">
                <span className="block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Actions de pivot</span>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => pivotTo('source', selectedLog.source)}
                    className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs font-bold text-slate-300 hover:border-cyan-500/40 hover:text-cyan-400"
                  >
                    Meme IP
                  </button>
                  <button
                    type="button"
                    onClick={() => pivotTo('service', selectedLog.service)}
                    className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs font-bold text-slate-300 hover:border-cyan-500/40 hover:text-cyan-400"
                  >
                    Meme service
                  </button>
                  <button
                    type="button"
                    onClick={() => pivotTo('severity', selectedLog.severity)}
                    className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs font-bold text-slate-300 hover:border-cyan-500/40 hover:text-cyan-400"
                  >
                    Meme gravite
                  </button>
                  <button
                    type="button"
                    onClick={() => setQuery(selectedLog.source)}
                    className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs font-bold text-slate-300 hover:border-cyan-500/40 hover:text-cyan-400"
                  >
                    Copier IOC
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex min-h-[420px] flex-col items-center justify-center text-center text-slate-500">
              <span className="font-bold text-slate-300">Aucun log selectionne</span>
              <span className="mt-2 max-w-xs font-sans text-sm text-slate-500">
                Selectionnez un evenement pour inspecter les metadonnees, le contexte chronologique et les actions de pivot.
              </span>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
