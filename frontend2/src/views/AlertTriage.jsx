import { useMemo, useState } from 'react';

const severities = ['ALL', 'CRITICAL', 'WARNING'];
const statuses = ['ALL', 'NON_TRAITE', 'EN_COURS', 'ESCALADE'];

const severityLabels = {
  ALL: 'TOUTES',
  CRITICAL: 'CRITIQUE',
  WARNING: 'AVERTISSEMENT',
};

const statusLabels = {
  ALL: 'TOUS',
  NON_TRAITE: 'NON TRAITE',
  EN_COURS: 'EN COURS',
  ESCALADE: 'ESCALADE',
};

function normalizeStatus(alert) {
  if (alert.escalated) return 'ESCALADE';
  if (alert.status === 'EN_COURS') return 'EN_COURS';
  return 'NON_TRAITE';
}

function severityClass(severity) {
  if (severity === 'CRITICAL') return 'border-red-500/30 bg-red-500/10 text-red-400';
  return 'border-amber-500/30 bg-amber-500/10 text-amber-400';
}

function statusClass(status) {
  if (status === 'ESCALADE') return 'border-red-500/30 bg-red-500/10 text-red-400';
  if (status === 'EN_COURS') return 'border-amber-500/30 bg-amber-500/10 text-amber-400';
  return 'border-slate-700 bg-slate-950/70 text-slate-400';
}

function Metric({ label, value, tone = 'text-slate-100' }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2">
      <span className="block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">{label}</span>
      <strong className={`mt-1 block text-lg ${tone}`}>{value}</strong>
    </div>
  );
}

export default function AlertTriage({ user, logs, setLogs }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedStatus, setSelectedStatus] = useState('ALL');
  const [selectedService, setSelectedService] = useState('ALL');
  const [showMoreFilters, setShowMoreFilters] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedAlertIds, setSelectedAlertIds] = useState([]);

  const isReader = user?.role === 'reader';

  const services = useMemo(() => {
    return ['ALL', ...Array.from(new Set(logs.map((log) => log.service).filter(Boolean)))];
  }, [logs]);

  const activeAlerts = useMemo(() => {
    return logs.filter((log) => {
      const isAlert = log.severity === 'CRITICAL' || log.severity === 'WARNING';
      const isNotClosed = log.status !== 'FAUX_POSITIF' && log.status !== 'TRAITE' && log.status !== 'TRAITÉ' && log.status !== 'TRAITÃ‰';
      return isAlert && isNotClosed;
    });
  }, [logs]);

  const alerts = useMemo(() => {
    const search = searchTerm.toLowerCase();

    return activeAlerts.filter((alert) => {
      const status = normalizeStatus(alert);
      const matchesSearch =
        alert.event.toLowerCase().includes(search) ||
        alert.source.includes(searchTerm) ||
        alert.service.toLowerCase().includes(search);
      const matchesSeverity = selectedSeverity === 'ALL' || alert.severity === selectedSeverity;
      const matchesStatus = selectedStatus === 'ALL' || status === selectedStatus;
      const matchesService = selectedService === 'ALL' || alert.service === selectedService;

      return matchesSearch && matchesSeverity && matchesStatus && matchesService;
    });
  }, [activeAlerts, searchTerm, selectedSeverity, selectedStatus, selectedService]);

  const metrics = useMemo(() => {
    return {
      open: activeAlerts.length,
      critical: activeAlerts.filter((alert) => alert.severity === 'CRITICAL').length,
      escalated: activeAlerts.filter((alert) => alert.escalated).length,
      selected: selectedAlertIds.length,
    };
  }, [activeAlerts, selectedAlertIds]);

  const clearFilters = () => {
    setSearchTerm('');
    setSelectedSeverity('ALL');
    setSelectedStatus('ALL');
    setSelectedService('ALL');
    setSelectedAlertIds([]);
  };

  const handleSelectAlert = (id, event) => {
    event.stopPropagation();
    if (isReader) return;

    setSelectedAlertIds((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id]
    );
  };

  const handleSelectAll = () => {
    if (isReader) return;

    const visibleIds = alerts.map((alert) => alert.id);
    const allVisibleAreSelected = visibleIds.length > 0 && visibleIds.every((id) => selectedAlertIds.includes(id));

    if (allVisibleAreSelected) {
      setSelectedAlertIds((current) => current.filter((id) => !visibleIds.includes(id)));
    } else {
      setSelectedAlertIds((current) => Array.from(new Set([...current, ...visibleIds])));
    }
  };

  const closeIfSelected = (ids) => {
    if (selectedAlert && ids.includes(selectedAlert.id)) setSelectedAlert(null);
  };

  const handleBulkUpdate = (newStatus) => {
    if (isReader || selectedAlertIds.length === 0) return;

    setLogs((previousLogs) =>
      previousLogs.map((log) =>
        selectedAlertIds.includes(log.id) ? { ...log, status: newStatus, escalated: false } : log
      )
    );
    closeIfSelected(selectedAlertIds);
    setSelectedAlertIds([]);
  };

  const handleUpdateSingleStatus = (id, newStatus) => {
    if (isReader) return;

    setLogs((previousLogs) =>
      previousLogs.map((log) => (log.id === id ? { ...log, status: newStatus, escalated: false } : log))
    );
    closeIfSelected([id]);
    setSelectedAlertIds((current) => current.filter((item) => item !== id));
  };

  const handleEscalate = (id) => {
    if (isReader) return;

    setLogs((previousLogs) =>
      previousLogs.map((log) => (log.id === id ? { ...log, escalated: true, status: 'EN_COURS' } : log))
    );
    if (selectedAlert?.id === id) {
      setSelectedAlert((current) => ({ ...current, escalated: true, status: 'EN_COURS' }));
    }
  };

  const allVisibleSelected = alerts.length > 0 && alerts.every((alert) => selectedAlertIds.includes(alert.id));

  return (
    <div className="max-h-[85vh] space-y-5 overflow-y-auto pr-2 text-slate-200 animate-in fade-in duration-300">
      <div className="flex flex-col gap-4 border-b border-slate-800/70 pb-5 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <span className="text-xs font-bold uppercase tracking-[0.3em] text-amber-400">File de correlation</span>
          <h1 className="mt-2 text-3xl font-black text-white">Triage des alertes</h1>
          <p className="mt-2 font-sans text-sm text-slate-400">
            Analysez les alertes correlees, validez les preuves et decidez ce qui sort de la file.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          {isReader && (
            <span className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 font-black text-red-400">
              LECTURE SEULE
            </span>
          )}
          <span className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 font-bold text-slate-300">
            Operateur : <span className="text-amber-400">{user?.name || 'Operateur SOC'}</span>
          </span>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800/80 bg-slate-950/70 p-4 shadow-lg">
        <div className="flex flex-col gap-3 xl:flex-row">
          <input
            type="text"
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
            placeholder="Rechercher une alerte par IP, service, signature, payload..."
            className="min-h-11 flex-1 rounded-lg border border-slate-800 bg-slate-900/80 px-4 py-2.5 font-mono text-sm text-white outline-none transition-colors placeholder:text-slate-600 hover:border-slate-700 focus:border-amber-500"
          />

          <div className="flex flex-wrap gap-2">
            {severities.map((severity) => (
              <button
                key={severity}
                type="button"
                onClick={() => setSelectedSeverity(severity)}
                className={`rounded-lg border px-3 py-2 text-xs font-black uppercase tracking-wider transition-colors ${
                  selectedSeverity === severity
                    ? 'border-amber-500/40 bg-amber-500/10 text-amber-400'
                    : 'border-slate-800 bg-slate-900 text-slate-400 hover:border-slate-700 hover:text-slate-100'
                }`}
              >
                {severityLabels[severity]}
              </button>
            ))}
            <button
              type="button"
              onClick={() => setShowMoreFilters((current) => !current)}
              className={`rounded-lg border px-3 py-2 text-xs font-black uppercase tracking-wider transition-colors ${
                showMoreFilters
                  ? 'border-amber-500/40 bg-amber-500/10 text-amber-400'
                  : 'border-slate-800 bg-slate-900 text-slate-400 hover:border-slate-700 hover:text-slate-100'
              }`}
            >
              Plus de filtres
            </button>
            <button
              type="button"
              onClick={clearFilters}
              className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs font-black uppercase tracking-wider text-slate-500 transition-colors hover:border-red-500/30 hover:text-red-400"
            >
              Reinitialiser
            </button>
          </div>
        </div>

        {showMoreFilters && (
          <div className="mt-4 grid gap-3 rounded-xl border border-slate-800 bg-slate-900/50 p-3 md:grid-cols-2">
            <label className="space-y-1.5">
              <span className="block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Statut</span>
              <select
                value={selectedStatus}
                onChange={(event) => setSelectedStatus(event.target.value)}
                className="w-full rounded-lg border border-slate-800 bg-slate-950/80 p-2.5 text-xs font-bold text-slate-300 outline-none focus:border-amber-500"
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
                className="w-full rounded-lg border border-slate-800 bg-slate-950/80 p-2.5 text-xs font-bold text-slate-300 outline-none focus:border-amber-500"
              >
                {services.map((service) => (
                  <option key={service} value={service}>
                    {service}
                  </option>
                ))}
              </select>
            </label>
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Metric label="Alertes ouvertes" value={metrics.open} tone="text-white" />
        <Metric label="Critiques" value={metrics.critical} tone="text-red-400" />
        <Metric label="Escaladees" value={metrics.escalated} tone="text-amber-400" />
        <Metric label="Selectionnees" value={metrics.selected} tone="text-cyan-400" />
      </div>

      {selectedAlertIds.length > 0 && !isReader && (
        <div className="flex flex-col gap-3 rounded-xl border border-amber-500/40 bg-amber-950/20 p-4 shadow-lg md:flex-row md:items-center md:justify-between">
          <div className="font-sans text-sm text-amber-200">
            <strong className="font-black text-white">{selectedAlertIds.length}</strong> alerte(s) selectionnee(s) pour une decision en masse.
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <button
              type="button"
              onClick={() => handleBulkUpdate('FAUX_POSITIF')}
              className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-xs font-black uppercase tracking-wider text-slate-300 hover:border-slate-500"
            >
              Marquer faux positif
            </button>
            <button
              type="button"
              onClick={() => handleBulkUpdate('TRAITE')}
              className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-xs font-black uppercase tracking-wider text-emerald-400 hover:bg-emerald-500 hover:text-white"
            >
              Resoudre la selection
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <main className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-950/65">
          <div className="flex flex-col gap-3 border-b border-slate-800 bg-slate-950/80 p-4 md:flex-row md:items-center md:justify-between">
            <div>
              <h2 className="text-xs font-black uppercase tracking-[0.24em] text-slate-200">File des alertes</h2>
              <p className="mt-1 font-sans text-xs text-slate-500">{alerts.length} alertes actives correspondantes</p>
            </div>
            <label className="flex items-center gap-2 text-xs font-bold text-slate-400">
              <input
                type="checkbox"
                checked={allVisibleSelected}
                onChange={handleSelectAll}
                disabled={isReader || alerts.length === 0}
                className="h-4 w-4 accent-amber-500"
              />
              Selectionner visibles
            </label>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] border-collapse text-left">
              <thead>
                <tr className="border-b border-slate-800 text-[10px] uppercase tracking-[0.22em] text-slate-500">
                  <th className="p-3">Selection</th>
                  <th className="p-3">Gravite</th>
                  <th className="p-3">Source</th>
                  <th className="p-3">Service</th>
                  <th className="p-3">Resume de l'alerte</th>
                  <th className="p-3 text-right">Statut</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs">
                {alerts.length === 0 ? (
                  <tr>
                    <td colSpan="6" className="p-10 text-center text-emerald-400">
                      La file des alertes actives est vide.
                    </td>
                  </tr>
                ) : (
                  alerts.map((alert) => {
                    const status = normalizeStatus(alert);
                    const checked = selectedAlertIds.includes(alert.id);

                    return (
                      <tr
                        key={alert.id}
                        onClick={() => setSelectedAlert(alert)}
                        className={`cursor-pointer transition-colors hover:bg-slate-900 ${
                          selectedAlert?.id === alert.id ? 'bg-slate-900/90' : ''
                        } ${checked ? 'bg-amber-950/20' : ''}`}
                      >
                        <td className="p-3" onClick={(event) => handleSelectAlert(alert.id, event)}>
                          <input
                            type="checkbox"
                            checked={checked}
                            disabled={isReader}
                            readOnly
                            className="h-4 w-4 accent-amber-500"
                          />
                        </td>
                        <td className="p-3">
                          <span className={`rounded border px-2 py-0.5 text-[10px] font-black ${severityClass(alert.severity)}`}>
                            {alert.severity}
                          </span>
                        </td>
                        <td className="p-3 font-bold text-cyan-400">{alert.source}</td>
                        <td className="p-3 text-slate-300">{alert.service}</td>
                        <td className="max-w-md truncate p-3 font-sans text-slate-300">{alert.event}</td>
                        <td className="p-3 text-right">
                          <span className={`rounded border px-2 py-1 text-[10px] font-black ${statusClass(status)}`}>
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
        </main>

        <aside className="rounded-xl border border-slate-800/80 bg-slate-950/65 p-4">
          {selectedAlert ? (
            <div className="space-y-5">
              <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <span className="text-[10px] font-bold uppercase tracking-[0.22em] text-amber-400">Inspecteur de cas</span>
                  <h2 className="mt-1 text-lg font-black text-white">{selectedAlert.id}</h2>
                  <p className="mt-1 text-[11px] uppercase tracking-[0.2em] text-slate-500">{selectedAlert.service}</p>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedAlert(null)}
                  className="rounded-lg border border-slate-800 bg-slate-900 px-2 py-1 text-xs font-bold text-slate-400 hover:text-white"
                >
                  Fermer
                </button>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-500">Source</span>
                  <strong className="mt-1 block select-all text-cyan-400">{selectedAlert.source}</strong>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-500">Gravite</span>
                  <strong className="mt-1 block text-slate-200">{selectedAlert.severity}</strong>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-500">Statut</span>
                  <strong className="mt-1 block text-slate-200">{normalizeStatus(selectedAlert)}</strong>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-500">Role</span>
                  <strong className="mt-1 block text-slate-200">{user?.role || 'unknown'}</strong>
                </div>
              </div>

              <div>
                <span className="mb-2 block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Preuves</span>
                <p className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 font-sans text-sm leading-6 text-slate-200">
                  {selectedAlert.event}
                </p>
              </div>

              <div>
                <span className="mb-2 block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Payload</span>
                <pre className="max-h-40 overflow-x-auto whitespace-pre-wrap rounded-lg border border-slate-900 bg-slate-950 p-3 text-[11px] leading-tight text-amber-400">
                  {selectedAlert.payload || 'Aucun payload disponible'}
                </pre>
              </div>

              {(selectedAlert.mitre_tactic_id || selectedAlert.mitre_technique_id) && (
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-sm">
                  <span className="mb-1 block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">
                    MITRE ATT&CK
                  </span>
                  {selectedAlert.mitre_tactic_id && (
                    <div className="font-bold text-slate-200">
                      {selectedAlert.mitre_tactic_id} - {selectedAlert.mitre_tactic_name}
                    </div>
                  )}
                  {selectedAlert.mitre_technique_id && (
                    <div className="text-slate-400">
                      {selectedAlert.mitre_technique_id} - {selectedAlert.mitre_technique_name}
                    </div>
                  )}
                </div>
              )}

              <div className="space-y-3 border-t border-slate-800 pt-4">
                <span className="block text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Decision</span>
                {isReader ? (
                  <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm font-bold text-red-400">
                    Les utilisateurs en lecture seule ne peuvent pas modifier les decisions d'alerte.
                  </div>
                ) : selectedAlert.escalated ? (
                  <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-center text-sm font-black text-red-400">
                    Escalade vers la salle de crise
                  </div>
                ) : (
                  <div className="grid gap-2">
                    <button
                      type="button"
                      onClick={() => handleUpdateSingleStatus(selectedAlert.id, 'FAUX_POSITIF')}
                      className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-2.5 text-xs font-black uppercase tracking-wider text-slate-300 hover:border-slate-500"
                    >
                      Marquer faux positif
                    </button>
                    <button
                      type="button"
                      onClick={() => handleUpdateSingleStatus(selectedAlert.id, 'TRAITE')}
                      className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2.5 text-xs font-black uppercase tracking-wider text-emerald-400 hover:bg-emerald-500 hover:text-white"
                    >
                      Resoudre l'alerte
                    </button>
                    <button
                      type="button"
                      onClick={() => handleEscalate(selectedAlert.id)}
                      className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-xs font-black uppercase tracking-wider text-red-400 hover:bg-red-500 hover:text-white"
                    >
                      Escalader vers la salle de crise
                    </button>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex min-h-[420px] flex-col items-center justify-center text-center text-slate-500">
              <span className="font-bold text-slate-300">Aucune alerte selectionnee</span>
              <span className="mt-2 max-w-xs font-sans text-sm text-slate-500">
                Selectionnez une alerte pour inspecter les preuves et appliquer une decision de triage.
              </span>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
