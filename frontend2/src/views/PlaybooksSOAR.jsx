import { useMemo, useState } from 'react';

const ATTACK_SEVERITIES = ['CRITICAL', 'WARNING'];

function getBlockReason(log) {
  if (log.payload?.toLowerCase().includes('sql')) return "Regle WAF declenchee par un motif d'injection SQL";
  if (log.event?.toLowerCase().includes('ssh')) return 'Seuil Fail2Ban depasse';
  if (log.event?.toLowerCase().includes('port')) return 'Reconnaissance reseau detectee par le pare-feu';
  if (log.event?.toLowerCase().includes('dns')) return 'Flux sortant mis en quarantaine par la politique DNS';
  return 'Politique de confinement SOAR appliquee automatiquement';
}

function getBlockEngine(log) {
  if (log.service?.toLowerCase().includes('waf') || log.service?.toLowerCase().includes('nginx')) return 'Nginx-WAF';
  if (log.service?.toLowerCase().includes('firewall')) return 'Internal Firewall';
  if (log.service?.toLowerCase().includes('dns')) return 'DNS Guard';
  return 'SOAR Firewall Orchestrator';
}

export default function PlaybooksSOAR({ user, logs, setLogs }) {
  const [selectedLogId, setSelectedLogId] = useState(null);
  const [runningUnblock, setRunningUnblock] = useState(null);
  const [consoleLogs, setConsoleLogs] = useState([]);

  const isAdmin = user?.role === 'administrator';

  const attackLogs = useMemo(() => {
    return logs
      .filter((log) => ATTACK_SEVERITIES.includes(log.severity))
      .map((log) => ({
        ...log,
        blockStatus: log.blockStatus || 'BLOCKED',
        blockedAt: log.blockedAt || log.timestamp,
        blockEngine: log.blockEngine || getBlockEngine(log),
        blockReason: log.blockReason || getBlockReason(log),
      }));
  }, [logs]);

  const selectedLog = attackLogs.find((log) => log.id === selectedLogId) || attackLogs[0] || null;
  const blockedCount = attackLogs.filter((log) => log.blockStatus !== 'UNBLOCKED').length;
  const releasedCount = attackLogs.length - blockedCount;

  const handleSelectLog = (log) => {
    if (runningUnblock) return;
    setSelectedLogId(log.id);
    setConsoleLogs([]);
  };

  const handleUnblockIp = (log) => {
    if (!isAdmin || runningUnblock || log.blockStatus === 'UNBLOCKED') return;

    setRunningUnblock(log.id);
    setConsoleLogs([
      `[SOAR] Admin ${user?.name || 'operateur'} demande le deblocage de ${log.source}`,
      `[VERIF] Validation des preuves pour ${log.id}`,
    ]);

    setTimeout(() => {
      setConsoleLogs((prev) => [...prev, `[LIEN] Connexion etablie avec ${log.blockEngine}`]);
    }, 500);

    setTimeout(() => {
      setConsoleLogs((prev) => [...prev, `[ACTION] Suppression de la regle de blocage pour ${log.source}`]);
    }, 1000);

    setTimeout(() => {
      setLogs((prevLogs) =>
        prevLogs.map((item) =>
          item.id === log.id
            ? {
                ...item,
                blockStatus: 'UNBLOCKED',
                status: 'DEBLOQUE',
                unblockedBy: user?.name || 'administrator',
                unblockedAt: new Date().toISOString(),
              }
            : item
        )
      );

      setConsoleLogs((prev) => [...prev, `[SUCCES] ${log.source} est debloquee et la piste d'audit est mise a jour.`]);
      setRunningUnblock(null);
    }, 1600);
  };

  return (
    <div className="space-y-6 font-mono text-sm animate-in fade-in duration-300">
      <div className="flex flex-col gap-4 border-b border-slate-800 pb-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <span className="block text-xs font-bold uppercase tracking-[0.3em] text-emerald-400">
            Revue de la liste de blocage SOAR
          </span>
          <h1 className="mt-1 text-2xl font-black text-white">Logs d'attaques bloquees</h1>
          <p className="mt-2 max-w-2xl font-sans text-sm text-slate-400">
            Consultez les attaques deja contenues automatiquement. Les administrateurs peuvent debloquer une IP apres validation.
          </p>
        </div>

        <div className="grid grid-cols-3 gap-2 text-xs">
          <div className="rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-2">
            <span className="block text-slate-500">Attaques</span>
            <strong className="text-white">{attackLogs.length}</strong>
          </div>
          <div className="rounded-lg border border-red-500/30 bg-red-950/20 px-3 py-2">
            <span className="block text-slate-500">Bloquees</span>
            <strong className="text-red-400">{blockedCount}</strong>
          </div>
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/20 px-3 py-2">
            <span className="block text-slate-500">Debloquees</span>
            <strong className="text-emerald-400">{releasedCount}</strong>
          </div>
        </div>
      </div>

      {!isAdmin && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 px-4 py-3 font-sans text-sm text-amber-200">
          Vous pouvez inspecter les attaques bloquees, mais seul un administrateur peut debloquer une adresse IP.
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-[#0f172a] p-4 lg:col-span-1">
          <div className="mb-3 flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500">File des attaques bloquees</span>
            <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-bold text-slate-400">
              Politique active
            </span>
          </div>

          <div className="max-h-[520px] space-y-2 overflow-y-auto pr-1">
            {attackLogs.length === 0 ? (
              <div className="rounded-xl border border-dashed border-emerald-800/40 bg-emerald-950/10 py-8 text-center text-emerald-400">
                Aucune attaque bloquee dans le flux actuel.
              </div>
            ) : (
              attackLogs.map((log) => {
                const selected = selectedLog?.id === log.id;
                const released = log.blockStatus === 'UNBLOCKED';

                return (
                  <button
                    key={log.id}
                    type="button"
                    onClick={() => handleSelectLog(log)}
                    className={`w-full rounded-lg border p-3 text-left transition-all ${
                      selected
                        ? 'border-cyan-500 bg-cyan-950/30 text-white'
                        : 'border-slate-800 bg-[#111827]/80 text-slate-300 hover:border-slate-700'
                    } ${runningUnblock ? 'cursor-not-allowed opacity-70' : ''}`}
                  >
                    <div className="mb-2 flex items-center justify-between gap-2">
                      <span
                        className={`rounded border px-1.5 py-0.5 text-[9px] font-bold ${
                          log.severity === 'CRITICAL'
                            ? 'border-red-500/30 bg-red-500/10 text-red-400'
                            : 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                        }`}
                      >
                        {log.severity}
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[9px] font-black ${
                          released ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'
                        }`}
                      >
                        {released ? 'DEBLOQUEE' : 'BLOQUEE'}
                      </span>
                    </div>

                    <div className="font-bold text-slate-100">{log.source}</div>
                    <div className="mt-1 truncate font-sans text-[11px] text-slate-400">{log.event}</div>
                    <div className="mt-2 text-[10px] text-slate-500">{log.timestamp}</div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        <div className="lg:col-span-2">
          {selectedLog ? (
            <div className="relative space-y-6 overflow-hidden rounded-xl border border-slate-800 bg-[#0f172a] p-6">
              <div className="flex flex-col gap-4 border-b border-slate-800/80 pb-5 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <span className="block text-[10px] font-bold uppercase tracking-widest text-cyan-400">
                    Preuves de l'attaque bloquee
                  </span>
                  <h2 className="mt-1 text-xl font-black text-white">{selectedLog.id}</h2>
                  <p className="mt-2 font-sans text-sm text-slate-400">{selectedLog.event}</p>
                </div>

                <span
                  className={`w-fit rounded-full border px-3 py-1 text-[10px] font-black uppercase tracking-wider ${
                    selectedLog.blockStatus === 'UNBLOCKED'
                      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                      : 'border-red-500/30 bg-red-500/10 text-red-400'
                  }`}
                >
                  {selectedLog.blockStatus === 'UNBLOCKED' ? 'IP debloquee' : 'IP bloquee'}
                </span>
              </div>

              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <div className="rounded-lg border border-slate-800/60 bg-[#111827] p-3 text-xs">
                  <span className="text-slate-500">IP bloquee</span>
                  <span className="mt-1 block select-all font-bold text-cyan-400">{selectedLog.source}</span>
                </div>
                <div className="rounded-lg border border-slate-800/60 bg-[#111827] p-3 text-xs">
                  <span className="text-slate-500">Actif protege</span>
                  <span className="mt-1 block font-bold text-slate-200">{selectedLog.destination || 'N/A'}</span>
                </div>
                <div className="rounded-lg border border-slate-800/60 bg-[#111827] p-3 text-xs">
                  <span className="text-slate-500">Moteur de blocage</span>
                  <span className="mt-1 block font-bold text-slate-200">{selectedLog.blockEngine}</span>
                </div>
                <div className="rounded-lg border border-slate-800/60 bg-[#111827] p-3 text-xs">
                  <span className="text-slate-500">Bloquee a</span>
                  <span className="mt-1 block font-bold text-slate-200">{selectedLog.blockedAt}</span>
                </div>
              </div>

              <div className="space-y-2">
                <span className="block text-[10px] font-bold uppercase text-slate-500">Raison du confinement</span>
                <p className="rounded-lg border border-slate-800 bg-[#111827] p-3 font-sans text-sm text-slate-200">
                  {selectedLog.blockReason}
                </p>
              </div>

              {selectedLog.payload && (
                <div className="space-y-2">
                  <span className="block text-[10px] font-bold uppercase text-slate-500">Log brut de l'attaque</span>
                  <pre className="max-h-36 overflow-x-auto whitespace-pre-wrap rounded-lg border border-slate-900 bg-slate-950 p-3 text-[11px] text-amber-400 shadow-inner">
                    {selectedLog.payload}
                  </pre>
                </div>
              )}

              <div className="rounded-xl border border-slate-800 bg-[#111827]/80 p-4">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                  <div>
                    <span className="block text-xs font-black uppercase tracking-wider text-emerald-400">
                      Remediation administrateur
                    </span>
                    <p className="mt-1 font-sans text-sm text-slate-400">
                      A utiliser uniquement apres confirmation que la source est sure ou bloquee par erreur.
                    </p>
                  </div>

                  <button
                    type="button"
                    disabled={!isAdmin || runningUnblock !== null || selectedLog.blockStatus === 'UNBLOCKED'}
                    onClick={() => handleUnblockIp(selectedLog)}
                    className={`rounded-lg border px-4 py-2 text-xs font-black uppercase tracking-wider transition-all ${
                      !isAdmin || selectedLog.blockStatus === 'UNBLOCKED'
                        ? 'cursor-not-allowed border-slate-700 bg-slate-800 text-slate-500'
                        : runningUnblock
                          ? 'cursor-wait border-cyan-500/30 bg-cyan-950/30 text-cyan-400'
                          : 'border-emerald-500/30 bg-emerald-950/30 text-emerald-400 hover:border-emerald-500 hover:bg-emerald-500 hover:text-white'
                    }`}
                  >
                    {selectedLog.blockStatus === 'UNBLOCKED'
                      ? 'Deja debloquee'
                      : runningUnblock === selectedLog.id
                        ? 'Deblocage...'
                        : "Debloquer l'IP"}
                  </button>
                </div>
              </div>

              {consoleLogs.length > 0 && (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <div className="mb-2 flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="text-xs font-bold tracking-widest text-cyan-400">Console d'audit SOAR</span>
                    {runningUnblock && <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />}
                  </div>
                  <div className="max-h-40 space-y-1.5 overflow-y-auto text-xs">
                    {consoleLogs.map((log, index) => (
                      <div
                        key={`${log}-${index}`}
                        className={log.includes('SUCCESS') ? 'font-bold text-emerald-400' : 'text-slate-300'}
                      >
                        {log}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex min-h-[420px] flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 bg-[#0f172a] p-12 text-center text-slate-500">
              <span>Aucune attaque bloquee selectionnee.</span>
              <span className="mt-1 font-sans text-[11px] text-slate-600">
                Selectionnez un log d'attaque bloquee pour inspecter ses preuves et son etat de remediation.
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
