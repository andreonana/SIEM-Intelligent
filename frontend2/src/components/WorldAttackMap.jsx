

export default function WorldAttackMap() {
  const hotZones = [
    { country: 'Douala, Cameroun', count: 312, percentage: '38%', status: 'CRITICAL', lastIp: '10.0.12.88', color: 'bg-red-500' },
    { country: 'Yaoundé, Cameroun', count: 208, percentage: '27%', status: 'WARNING', lastIp: '10.0.15.77', color: 'bg-amber-500' },
    { country: 'Lagos, Nigeria', count: 176, percentage: '24%', status: 'WARNING', lastIp: '41.216.10.44', color: 'bg-amber-500' },
    { country: 'Nairobi, Kenya', count: 128, percentage: '18%', status: 'MONITORED', lastIp: '196.201.64.11', color: 'bg-cyan-500' },
    { country: 'Johannesburg, Afrique du Sud', count: 96, percentage: '14%', status: 'MONITORED', lastIp: '197.80.44.9', color: 'bg-cyan-500' }
  ];

  return (
    <div className="flex h-[520px] flex-col justify-between overflow-hidden rounded-xl border border-slate-800/80 bg-slate-950/80 p-6 shadow-2xl">
      <div className="z-10 flex items-center justify-between border-b border-slate-800/70 pb-3.5">
        <div>
          <h3 className="text-sm font-black uppercase tracking-wider text-white">TÉLÉMÉTRIE GÉO-RÉGIONALE AFRICAINE</h3>
          <p className="mt-0.5 text-xs text-slate-400">Priorisation des zones d’intérêt au Cameroun et à travers l’Afrique</p>
        </div>
        <div className="rounded border border-red-500/20 bg-red-500/10 px-3 py-1 text-xs font-bold uppercase tracking-wide text-red-400">
          Corrélation active
        </div>
      </div>

      <div className="my-4 flex-1 space-y-4 overflow-y-auto pr-1">
        {hotZones.map((zone, index) => (
          <div key={index} className="rounded-lg border border-slate-800/80 bg-slate-900/80 p-4 transition-all duration-200 hover:border-slate-700">
            <div className="mb-2.5 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="font-bold text-slate-500">#0{index + 1}</span>
                <span className="text-[13px] font-bold tracking-wide text-slate-100">{zone.country}</span>
              </div>
              <div className="text-right">
                <span className="text-[13px] font-bold text-slate-300">{zone.count} logs </span>
                <span className="text-slate-500">({zone.percentage})</span>
              </div>
            </div>

            <div className="mb-2.5 h-2.5 w-full overflow-hidden rounded-full border border-slate-800/30 bg-slate-800/70">
              <div className={`${zone.color} h-full rounded-full transition-all duration-1000`} style={{ width: zone.percentage }}></div>
            </div>

            <div className="flex items-center justify-between pt-0.5 text-xs text-slate-400">
              <div>
                <span className="text-slate-500">Last observed pattern:</span>{' '}
                <span className="select-all rounded border border-cyan-900/50 bg-cyan-950/40 px-2 py-0.5 font-semibold text-cyan-400">
                  {zone.lastIp}
                </span>
              </div>
              <div>
                <span className="text-slate-500">Signal:</span>{' '}
                <span className={`font-bold tracking-wider ${zone.status === 'CRITICAL' ? 'text-red-400' : zone.status === 'WARNING' ? 'text-amber-400' : 'text-cyan-400'}`}>
                  ● {zone.status}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="z-10 flex items-center justify-between border-t border-slate-800/70 pt-3.5 text-xs text-slate-400">
        <div className="flex gap-5">
          <div className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-red-500 shadow-[0_0_6px_#ef4444]"></span> Cible critique</div>
          <div className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-amber-500 shadow-[0_0_6px_#f59e0b]"></span> Nœud suspect</div>
        </div>
        <div className="tracking-wider text-slate-500">Geo focus: Africa • Refresh: 5s</div>
      </div>
    </div>
  );
}