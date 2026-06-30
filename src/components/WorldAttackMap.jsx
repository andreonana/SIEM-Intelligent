import React from 'react';

export default function WorldAttackMap() {
  // Liste des zones les plus hostiles (alignée sur les scénarios de la CTU)
  const hotZones = [
    { country: "Moscou, Fédération de Russie", count: 1420, percentage: "92%", status: "CRITICAL", lastIp: "194.26.29.84", color: "bg-red-500" },
    { country: "Pékin, République Populaire de Chine", count: 854, percentage: "65%", status: "WARNING", lastIp: "45.142.120.9", color: "bg-amber-500" },
    { country: "Douala, Cameroun (Zone sensible)", count: 312, percentage: "35%", status: "CRITICAL", lastIp: "10.0.12.88", color: "bg-red-500" },
    { country: "Réseaux d'anonymisation (Sorties Tor)", count: 184, percentage: "20%", status: "MONITORED", lastIp: "185.220.101.5", color: "bg-cyan-500" }
  ];

  return (
    <div className="bg-[#0f172a] [.light_&]:bg-white border border-slate-800/80 [.light_&]:border-slate-200 rounded-xl p-6 font-mono flex flex-col justify-between h-[520px] relative overflow-hidden shadow-2xl">
      
      {/* EN-TÊTE DU COMPOSANT */}
      <div className="flex justify-between items-center border-b border-slate-900/60 [.light_&]:border-slate-200 pb-3.5 bg-[#0f172a] [.light_&]:bg-white z-10">
        <div>
          <h3 className="text-sm font-black text-white [.light_&]:text-slate-900 tracking-wider uppercase"> TÉLÉMÉTRIE DES ZONES GÉO-SPATIALES HOSTILES</h3>
          <p className="text-xs text-slate-400 [.light_&]:text-slate-500 mt-0.5">// Classement par volume cumulé de vecteurs malveillants détectés</p>
        </div>
        <div className="text-xs font-bold bg-red-500/10 text-red-400 [.light_&]:text-red-700 px-3 py-1 rounded border border-red-500/20 [.light_&]:border-red-200 animate-pulse uppercase tracking-wide">
           Corrélation Active
        </div>
      </div>

      {/* LISTE DES ZONES */}
      <div className="flex-1 my-4 space-y-4 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-slate-800 [.light_&]:scrollbar-thumb-slate-200">
        {hotZones.map((zone, index) => (
          <div key={index} className="bg-slate-950/40 [.light_&]:bg-slate-50 border border-slate-900 [.light_&]:border-slate-200 rounded-lg p-4 hover:border-slate-800/80 [.light_&]:hover:border-slate-300 transition-all duration-200">
            
            {/* Ligne d'information supérieure (Pays, logs, pourcentages) */}
            <div className="flex justify-between items-center mb-2.5 text-xs">
              <div className="flex items-center gap-2">
                <span className="text-slate-500 [.light_&]:text-slate-400 font-bold">#0{index + 1}</span>
                <span className="text-slate-100 [.light_&]:text-slate-900 font-bold tracking-wide text-[13px]">{zone.country}</span>
              </div>
              <div className="text-right">
                <span className="text-slate-300 [.light_&]:text-slate-800 font-bold text-[13px]">{zone.count} logs </span>
                <span className="text-slate-500 [.light_&]:text-slate-400">({zone.percentage})</span>
              </div>
            </div>

            {/* Barre de jauge */}
            <div className="w-full bg-slate-900 [.light_&]:bg-slate-200 h-2.5 rounded-full overflow-hidden mb-2.5 border border-slate-800/30 [.light_&]:border-slate-300/50">
              <div 
                className={`${zone.color} h-full rounded-full transition-all duration-1000`} 
                style={{ width: zone.percentage }}
              ></div>
            </div>

            {/* Métriques techniques complémentaires */}
            <div className="flex justify-between items-center text-xs text-slate-400 [.light_&]:text-slate-600 pt-0.5">
              <div>
                <span className="text-slate-500 [.light_&]:text-slate-400">Dernier vecteur intercepté :</span>{" "}
                <span className="text-cyan-400 [.light_&]:text-cyan-700 bg-cyan-950/40 [.light_&]:bg-cyan-50 px-2 py-0.5 rounded border border-cyan-900/50 [.light_&]:border-cyan-200 font-bold font-mono select-all tracking-wide">
                  {zone.lastIp}
                </span>
              </div>
              <div>
                <span className="text-slate-500 [.light_&]:text-slate-400">Alerte :</span>{" "}
                <span className={`font-bold tracking-wider ${
                  zone.status === 'CRITICAL' 
                    ? 'text-red-400 [.light_&]:text-red-600' 
                    : zone.status === 'WARNING' 
                      ? 'text-amber-400 [.light_&]:text-amber-600' 
                      : 'text-cyan-400 [.light_&]:text-cyan-600'
                }`}>
                  ● {zone.status}
                </span>
              </div>
            </div>

          </div>
        ))}
      </div>

      {/* PIED DE COMPOSANT */}
      <div className="border-t border-slate-900 [.light_&]:border-slate-200 pt-3.5 flex items-center justify-between text-xs text-slate-400 [.light_&]:text-slate-600 z-10 bg-[#0f172a] [.light_&]:bg-white">
        <div className="flex gap-5">
          <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_6px_#ef4444]"></span> Critical Target</div>
          <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-500 shadow-[0_0_6px_#f59e0b]"></span> Suspect Node</div>
        </div>
        <div className="text-xs text-slate-500 [.light_&]:text-slate-400 font-mono tracking-wider">
          GEO_FILTER: ACTIVE // REFRESH: 5s
        </div>
      </div>

    </div>
  );
}