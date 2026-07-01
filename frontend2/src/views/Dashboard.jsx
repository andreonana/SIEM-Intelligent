import { useState } from 'react';
import WorldAttackMap from '../components/WorldAttackMap';
import alertsData from '../mocks/alerts_mock.json';

export default function Dashboard({ user }) {
  const [timePeriod, setTimePeriod] = useState('24h');

  const totalLogs = 142840;
  const criticalCount = alertsData.filter(a => a.severity === 'CRITICAL').length;
  const warningCount = alertsData.filter(a => a.severity === 'WARNING').length;
  const infoCount = alertsData.filter(a => a.severity === 'INFO' || a.status === 'FAUX_POSITIF').length;
  const totalAlerts = criticalCount + warningCount + infoCount || 1;

  const pctCritical = Math.round((criticalCount / totalAlerts) * 100);
  const pctWarning = Math.round((warningCount / totalAlerts) * 100);
  const pctInfo = Math.round((infoCount / totalAlerts) * 100);

  return (
    <div className="space-y-6 text-slate-200 overflow-y-auto max-h-[85vh] pr-2 animate-in fade-in duration-300">
      
      {/* 1. LIVE STATUS BAR */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 p-4 rounded-2xl border border-white/10 bg-gradient-to-r from-slate-900/80 to-slate-950/50 shadow-lg">
        <div className="flex items-center gap-4">
          <div className="flex flex-col">
            <p className="text-xs font-semibold uppercase tracking-[0.3em] text-slate-400">Regional Threat Level</p>
            <div className="flex items-center gap-2 mt-1">
              <span className="relative flex h-3 w-3 items-center justify-center">
                <span className="absolute inline-flex h-full w-full animate-pulse rounded-full bg-amber-500/80"></span>
                <span className="relative inline-flex h-2 w-2 rounded-full bg-amber-400"></span>
              </span>
              <span className="text-lg font-black text-amber-400">ELEVATED</span>
            </div>
          </div>
          <div className="border-l border-slate-700/50 pl-4 flex flex-col">
            <p className="text-xs font-semibold uppercase tracking-[0.3em] text-slate-400">Monitoring Health</p>
            <span className="text-lg font-black text-emerald-400 mt-1">94.2%</span>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span className="inline-flex gap-1 px-2 py-1 rounded-full bg-slate-800/50 border border-slate-700/50">
            <span className="relative flex h-2 w-2 items-center justify-center mt-0.5">
              <span className="absolute inline-flex h-full w-full animate-pulse rounded-full bg-green-500/80"></span>
              <span className="relative inline-flex h-1 w-1 rounded-full bg-green-400"></span>
            </span>
            Monitoring active
          </span>
        </div>
      </div>

      {/* 2. HEADER WITH TIME FILTER */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-3xl font-black text-white tracking-tight">Regional SOC Command Center</h2>
          <p className="text-sm text-slate-400 mt-2">
            Operator: <strong className="text-emerald-400">{user?.name || "Chloe O'Brian"}</strong> • Cameroon and Africa telemetry monitored across {totalLogs.toLocaleString()} events
          </p>
        </div>
        
        <div className="flex bg-slate-900/80 p-1 rounded-xl border border-slate-800/60 text-xs shadow-lg gap-1">
          {['1h', '6h', '24h', '7d'].map((period) => (
            <button
              key={period}
              onClick={() => setTimePeriod(period)}
              className={`px-4 py-2 rounded-lg font-semibold uppercase tracking-wider transition-all ${
                timePeriod === period 
                  ? 'bg-gradient-to-r from-emerald-500 to-cyan-500 text-white shadow-lg' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              {period}
            </button>
          ))}
        </div>
      </div>

      {/* 3. KPI CARDS WITH TREND INDICATORS */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-2xl border border-white/10 bg-gradient-to-br from-blue-500/10 to-cyan-500/5 p-5 shadow-lg hover:border-blue-500/30 transition-all">
          <div className="flex items-start justify-between mb-3">
            <span className="text-xs font-semibold uppercase tracking-[0.3em] text-slate-400">Total Events</span>
            <span className="inline-flex px-2 py-1 rounded-lg text-xs font-bold text-green-400 bg-green-500/10 border border-green-500/20">↑ 12%</span>
          </div>
          <div className="text-4xl font-black text-blue-400">{totalLogs.toLocaleString()}</div>
          <p className="text-xs text-slate-400 mt-3">Last 24 hours ingestion rate</p>
        </div>
        
        <div className="rounded-2xl border border-white/10 bg-gradient-to-br from-red-500/10 to-pink-500/5 p-5 shadow-lg hover:border-red-500/30 transition-all">
          <div className="flex items-start justify-between mb-3">
            <span className="text-xs font-semibold uppercase tracking-[0.3em] text-slate-400">Critical Alerts</span>
            <span className="inline-flex px-2 py-1 rounded-lg text-xs font-bold text-red-400 bg-red-500/10 border border-red-500/20 animate-pulse">↑ 28%</span>
          </div>
          <div className="text-4xl font-black text-red-400">{criticalCount}</div>
          <p className="text-xs text-red-400/80 font-semibold mt-3">Immediate action required</p>
        </div>
        
        <div className="rounded-2xl border border-white/10 bg-gradient-to-br from-amber-500/10 to-orange-500/5 p-5 shadow-lg hover:border-amber-500/30 transition-all">
          <div className="flex items-start justify-between mb-3">
            <span className="text-xs font-semibold uppercase tracking-[0.3em] text-slate-400">Open Incidents</span>
            <span className="inline-flex px-2 py-1 rounded-lg text-xs font-bold text-amber-400 bg-amber-500/10 border border-amber-500/20">↓ 5%</span>
          </div>
          <div className="text-4xl font-black text-amber-400">
            {alertsData.filter(a => a.escalated === true).length}
          </div>
          <p className="text-xs text-slate-400 mt-3">In crisis room investigation</p>
        </div>
        
        <div className="rounded-2xl border border-white/10 bg-gradient-to-br from-emerald-500/10 to-green-500/5 p-5 shadow-lg hover:border-emerald-500/30 transition-all">
          <div className="flex items-start justify-between mb-3">
            <span className="text-xs font-semibold uppercase tracking-[0.3em] text-slate-400">Resolved</span>
            <span className="inline-flex px-2 py-1 rounded-lg text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20">↑ 18%</span>
          </div>
          <div className="text-4xl font-black text-emerald-400">
            {alertsData.filter(a => a.status === 'TRAITÉ').length}
          </div>
          <p className="text-xs text-slate-400 mt-3">Automated remediation executed</p>
        </div>
      </div>

      {/* 4. MAIN ANALYTICS SECTION */}
      <div className="w-full">
        <WorldAttackMap />
      </div>

      {/* 5. ANALYTICS CHARTS */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* SEVERITY DISTRIBUTION */}
        <div className="rounded-2xl border border-white/10 bg-slate-900/60 p-5 shadow-lg">
          <h3 className="text-xs font-black text-slate-100 uppercase tracking-[0.3em] mb-4 pb-3 border-b border-slate-700/50">Alert Severity</h3>
          <span className="text-xs text-slate-400 block mb-6">Distribution of detected threats</span>

          <div className="flex items-center justify-center mb-6 gap-8">
            <div 
              style={{
                background: `conic-gradient(
                  #ef4444 0% ${pctCritical}%, 
                  #f59e0b ${pctCritical}% ${pctCritical + pctWarning}%, 
                  #3b82f6 ${pctCritical + pctWarning}% 100%
                )`
              }}
              className="w-32 h-32 rounded-full shadow-lg flex items-center justify-center border border-slate-700/50"
            >
              <div className="w-20 h-20 rounded-full bg-slate-900 flex flex-col items-center justify-center shadow-inner">
                <span className="text-[10px] text-slate-500 font-semibold uppercase">Total</span>
                <span className="text-base font-black text-white">{totalAlerts}</span>
              </div>
            </div>

            {/* LEGEND */}
            <div className="space-y-3 text-xs">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-red-500"></span>
                <div>
                  <span className="text-slate-400 font-semibold block">Critical</span>
                  <strong className="text-red-400 text-sm">{pctCritical}%</strong>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-amber-500"></span>
                <div>
                  <span className="text-slate-400 font-semibold block">Warning</span>
                  <strong className="text-amber-400 text-sm">{pctWarning}%</strong>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-blue-500"></span>
                <div>
                  <span className="text-slate-400 font-semibold block">Info</span>
                  <strong className="text-blue-400 text-sm">{pctInfo}%</strong>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* TIMELINE CHART */}
        <div className="lg:col-span-2 rounded-2xl border border-white/10 bg-slate-900/60 p-5 shadow-lg">
          <h3 className="text-xs font-black text-slate-100 uppercase tracking-[0.3em] mb-4 pb-3 border-b border-slate-700/50">Attack Timeline</h3>
          <span className="text-xs text-slate-400 block mb-6">Threat activity across 24-hour period</span>

          <div className="flex-1 flex items-end justify-between gap-2 px-2 pb-4">
            {[
              { time: '00h', value: 12, label: 'Nominal' },
              { time: '04h', value: 45, label: 'DDoS' },
              { time: '08h', value: 18, label: 'Mixed' },
              { time: '12h', value: 9, label: 'Low' },
              { time: '16h', value: 15, label: 'Nominal' },
              { time: '20h', value: 22, label: 'Moderate' }
            ].map((bar, idx) => (
              <div key={idx} className="flex-1 flex flex-col items-center gap-2 group">
                <span className="text-xs font-bold text-slate-100 opacity-0 group-hover:opacity-100 transition-all duration-200">{bar.value}k</span>
                <div className="w-full bg-slate-800/40 rounded-t-xl overflow-hidden transition-all group-hover:bg-slate-700/60 border border-transparent group-hover:border-emerald-500/30">
                  <div 
                    className="w-full bg-gradient-to-t from-emerald-500 to-cyan-500 rounded-t-xl shadow-lg shadow-emerald-500/20"
                    style={{ height: `${(bar.value / 45) * 140}px` }}
                  />
                </div>
                <span className="text-[10px] text-slate-400 font-semibold">{bar.time}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      
    </div>
  );
}