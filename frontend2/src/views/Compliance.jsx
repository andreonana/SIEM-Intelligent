
export default function Compliance({ logs }) {
    const activeIncidentsCount = logs.filter((l) => l.escalated === true).length;
    const unresolvedCriticals = logs.filter((l) => l.severity === 'CRITICAL' && l.status !== 'TRAITÉ').length;

    const isoScore = Math.max(55, 94 - unresolvedCriticals * 5 - activeIncidentsCount * 2);
    const rgpdScore = Math.max(50, 91 - unresolvedCriticals * 6);
    const overallCompliance = Math.round((isoScore + rgpdScore) / 2);
    const openActions = Math.max(1, activeIncidentsCount + unresolvedCriticals);

    const dataViolations = logs.filter((log) =>
        log.service?.toLowerCase().includes('db') ||
        log.service?.toLowerCase().includes('auth') ||
        log.event?.toLowerCase().includes('exfiltration') ||
        log.event?.toLowerCase().includes('sql') ||
        log.event?.toLowerCase().includes('privilège')
    );

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="flex flex-col gap-4 border-b border-slate-800 pb-5 md:flex-row md:items-center md:justify-between">
                <div>
                    <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.3em] text-cyan-400">
                        <span className="h-2 w-2 rounded-full bg-cyan-500 shadow-[0_0_8px_rgba(6,182,212,0.4)]"></span>
                        <span>Regulatory compliance & audit assurance</span>
                    </div>
                    <h1 className="text-3xl font-black text-white">Compliance Dashboard</h1>
                    <p className="mt-1 text-sm text-slate-400">
                        Live insight into control coverage, privacy obligations, and remediation pressure.
                    </p>
                </div>
                <div className="rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3 text-sm text-slate-400 shadow-lg">
                    Legal retention
                    <span className="ml-2 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 font-semibold text-emerald-400">
                        60 days • OK
                    </span>
                </div>
            </div>

            <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
                <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-400">Overall posture</p>
                            <p className="mt-2 text-4xl font-black text-white">{overallCompliance}%</p>
                        </div>
                        <div className="rounded-2xl border border-cyan-500/20 bg-cyan-500/10 px-3 py-2 text-sm font-semibold text-cyan-300">
                            {activeIncidentsCount === 0 ? 'Stable' : 'Watchlist'}
                        </div>
                    </div>
                    <div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-950">
                        <div className="h-full rounded-full bg-cyan-500 transition-all duration-700" style={{ width: `${overallCompliance}%` }}></div>
                    </div>
                    <div className="mt-4 grid gap-3 sm:grid-cols-3">
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                            <p className="text-[11px] uppercase tracking-[0.25em] text-slate-500">ISO</p>
                            <p className="mt-1 text-xl font-bold text-white">{isoScore}%</p>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                            <p className="text-[11px] uppercase tracking-[0.25em] text-slate-500">GDPR</p>
                            <p className="mt-1 text-xl font-bold text-white">{rgpdScore}%</p>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                            <p className="text-[11px] uppercase tracking-[0.25em] text-slate-500">Open actions</p>
                            <p className="mt-1 text-xl font-bold text-white">{openActions}</p>
                        </div>
                    </div>
                </div>

                <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
                    <p className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-400">Audit readiness</p>
                    <div className="mt-4 space-y-3">
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                            <div className="flex items-center justify-between">
                                <span className="text-sm text-slate-300">Evidence package</span>
                                <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-[11px] font-semibold text-emerald-400">Ready</span>
                            </div>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                            <div className="flex items-center justify-between">
                                <span className="text-sm text-slate-300">Log integrity</span>
                                <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2 py-1 text-[11px] font-semibold text-cyan-400">Valid</span>
                            </div>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                            <div className="flex items-center justify-between">
                                <span className="text-sm text-slate-300">Next review</span>
                                <span className="text-sm font-semibold text-white">Within 7 days</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
                <div className="space-y-6">
                    <div className="grid gap-6 md:grid-cols-2">
                        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
                            <div className="flex items-center justify-between">
                                <h3 className="text-sm font-semibold uppercase tracking-[0.25em] text-cyan-400">ISO 27001</h3>
                                <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2 py-1 text-[10px] font-semibold text-cyan-300">Control map</span>
                            </div>
                            <div className="mt-4 space-y-3">
                                <div className="h-2 overflow-hidden rounded-full bg-slate-950">
                                    <div className="h-full rounded-full bg-cyan-500" style={{ width: `${isoScore}%` }}></div>
                                </div>
                                <p className="text-sm text-slate-400">
                                    Logging, access governance, incident handling, and business continuity coverage remain strong.
                                </p>
                            </div>
                        </div>

                        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
                            <div className="flex items-center justify-between">
                                <h3 className="text-sm font-semibold uppercase tracking-[0.25em] text-purple-400">GDPR</h3>
                                <span className="rounded-full border border-purple-500/20 bg-purple-500/10 px-2 py-1 text-[10px] font-semibold text-purple-300">Privacy ops</span>
                            </div>
                            <div className="mt-4 space-y-3">
                                <div className="h-2 overflow-hidden rounded-full bg-slate-950">
                                    <div className="h-full rounded-full bg-purple-500" style={{ width: `${rgpdScore}%` }}></div>
                                </div>
                                <p className="text-sm text-slate-400">
                                    Data minimization, retention handling, and breach response coordination are aligned with policy.
                                </p>
                            </div>
                        </div>
                    </div>

                    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
                        <div className="flex items-center justify-between">
                            <h3 className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-300">Data protection incidents</h3>
                            <span className="rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-1 text-[10px] font-semibold text-amber-400">Art. 33 tracking</span>
                        </div>
                        <div className="mt-4 space-y-3">
                            {dataViolations.length === 0 ? (
                                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-500">
                                    No active incidents currently affect personal data workflows.
                                </div>
                            ) : (
                                dataViolations.map((violation) => (
                                    <div key={violation.id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                                        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                                            <div>
                                                <div className="flex items-center gap-2">
                                                    <span className={`h-2.5 w-2.5 rounded-full ${violation.status === 'TRAITÉ' ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
                                                    <span className="text-sm font-semibold text-white">{violation.id}</span>
                                                    <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-cyan-400">
                                                        {violation.service}
                                                    </span>
                                                </div>
                                                <p className="mt-2 text-sm text-slate-400">{violation.event}</p>
                                            </div>
                                            <div className="flex items-center gap-3">
                                                <span className={`rounded-full px-2.5 py-1 text-[10px] font-semibold ${violation.status === 'TRAITÉ' ? 'border border-emerald-500/20 bg-emerald-500/10 text-emerald-400' : 'border border-red-500/20 bg-red-500/10 text-red-400'}`}>
                                                    {violation.status === 'TRAITÉ' ? 'Risk cleared' : 'Action required'}
                                                </span>
                                                <span className="text-xs text-slate-500">{violation.timestamp}</span>
                                            </div>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                </div>

                <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
                    <h3 className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-300">Control coverage</h3>
                    <div className="mt-4 space-y-3">
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                            <div className="flex items-start justify-between gap-3">
                                <div>
                                    <p className="font-semibold text-slate-200">A.12.4.1 — Event logging</p>
                                    <p className="mt-1 text-sm text-slate-400">Continuous capture of user activity, access events, and SOC alerts.</p>
                                </div>
                                <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-[10px] font-semibold text-emerald-400">Compliant</span>
                            </div>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                            <div className="flex items-start justify-between gap-3">
                                <div>
                                    <p className="font-semibold text-slate-200">A.12.4.2 — Log protection</p>
                                    <p className="mt-1 text-sm text-slate-400">Protection against tampering and unauthorized changes to audit trails.</p>
                                </div>
                                <span className="rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-1 text-[10px] font-semibold text-amber-400">Needs review</span>
                            </div>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                            <div className="flex items-start justify-between gap-3">
                                <div>
                                    <p className="font-semibold text-slate-200">A.9.1.1 — Access control</p>
                                    <p className="mt-1 text-sm text-slate-400">Role-based access and segmentation maintain least-privilege principles.</p>
                                </div>
                                <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-[10px] font-semibold text-emerald-400">Compliant</span>
                            </div>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                            <div className="flex items-start justify-between gap-3">
                                <div>
                                    <p className="font-semibold text-slate-200">Art. 30 — Processing register</p>
                                    <p className="mt-1 text-sm text-slate-400">Data inventory and processing mapping remain current for audit evidence.</p>
                                </div>
                                <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-[10px] font-semibold text-emerald-400">Up to date</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}