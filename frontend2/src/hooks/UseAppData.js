// ============================================================
// useAppData.js — Fetches all app data from API
// Falls back to mock data if API is not available
// Used by App.jsx to feed data down to all pages
// ============================================================

import { useState, useEffect } from 'react';
import { getAlerts } from '../services/alertService';
import { getLogs, getDashboardStats } from '../services/logService';
import { isLoggedIn } from '../services/authService';

// Mock fallbacks — keep working during demo if API is down
import alertsMock from '../mocks/alerts_mock.json';
import logsMock   from '../mocks/logs_mock.json';

export function useAppData() {
  const [logs,         setLogs]         = useState(logsMock);
  const [alerts,       setAlerts]       = useState(alertsMock);
  const [dashStats,    setDashStats]    = useState(null);
  const [loading,      setLoading]      = useState(false);
  const [apiConnected, setApiConnected] = useState(false);

  useEffect(() => {
    // Only fetch if user is logged in
    if (!isLoggedIn()) return;

    const fetchAll = async () => {
      setLoading(true);

      // ── Try to get real alerts ────────────────────────
      try {
        const realAlerts = await getAlerts({ limit: 100 });
        if (realAlerts && realAlerts.length > 0) {
          // Map API fields to what the pages expect
          const mapped = realAlerts.map(a => ({
            id:                  a.alert_id || a.id,
            timestamp:           a.detected_at,
            source:              a.source_ip  || a.source,
            service:             a.rule_name  || a.service,
            event:               a.description,
            severity:            a.severity,
            status:              a.status === 'ouvert' ? 'NON_TRAITE' : a.status,
            escalated:           a.status === 'ESCALADE',
            payload:             a.description,
            // MITRE fields — from backend security integration
            mitre_tactic_id:     a.mitre_tactic_id,
            mitre_tactic_name:   a.mitre_tactic_name,
            mitre_technique_id:  a.mitre_technique_id,
            mitre_technique_name: a.mitre_technique_name,
          }));
          setAlerts(mapped);
          setApiConnected(true);
        }
      } catch  {
        // API not available — keep mock alerts
        console.log('[SIEM] Using mock alerts (API not reachable)');
      }

      // ── Try to get real logs ──────────────────────────
      try {
        const realLogs = await getLogs({ limit: 200 });
        if (realLogs && realLogs.length > 0) {
          const mapped = realLogs.map(l => ({
            id:          l.id || l._id,
            timestamp:   l.timestamp,
            source:      l.source_ip,
            destination: l.destination_ip || null,
            service:     l.log_type,
            event:       l.raw_message,
            severity:    l.severity?.toUpperCase(),
            status:      'NON_TRAITE',
            escalated:   false,
            payload:     l.raw_message,
          }));
          setLogs(mapped);
          setApiConnected(true);
        }
      } catch  {
        console.log('[SIEM] Using mock logs (API not reachable)');
      }

      // ── Try to get dashboard stats ────────────────────
      try {
        const stats = await getDashboardStats();
        if (stats) setDashStats(stats);
      } catch  {
        // Keep null — Dashboard computes its own from logs
      }

      setLoading(false);
    };

    fetchAll();

    // Refresh every 30 seconds when connected to real API
    const interval = setInterval(fetchAll, 30000);
    return () => clearInterval(interval);
  }, []);

  return {
    logs,
    setLogs,
    alerts,
    setAlerts,
    dashStats,
    loading,
    apiConnected,
  };
}
