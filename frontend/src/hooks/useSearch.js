import { useCallback, useState } from 'react';
import { searchLogs } from '../services/api';

/**
 * Hook de recherche multi-critères — source de vérité : POST /api/search.
 * Gère les critères, le chargement, les erreurs, les résultats et la pagination.
 * Aucun filtrage local : chaque changement de critère ou de page relance un
 * vrai appel backend (le frontend n'est qu'un client de l'API réelle).
 */
export const DEFAULT_CRITERIA = {
  source_ip: '',
  host: '',
  username: '',
  log_type: '',
  severity: '',
  start_date: '',
  end_date: '',
};

const PAGE_SIZE = 25;

export default function useSearch() {
  const [criteria, setCriteria] = useState(DEFAULT_CRITERIA);
  const [results, setResults] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState('idle'); // idle | loading | ready | error
  const [error, setError] = useState(null);

  const runSearch = useCallback(async (targetPage = 1, overrideCriteria = null) => {
    const activeCriteria = overrideCriteria ?? criteria;
    setStatus('loading');
    setError(null);
    try {
      const payload = { page: targetPage, page_size: PAGE_SIZE };
      Object.entries(activeCriteria).forEach(([key, value]) => {
        if (value) payload[key] = value;
      });
      const data = await searchLogs(payload);
      setResults(data.results);
      setTotal(data.total);
      setPage(targetPage);
      setStatus('ready');
    } catch (err) {
      setError(err.message || 'La recherche a échoué.');
      setStatus('error');
    }
  }, [criteria]);

  const updateCriteria = useCallback((patch) => {
    setCriteria((prev) => ({ ...prev, ...patch }));
  }, []);

  const resetCriteria = useCallback(() => {
    setCriteria(DEFAULT_CRITERIA);
    setResults([]);
    setTotal(0);
    setPage(1);
    setStatus('idle');
  }, []);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const goToPage = useCallback((targetPage) => {
    if (targetPage < 1 || targetPage > totalPages) return;
    runSearch(targetPage);
  }, [runSearch, totalPages]);

  return {
    criteria,
    updateCriteria,
    resetCriteria,
    runSearch,
    goToPage,
    results,
    total,
    page,
    totalPages,
    pageSize: PAGE_SIZE,
    status,
    error,
  };
}
