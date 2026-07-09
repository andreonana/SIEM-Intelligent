import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import useSearch from '../hooks/useSearch';
import { searchLogs } from '../services/api';

vi.mock('../services/api', () => ({
    searchLogs: vi.fn(),
}));

describe('useSearch', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('appelle POST /api/search (via searchLogs) avec les bons critères', async () => {
        searchLogs.mockResolvedValue({ total: 1, page: 1, page_size: 25, results: [{ id: '1', source_ip: '198.51.100.77' }] });

        const { result } = renderHook(() => useSearch());

        act(() => {
            result.current.updateCriteria({
                source_ip: '198.51.100.77',
                username: 'root',
                log_type: 'auth',
                severity: 'critical',
                start_date: '2026-01-01T00:00:00.000Z',
                end_date: '2026-01-02T00:00:00.000Z',
            });
        });

        await act(async () => {
            await result.current.runSearch(1);
        });

        expect(searchLogs).toHaveBeenCalledWith({
            page: 1,
            page_size: 25,
            source_ip: '198.51.100.77',
            username: 'root',
            log_type: 'auth',
            severity: 'critical',
            start_date: '2026-01-01T00:00:00.000Z',
            end_date: '2026-01-02T00:00:00.000Z',
        });
    });

    it("n'envoie pas les critères vides", async () => {
        searchLogs.mockResolvedValue({ total: 0, page: 1, page_size: 25, results: [] });
        const { result } = renderHook(() => useSearch());

        await act(async () => {
            await result.current.runSearch(1);
        });

        expect(searchLogs).toHaveBeenCalledWith({ page: 1, page_size: 25 });
    });

    it('expose les résultats et le total après une recherche réussie', async () => {
        searchLogs.mockResolvedValue({
            total: 2,
            page: 1,
            page_size: 25,
            results: [{ id: 'a', timestamp: '2026-01-01T00:00:00Z' }, { id: 'b', timestamp: '2026-01-02T00:00:00Z' }],
        });
        const { result } = renderHook(() => useSearch());

        await act(async () => {
            await result.current.runSearch(1);
        });

        await waitFor(() => expect(result.current.status).toBe('ready'));
        expect(result.current.total).toBe(2);
        expect(result.current.results).toHaveLength(2);
    });

    it('passe en état error si le backend échoue', async () => {
        searchLogs.mockRejectedValue(new Error('Erreur de communication avec Elasticsearch'));
        const { result } = renderHook(() => useSearch());

        await act(async () => {
            await result.current.runSearch(1);
        });

        expect(result.current.status).toBe('error');
        expect(result.current.error).toMatch(/Elasticsearch/);
    });

    it('calcule correctement totalPages et navigue via goToPage', async () => {
        searchLogs.mockResolvedValue({ total: 60, page: 1, page_size: 25, results: [] });
        const { result } = renderHook(() => useSearch());

        await act(async () => {
            await result.current.runSearch(1);
        });
        await waitFor(() => expect(result.current.totalPages).toBe(3));

        searchLogs.mockResolvedValue({ total: 60, page: 2, page_size: 25, results: [] });
        await act(async () => {
            result.current.goToPage(2);
        });
        await waitFor(() => expect(result.current.page).toBe(2));
    });
});
