import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import LogExplorer from '../views/LogExplorer.jsx';
import { searchLogs, exportLogsCsv, exportLogsXlsx } from '../services/api';

vi.mock('../services/api', () => ({
    searchLogs: vi.fn(),
    exportLogsCsv: vi.fn(),
    exportLogsXlsx: vi.fn(),
}));

const SAMPLE_RESULT = {
    id: 'log-1',
    timestamp: '2026-07-01T12:00:00Z',
    source_ip: '198.51.100.77',
    host: 'web-srv-01',
    log_type: 'auth',
    severity: 'critical',
    raw_message: 'Failed password for root from 198.51.100.77',
};

describe('LogExplorer (recherche S2 Data)', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        searchLogs.mockResolvedValue({ total: 1, page: 1, page_size: 25, results: [SAMPLE_RESULT] });
    });

    it('lance une recherche backend au montage et affiche les résultats horodatés', async () => {
        render(<LogExplorer user={{ name: 'admin' }} />);

        await waitFor(() => expect(searchLogs).toHaveBeenCalled());
        expect((await screen.findAllByText(/198.51.100.77/)).length).toBeGreaterThan(0);
        expect(screen.getByText(/2026-07-01 12:00:00/)).toBeInTheDocument();
        expect(screen.getByText('web-srv-01')).toBeInTheDocument();
    });

    it('affiche un état vide honnête quand aucun résultat ne correspond', async () => {
        searchLogs.mockResolvedValue({ total: 0, page: 1, page_size: 25, results: [] });
        render(<LogExplorer user={{ name: 'admin' }} />);

        expect(await screen.findByText(/Aucun log ne correspond aux critères/)).toBeInTheDocument();
    });

    it('affiche une bannière d\'erreur honnête si le backend échoue', async () => {
        searchLogs.mockRejectedValue(new Error('Erreur de communication avec Elasticsearch'));
        render(<LogExplorer user={{ name: 'admin' }} />);

        expect(await screen.findByText(/Erreur de communication avec Elasticsearch/)).toBeInTheDocument();
    });

    it('soumet le formulaire avec les critères saisis (IP, sévérité, type de log)', async () => {
        render(<LogExplorer user={{ name: 'admin' }} />);
        await waitFor(() => expect(searchLogs).toHaveBeenCalledTimes(1));

        fireEvent.change(screen.getByPlaceholderText('198.51.100.77'), { target: { value: '10.0.0.5' } });
        fireEvent.click(screen.getByRole('button', { name: /Rechercher/ }));

        await waitFor(() => expect(searchLogs).toHaveBeenCalledTimes(2));
        expect(searchLogs).toHaveBeenLastCalledWith(expect.objectContaining({ source_ip: '10.0.0.5', page: 1 }));
    });

    it('le pivot "Investiguer cette IP" transmet bien source_ip au parent', async () => {
        const onInvestigate = vi.fn();
        render(<LogExplorer user={{ name: 'admin' }} onInvestigate={onInvestigate} />);

        const row = await screen.findByText(/Failed password for root/);
        fireEvent.click(row.closest('tr'));

        const investigateIpButton = await screen.findByRole('button', { name: /Investiguer cette IP/ });
        fireEvent.click(investigateIpButton);

        expect(onInvestigate).toHaveBeenCalledWith('198.51.100.77');
    });

    it('le pivot "Investiguer cet hôte" transmet bien host au parent', async () => {
        const onInvestigate = vi.fn();
        render(<LogExplorer user={{ name: 'admin' }} onInvestigate={onInvestigate} />);

        const row = await screen.findByText(/Failed password for root/);
        fireEvent.click(row.closest('tr'));

        const investigateHostButton = await screen.findByRole('button', { name: /Investiguer cet hôte/ });
        fireEvent.click(investigateHostButton);

        expect(onInvestigate).toHaveBeenCalledWith('web-srv-01');
    });

    it('exporte avec les critères actifs quand on clique sur CSV', async () => {
        render(<LogExplorer user={{ name: 'admin' }} />);
        await waitFor(() => expect(searchLogs).toHaveBeenCalledTimes(1));

        fireEvent.click(screen.getByRole('button', { name: /CSV/ }));
        await waitFor(() => expect(exportLogsCsv).toHaveBeenCalled());
    });
});
