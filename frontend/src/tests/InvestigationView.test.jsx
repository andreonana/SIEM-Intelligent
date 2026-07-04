import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import InvestigationView from '../views/InvestigationView';
import { getInvestigation, getInvestigationFlags, flagInvestigation } from '../services/api';

vi.mock('../services/api', () => ({
    getInvestigation: vi.fn(),
    getInvestigationFlags: vi.fn(),
    flagInvestigation: vi.fn(),
}));

const TIMELINE = [
    { id: 'e1', timestamp: '2026-07-01T10:00:00Z', source_ip: '198.51.100.77', host: 'web-srv', log_type: 'auth', severity: 'critical', raw_message: 'Failed password for root' },
    { id: 'e2', timestamp: '2026-07-01T10:05:00Z', source_ip: '198.51.100.77', host: 'web-srv', log_type: 'auth', severity: 'warning', raw_message: 'Accepted publickey for root' },
];

describe('InvestigationView (timeline S2 Data)', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        getInvestigation.mockResolvedValue({ entity_id: '198.51.100.77', timeline: TIMELINE });
        getInvestigationFlags.mockResolvedValue([]);
    });

    it("appelle GET /api/investigation/{entity_id} et affiche la chronologie horodatée", async () => {
        render(<InvestigationView user={{ name: 'admin' }} />);

        fireEvent.change(screen.getByPlaceholderText(/IP source ou hôte/), { target: { value: '198.51.100.77' } });
        fireEvent.click(screen.getByRole('button', { name: /^Investiguer$/ }));

        await waitFor(() => expect(getInvestigation).toHaveBeenCalledWith('198.51.100.77'));
        expect(await screen.findByText('2026-07-01 10:00:00')).toBeInTheDocument();
        expect(screen.getByText('Failed password for root')).toBeInTheDocument();
        expect(screen.getByText('2 événement(s)')).toBeInTheDocument();
    });

    it('charge automatiquement la timeline quand initialEntityId est fourni (pivot depuis la recherche)', async () => {
        render(<InvestigationView user={{ name: 'admin' }} initialEntityId="198.51.100.77" />);

        await waitFor(() => expect(getInvestigation).toHaveBeenCalledWith('198.51.100.77'));
        expect(await screen.findByText('Failed password for root')).toBeInTheDocument();
    });

    it('affiche un état vide honnête tant qu\'aucune entité n\'est chargée', () => {
        render(<InvestigationView user={{ name: 'admin' }} />);
        expect(screen.getByText(/Saisissez une entité/)).toBeInTheDocument();
    });

    it("affiche une erreur honnête si l'investigation échoue", async () => {
        getInvestigation.mockRejectedValue(new Error("Erreur de communication avec Elasticsearch"));
        render(<InvestigationView user={{ name: 'admin' }} />);

        fireEvent.change(screen.getByPlaceholderText(/IP source ou hôte/), { target: { value: '198.51.100.77' } });
        fireEvent.click(screen.getByRole('button', { name: /^Investiguer$/ }));

        expect(await screen.findByText(/Erreur de communication avec Elasticsearch/)).toBeInTheDocument();
    });

    it('le bouton "Marquer suspect" appelle POST /api/investigation/{id}/flag', async () => {
        flagInvestigation.mockResolvedValue({ status: 'flagged' });
        vi.spyOn(window, 'prompt').mockReturnValue('Comportement suspect confirmé');

        render(<InvestigationView user={{ name: 'admin' }} initialEntityId="198.51.100.77" />);
        await waitFor(() => expect(getInvestigation).toHaveBeenCalled());

        fireEvent.click(await screen.findByRole('button', { name: /Marquer suspect/ }));

        await waitFor(() => expect(flagInvestigation).toHaveBeenCalledWith('198.51.100.77', 'Comportement suspect confirmé'));
    });

    it('clic sur un événement de la chronologie affiche son détail', async () => {
        render(<InvestigationView user={{ name: 'admin' }} initialEntityId="198.51.100.77" />);
        await waitFor(() => expect(getInvestigation).toHaveBeenCalled());

        fireEvent.click(await screen.findByText('Accepted publickey for root'));
        expect(screen.getByText("Détail de l'événement")).toBeInTheDocument();
    });
});
