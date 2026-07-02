# backend/tests/test_no_fake_data.py
#
# Tests de garde-fou : empêchent la réintroduction de données fictives,
# de mocks frontend ou de réponses backend mensongères sur des états
# de fonctionnalité (garantie demandée lors du nettoyage "no fake data").

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"
BACKEND_APP = REPO_ROOT / "backend" / "app"


def _read_text_files(base: Path, suffixes: tuple[str, ...]) -> list[tuple[Path, str]]:
    files = []
    for suffix in suffixes:
        for path in base.rglob(f"*{suffix}"):
            if "node_modules" in path.parts or "__pycache__" in path.parts:
                continue
            try:
                files.append((path, path.read_text(encoding="utf-8")))
            except UnicodeDecodeError:
                continue
    return files


def test_no_mocks_directory_in_frontend():
    """Le dossier frontend/src/mocks ne doit plus exister."""
    mocks_dir = FRONTEND_SRC / "mocks"
    assert not mocks_dir.exists(), (
        f"Le dossier {mocks_dir} existe encore — les données mock doivent être supprimées."
    )


def test_no_mock_imports_in_frontend():
    """Aucun fichier source frontend ne doit importer depuis un dossier mocks/."""
    offenders = []
    for path, content in _read_text_files(FRONTEND_SRC, (".jsx", ".js")):
        if re.search(r"""from\s+['"].*mocks/""", content):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, f"Imports de mocks détectés : {offenders}"


def test_no_misleading_simulated_status_in_backend():
    """
    Aucune route backend ne doit renvoyer un statut "simulated" présenté
    comme un succès trompeur. Les intégrations externes non configurées
    doivent renvoyer un statut honnête ("unavailable", "failure", etc.).
    """
    offenders = []
    for path, content in _read_text_files(BACKEND_APP, (".py",)):
        if re.search(r'"status"\s*:\s*"simulated"', content):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, f"Statut 'simulated' trompeur détecté : {offenders}"


def test_no_skeleton_placeholder_markers_in_routers():
    """
    Les routeurs API ne doivent plus contenir de marqueurs de squelette
    ("SQUELETTE", "à venir", "coming soon") signalant une fausse complétude.
    """
    routers_dir = BACKEND_APP / "api" / "v1" / "routers"
    offenders = []
    pattern = re.compile(r"squelette|à venir|coming soon|fonctionnalité à venir", re.IGNORECASE)
    for path, content in _read_text_files(routers_dir, (".py",)):
        if pattern.search(content):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, f"Marqueurs de squelette/placeholder détectés : {offenders}"


def test_block_ip_playbook_does_not_fake_success():
    """
    Le playbook block_ip doit persister un statut honnête ("failure") quand
    aucune intégration pare-feu réelle n'est configurée ou que le blocage
    échoue réellement, jamais un faux "success"/"simulated".
    """
    playbooks_path = BACKEND_APP / "modules" / "soar" / "playbooks.py"
    content = playbooks_path.read_text(encoding="utf-8")
    assert '"status": "failure"' in content, (
        "Le playbook block_ip doit exposer un état 'failure' honnête en cas d'échec."
    )
    assert '"status": "simulated"' not in content


def test_block_ip_reads_real_firewall_response_body():
    """
    Régression : block_ip ne doit jamais présumer un succès uniquement parce
    que l'appel HTTP au firewall a un code 2xx — il doit lire resp.json() et
    vérifier que le firewall confirme réellement le blocage.
    """
    playbooks_path = BACKEND_APP / "modules" / "soar" / "playbooks.py"
    content = playbooks_path.read_text(encoding="utf-8")
    assert "resp.json()" in content, (
        "block_ip doit lire le corps de la réponse du firewall, pas seulement son code HTTP."
    )
