#!/usr/bin/env python3
"""
Test de connexion réel par type de connecteur — réutilise uniquement la
logique d'authentification déjà présente dans connecteur_glpi.py,
connecteur_wazuh.py, connecteur_wazuh_alertes.py et connecteur_openvas.py
(auth seule, sans récupération complète des données).
"""

import os
import subprocess
import tempfile
import time
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Chemin du socket gvmd sur la VM openvas — spécifique à ce déploiement Greenbone
# (docker-compose community edition, voir NOTES_OPENVAS.md). Le schéma openvas ne
# définit que ssh_host/gmp_user/gmp_password (pas ce chemin) : c'est une limite
# connue de ce jalon, à signaler si une autre instance Greenbone doit être ajoutée.
OPENVAS_SOCKET_REMOTE = "/var/lib/docker/volumes/greenbone-community-edition_gvmd_socket_vol/_data/gvmd.sock"


def tester_glpi(config_publique: dict, secrets: dict) -> tuple[bool, str]:
    """Reprend la logique de connecteur_glpi.py : initSession puis killSession."""
    url = config_publique["url"].rstrip("/")
    app_token = secrets["app_token"]
    user_token = secrets["user_token"]
    try:
        resp = requests.get(
            f"{url}/apirest.php/initSession",
            headers={
                "App-Token": app_token,
                "Authorization": f"user_token {user_token}",
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        if resp.status_code == 400:
            body = resp.json() if resp.content else []
            return False, f"Erreur GLPI : {body}"
        resp.raise_for_status()
        session_token = resp.json()["session_token"]
        requests.get(
            f"{url}/apirest.php/killSession",
            headers={"App-Token": app_token, "Session-Token": session_token},
            timeout=10,
        )
        return True, "Authentification GLPI réussie (session ouverte puis fermée)."
    except requests.RequestException as e:
        return False, f"Erreur réseau : {e}"


def tester_wazuh_agents(config_publique: dict, secrets: dict) -> tuple[bool, str]:
    """Reprend la logique de connecteur_wazuh.py : get_token (authenticate)."""
    host = config_publique["host"]
    port = config_publique.get("port", 55000)
    user = config_publique["user"]
    password = secrets["password"]
    url = f"https://{host}:{port}"
    try:
        resp = requests.get(
            f"{url}/security/user/authenticate",
            auth=(user, password),
            verify=False,
            timeout=10,
        )
        if resp.status_code == 401:
            return False, "Identifiants refusés par Wazuh Manager."
        resp.raise_for_status()
        resp.json()["data"]["token"]
        return True, "Authentification Wazuh (agents) réussie, token obtenu."
    except requests.RequestException as e:
        return False, f"Erreur réseau : {e}"


def tester_wazuh_alertes(config_publique: dict, secrets: dict) -> tuple[bool, str]:
    """Authentification sur l'Indexer OpenSearch (même compte que
    connecteur_wazuh_alertes.py), requête minimale sans agrégation.

    L'Indexer n'écoute qu'en local sur la VM Wazuh : si ssh_host est
    renseigné, un tunnel SSH (port forward TCP classique, même principe que
    connecteur_wazuh_alertes.py) est ouvert puis refermé proprement.
    """
    host = config_publique["host"]
    port = config_publique.get("port", 9200)
    user = config_publique["user"]
    password = secrets["password"]
    ssh_host = config_publique.get("ssh_host") or ""

    if not ssh_host:
        return _tester_opensearch(f"https://{host}:{port}", user, password)

    local_port = 19200
    proc = subprocess.Popen(
        ["ssh", "-N", "-L", f"127.0.0.1:{local_port}:127.0.0.1:{port}", ssh_host],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(20):
            if proc.poll() is not None:
                return False, f"Tunnel SSH fermé prématurément (alias/hôte '{ssh_host}' invalide ?)."
            time.sleep(0.2)
            break  # laisser le temps au process de démarrer avant de tester le port
        time.sleep(1.0)
        return _tester_opensearch(f"https://127.0.0.1:{local_port}", user, password)
    finally:
        proc.terminate()
        proc.wait()


def _tester_opensearch(url: str, user: str, password: str) -> tuple[bool, str]:
    """
    Le compte readall n'a pas la permission cluster:monitor/main (endpoint
    racine "/" refusé en 403, vérifié en direct) — seule une recherche sur
    les indices wazuh-alerts-* est autorisée. On reprend donc exactement la
    requête de connecteur_wazuh_alertes.py (recherche à vide, size=0), pas
    un endpoint générique de santé du cluster.
    """
    try:
        resp = requests.post(
            f"{url}/wazuh-alerts-*/_search",
            auth=(user, password),
            json={"size": 0},
            verify=False,
            timeout=10,
        )
        if resp.status_code == 401:
            return False, "Identifiants OpenSearch refusés."
        if resp.status_code == 403:
            return False, "Accès interdit (droits insuffisants sur wazuh-alerts-*)."
        resp.raise_for_status()
        total = resp.json().get("hits", {}).get("total", {}).get("value", 0)
        return True, f"Authentification Wazuh (Indexer/alertes) réussie ({total} document(s) trouvés)."
    except requests.RequestException as e:
        return False, f"Erreur réseau : {e}"


def tester_openvas(config_publique: dict, secrets: dict) -> tuple[bool, str]:
    """Reprend la logique de connecteur_openvas.py : tunnel SSH Unix-vers-Unix
    (clé dédiée ~/.ssh/id_ed25519_openvas_dashboard du conteneur) puis
    authentification GMP avec le compte connecteur-api."""
    from gvm.connections import UnixSocketConnection
    from gvm.errors import GvmError
    from gvm.protocols.gmp import Gmp

    ssh_host = config_publique["ssh_host"]
    gmp_user = config_publique.get("gmp_user", "connecteur-api")
    gmp_password = secrets["gmp_password"]

    tmp_dir = tempfile.mkdtemp(prefix="gvmd_")
    local_socket = os.path.join(tmp_dir, "gvmd.sock")
    proc = subprocess.Popen(
        ["ssh", "-N", "-L", f"{local_socket}:{OPENVAS_SOCKET_REMOTE}", ssh_host],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(20):
            if os.path.exists(local_socket):
                break
            if proc.poll() is not None:
                return False, f"Tunnel SSH fermé prématurément (alias/hôte '{ssh_host}' invalide ?)."
            time.sleep(0.3)
        else:
            return False, "Timeout en attendant l'établissement du tunnel SSH."

        try:
            conn = UnixSocketConnection(path=local_socket)
            with Gmp(connection=conn) as gmp:
                gmp.authenticate(gmp_user, gmp_password)
            return True, "Authentification GMP réussie via le tunnel SSH."
        except GvmError as e:
            return False, f"Erreur GMP : {e}"
    finally:
        proc.terminate()
        proc.wait()
        Path(local_socket).unlink(missing_ok=True)
        try:
            os.rmdir(tmp_dir)
        except OSError:
            pass


TESTEURS = {
    "glpi": tester_glpi,
    "wazuh_agents": tester_wazuh_agents,
    "wazuh_alertes": tester_wazuh_alertes,
    "openvas": tester_openvas,
}


def tester_connecteur(type_: str, config_publique: dict, secrets: dict) -> tuple[bool, str]:
    testeur = TESTEURS.get(type_)
    if testeur is None:
        return False, f"Type de connecteur inconnu : {type_}"
    return testeur(config_publique, secrets)
