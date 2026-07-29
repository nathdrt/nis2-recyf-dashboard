#!/usr/bin/env python3
"""
Connecteur Wazuh — Récupère la liste des agents et leur statut via l'API REST.
Utilise un compte dédié en lecture seule (rôle agents_readonly).
Aucun secret en dur : tout via .env.
"""

import json
import os
import sys
import urllib3
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

# L'API Wazuh utilise un certificat TLS auto-signé — on désactive les warnings
# plutôt que d'exposer la clé privée de l'AC dans le dépôt.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

WAZUH_URL   = os.getenv("WAZUH_URL", "").rstrip("/")
WAZUH_USER  = os.getenv("WAZUH_USER", "")
WAZUH_PASS  = os.getenv("WAZUH_PASSWORD", "")
OUTPUT_FILE = os.getenv("WAZUH_OUTPUT_FILE", "agents_wazuh.json")

# Wazuh pagine à 500 par défaut — on demande jusqu'à 10 000 pour les grands parcs
MAX_AGENTS = 10000


def check_config():
    missing = [v for v in ["WAZUH_URL", "WAZUH_USER", "WAZUH_PASSWORD"]
               if not os.getenv(v)]
    if missing:
        print(f"Erreur : variables manquantes dans .env : {', '.join(missing)}")
        sys.exit(1)


def get_token() -> str:
    """Authentifie avec login/mot de passe et retourne un JWT valable 15 min."""
    resp = requests.get(
        f"{WAZUH_URL}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False,
        timeout=10,
    )
    if resp.status_code == 401:
        print("Erreur : identifiants refusés. Vérifie WAZUH_USER et WAZUH_PASSWORD dans .env.")
        sys.exit(1)
    resp.raise_for_status()
    return resp.json()["data"]["token"]


def get_agents(token: str) -> list:
    """Récupère tous les agents enregistrés avec leur statut."""
    resp = requests.get(
        f"{WAZUH_URL}/agents",
        headers={"Authorization": f"Bearer {token}"},
        params={
            "limit": MAX_AGENTS,
            "offset": 0,
            # On exclut le manager lui-même (id=000) qui n'est pas un vrai agent
            "q": "id!=000",
        },
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})
    agents = data.get("affected_items", [])
    total = data.get("total_affected_items", len(agents))
    if total > MAX_AGENTS:
        print(f"Avertissement : {total} agents trouvés, seuls les {MAX_AGENTS} premiers sont récupérés.")
    return agents


def format_agent(raw: dict) -> dict:
    """Extrait les champs utiles pour la conformité NIS2/ReCyF."""
    return {
        "id": raw.get("id"),
        "nom": raw.get("name"),
        "ip": raw.get("ip"),
        "statut": raw.get("status"),          # active / disconnected / never_connected / pending
        "version_agent": raw.get("version"),
        "os_plateforme": raw.get("os", {}).get("platform"),
        "os_version": raw.get("os", {}).get("version"),
        "os_nom": raw.get("os", {}).get("name"),
        "derniere_connexion": raw.get("lastKeepAlive"),
        "date_enregistrement": raw.get("dateAdd"),
        "groupe": raw.get("group", []),
        "manager": raw.get("manager"),
        "node": raw.get("node_name"),
    }


def main():
    check_config()
    print(f"Connexion à {WAZUH_URL}...")

    token = get_token()
    print("Token JWT obtenu.")

    raw_agents = get_agents(token)
    agents = [format_agent(a) for a in raw_agents]

    # Comptage par statut pour un résumé rapide
    par_statut: dict[str, int] = {}
    for a in agents:
        s = a["statut"] or "inconnu"
        par_statut[s] = par_statut.get(s, 0) + 1

    print(f"{len(agents)} agent(s) trouvé(s) : {par_statut}")

    output = {
        "source": "Wazuh",
        "url": WAZUH_URL,
        "date_extraction": datetime.now(timezone.utc).isoformat(),
        "nombre_agents": len(agents),
        "resume_statuts": par_statut,
        "agents": agents,
    }

    Path(OUTPUT_FILE).write_text(
        json.dumps(output, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Données sauvegardées dans {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
