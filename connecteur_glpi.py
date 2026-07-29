#!/usr/bin/env python3
"""
Connecteur GLPI — Récupère l'inventaire des ordinateurs via l'API REST GLPI.
Utilise un compte dédié en lecture seule. Aucun secret en dur : tout via .env.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

GLPI_URL = os.getenv("GLPI_URL", "").rstrip("/")
GLPI_APP_TOKEN = os.getenv("GLPI_APP_TOKEN", "")
GLPI_USER_TOKEN = os.getenv("GLPI_USER_TOKEN", "")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "inventaire.json")

# GLPI pagine à 50 par défaut — on demande jusqu'à 5000 pour couvrir les grands parcs
MAX_ITEMS = 5000


def check_config():
    missing = [v for v in ["GLPI_URL", "GLPI_APP_TOKEN", "GLPI_USER_TOKEN"] if not os.getenv(v)]
    if missing:
        print(f"Erreur : variables manquantes dans .env : {', '.join(missing)}")
        sys.exit(1)


def init_session() -> str:
    """Ouvre une session GLPI et retourne le session_token."""
    resp = requests.get(
        f"{GLPI_URL}/apirest.php/initSession",
        headers={
            "App-Token": GLPI_APP_TOKEN,
            "Authorization": f"user_token {GLPI_USER_TOKEN}",
            "Content-Type": "application/json",
        },
        timeout=10,
    )
    if resp.status_code == 400:
        body = resp.json() if resp.content else []
        print(f"Erreur GLPI : {body}")
        print("Conseil : vérifie que l'API REST est activée dans GLPI (Setup > General > API).")
        sys.exit(1)
    resp.raise_for_status()
    return resp.json()["session_token"]


def kill_session(session_token: str):
    """Ferme proprement la session GLPI."""
    requests.get(
        f"{GLPI_URL}/apirest.php/killSession",
        headers={"App-Token": GLPI_APP_TOKEN, "Session-Token": session_token},
        timeout=10,
    )


def get_computers(session_token: str) -> list:
    """Récupère la liste complète des ordinateurs (avec noms résolus)."""
    resp = requests.get(
        f"{GLPI_URL}/apirest.php/Computer",
        headers={
            "App-Token": GLPI_APP_TOKEN,
            "Session-Token": session_token,
            "Content-Type": "application/json",
        },
        params={
            "range": f"0-{MAX_ITEMS - 1}",
            "expand_dropdowns": True,   # Résout les IDs FK en noms lisibles
            "with_networkports": False,
        },
        timeout=30,
    )
    if resp.status_code == 206:
        print(f"Avertissement : le parc dépasse {MAX_ITEMS} machines, seules les premières sont récupérées.")
    if resp.status_code == 401:
        print("Erreur d'authentification. Vérifie GLPI_APP_TOKEN et GLPI_USER_TOKEN dans .env.")
        sys.exit(1)
    resp.raise_for_status()
    data = resp.json()
    # GLPI retourne parfois une liste, parfois un dict avec un message d'erreur
    if isinstance(data, dict) and "ERROR" in data:
        print(f"Erreur API GLPI : {data}")
        sys.exit(1)
    return data if isinstance(data, list) else []


def format_computer(raw: dict) -> dict:
    """Extrait les champs utiles pour l'inventaire NIS2/ReCyF."""
    return {
        "id": raw.get("id"),
        "nom": raw.get("name"),
        "numero_serie": raw.get("serial"),
        "uuid": raw.get("uuid"),
        "utilisateur": raw.get("users_id"),         # Résolu en nom si expand_dropdowns=True
        "localisation": raw.get("locations_id"),
        "etat": raw.get("states_id"),
        "fabricant": raw.get("manufacturers_id"),
        "type": raw.get("computertypes_id"),
        "systeme_exploitation": raw.get("operatingsystems_id"),
        "dernier_demarrage": raw.get("last_boot"),
        "date_creation": raw.get("date_creation"),
        "date_modification": raw.get("date_mod"),
        "commentaire": raw.get("comment"),
        "actif": not raw.get("is_deleted", False),
        "template": raw.get("is_template", False),
    }


def main():
    check_config()
    print(f"Connexion à {GLPI_URL}...")

    session_token = init_session()
    print("Session ouverte.")

    try:
        raw_computers = get_computers(session_token)
        # Exclure les templates GLPI de l'inventaire réel
        computers = [format_computer(c) for c in raw_computers if not c.get("is_template")]
        print(f"{len(computers)} ordinateur(s) trouvé(s).")

        output = {
            "source": "GLPI",
            "url": GLPI_URL,
            "date_extraction": datetime.now(timezone.utc).isoformat(),
            "nombre_machines": len(computers),
            "ordinateurs": computers,
        }

        Path(OUTPUT_FILE).write_text(
            json.dumps(output, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"Inventaire sauvegardé dans {OUTPUT_FILE}")

    finally:
        kill_session(session_token)
        print("Session fermée.")


if __name__ == "__main__":
    main()
