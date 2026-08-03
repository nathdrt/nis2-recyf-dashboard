#!/usr/bin/env python3
"""
Accès à la base SQLite du dashboard : compte admin (webapp/app.py) et
configuration des connecteurs (ce module).

Les champs secrets d'un connecteur (tokens, mots de passe) ne sont jamais
stockés en clair : ils sont chiffrés en un blob unique (JSON chiffré via
Fernet) dans la colonne config_secrete, avec la clé générée par
setup_dashboard.sh (secrets/fernet.key, jamais committée).
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "dashboard.db"
FERNET_KEY_FILE = BASE_DIR / "secrets" / "fernet.key"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_fernet() -> Fernet:
    if not FERNET_KEY_FILE.exists():
        raise RuntimeError(
            f"{FERNET_KEY_FILE} introuvable. Lance setup_dashboard.sh avant de démarrer l'application."
        )
    return Fernet(FERNET_KEY_FILE.read_bytes().strip())


def init_connecteurs_table():
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS connecteurs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL CHECK(type IN ('glpi', 'wazuh_agents', 'wazuh_alertes', 'openvas')),
                nom TEXT NOT NULL,
                config_publique TEXT NOT NULL,
                config_secrete TEXT NOT NULL,
                actif INTEGER NOT NULL DEFAULT 1,
                derniere_execution TEXT,
                dernier_statut TEXT,
                date_creation TEXT NOT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()


def chiffrer_secrets(secrets: dict) -> str:
    """Sérialise puis chiffre les champs secrets en un blob unique."""
    return get_fernet().encrypt(json.dumps(secrets).encode()).decode()


def dechiffrer_secrets(blob: str) -> dict:
    try:
        return json.loads(get_fernet().decrypt(blob.encode()).decode())
    except InvalidToken as e:
        raise RuntimeError("Impossible de déchiffrer la configuration secrète (clé Fernet invalide ou changée).") from e


def lister_connecteurs() -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, type, nom, actif, derniere_execution, dernier_statut, date_creation "
            "FROM connecteurs ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def obtenir_connecteur(connecteur_id: int) -> Optional[dict]:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM connecteurs WHERE id = ?", (connecteur_id,)
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["config_publique"] = json.loads(d["config_publique"])
        return d
    finally:
        conn.close()


def obtenir_connecteur_avec_secrets(connecteur_id: int) -> Optional[dict]:
    """Comme obtenir_connecteur, mais déchiffre aussi config_secrete. Réservé
    aux besoins internes (test de connexion) — jamais exposé tel quel à une vue."""
    d = obtenir_connecteur(connecteur_id)
    if d is None:
        return None
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT config_secrete FROM connecteurs WHERE id = ?", (connecteur_id,)
        ).fetchone()
    finally:
        conn.close()
    d["secrets"] = dechiffrer_secrets(row["config_secrete"])
    return d


def creer_connecteur(type_: str, nom: str, config_publique: dict, secrets: dict) -> int:
    conn = get_connection()
    try:
        cur = conn.execute(
            "INSERT INTO connecteurs (type, nom, config_publique, config_secrete, actif, date_creation) "
            "VALUES (?, ?, ?, ?, 1, ?)",
            (
                type_,
                nom,
                json.dumps(config_publique),
                chiffrer_secrets(secrets),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def modifier_connecteur(connecteur_id: int, nom: str, config_publique: dict, secrets: Optional[dict]):
    """Si secrets est None, la config secrète existante est conservée telle quelle
    (cas : l'utilisateur laisse les champs secrets vides pour ne pas les changer)."""
    conn = get_connection()
    try:
        if secrets is not None:
            conn.execute(
                "UPDATE connecteurs SET nom = ?, config_publique = ?, config_secrete = ? WHERE id = ?",
                (nom, json.dumps(config_publique), chiffrer_secrets(secrets), connecteur_id),
            )
        else:
            conn.execute(
                "UPDATE connecteurs SET nom = ?, config_publique = ? WHERE id = ?",
                (nom, json.dumps(config_publique), connecteur_id),
            )
        conn.commit()
    finally:
        conn.close()


def supprimer_connecteur(connecteur_id: int):
    conn = get_connection()
    try:
        conn.execute("DELETE FROM connecteurs WHERE id = ?", (connecteur_id,))
        conn.commit()
    finally:
        conn.close()


def enregistrer_resultat_test(connecteur_id: int, statut: str):
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE connecteurs SET derniere_execution = ?, dernier_statut = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), statut, connecteur_id),
        )
        conn.commit()
    finally:
        conn.close()
