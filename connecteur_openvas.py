#!/usr/bin/env python3
"""
Connecteur OpenVAS/Greenbone — Récupère les tâches de scan et les résultats
de vulnérabilités via le protocole GMP natif (python-gvm).

gvmd ne parle GMP que via un socket Unix distant (pas de port TCP exposé
sur le réseau). Ce connecteur ouvre un tunnel SSH avec forwarding
Unix-vers-Unix (OpenSSH >= 6.7, alias SSH "openvas" dans ~/.ssh/config)
vers ce socket, refermé proprement en fin d'exécution.

Compte dédié en lecture seule (rôle Observer). Aucun secret en dur : tout
via .env.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from dotenv import load_dotenv
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp

load_dotenv()

SSH_HOST       = os.getenv("OPENVAS_SSH_HOST", "")          # alias SSH (ex: "openvas")
SOCKET_DISTANT = os.getenv("OPENVAS_SOCKET_REMOTE", "")      # chemin du socket gvmd sur la VM
GMP_USER       = os.getenv("OPENVAS_GMP_USER", "")
GMP_PASSWORD   = os.getenv("OPENVAS_GMP_PASSWORD", "")
OUTPUT_FILE    = os.getenv("OPENVAS_OUTPUT_FILE", "vulnerabilites_openvas.json")

SEUIL_CVSS_ELEVE = 7.0


def check_config():
    missing = [v for v in ["OPENVAS_SSH_HOST", "OPENVAS_SOCKET_REMOTE", "OPENVAS_GMP_USER", "OPENVAS_GMP_PASSWORD"]
               if not os.getenv(v)]
    if missing:
        print(f"Erreur : variables manquantes dans .env : {', '.join(missing)}")
        sys.exit(1)


@contextmanager
def tunnel_ssh():
    """
    Ouvre un tunnel SSH avec forwarding Unix-vers-Unix vers le socket gvmd
    distant. Le socket local est créé dans un répertoire temporaire à chemin
    court (la limite AF_UNIX est d'environ 108 caractères). Le tunnel et le
    fichier socket sont supprimés en sortie du contexte, succès ou échec.
    """
    tmp_dir = tempfile.mkdtemp(prefix="gvmd_")
    local_socket = os.path.join(tmp_dir, "gvmd.sock")

    print(f"Tunnel SSH : {SSH_HOST} → socket local (distant : {SOCKET_DISTANT})...")
    proc = subprocess.Popen(
        ["ssh", "-N", "-L", f"{local_socket}:{SOCKET_DISTANT}", SSH_HOST],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        for _ in range(20):
            if os.path.exists(local_socket):
                break
            if proc.poll() is not None:
                print("Erreur : le tunnel SSH s'est fermé avant l'établissement du socket.")
                print(f"Vérifie l'alias SSH '{SSH_HOST}' et le chemin OPENVAS_SOCKET_REMOTE.")
                sys.exit(1)
            time.sleep(0.3)
        else:
            print("Erreur : timeout en attendant la création du socket local du tunnel.")
            proc.terminate()
            proc.wait()
            sys.exit(1)

        yield local_socket
    finally:
        proc.terminate()
        proc.wait()
        Path(local_socket).unlink(missing_ok=True)
        try:
            os.rmdir(tmp_dir)
        except OSError:
            pass


def format_tache(raw: ET.Element) -> dict:
    """Extrait les champs utiles d'une <task> GMP."""
    last_report = raw.find("last_report/report")
    return {
        "id":                   raw.get("id"),
        "nom":                  raw.findtext("name"),
        "statut":               raw.findtext("status"),
        "progression":          raw.findtext("progress"),
        "cible":                raw.findtext("target/name"),
        "nb_rapports":          raw.findtext("report_count"),
        "dernier_rapport_date": last_report.findtext("timestamp") if last_report is not None else None,
    }


def format_resultat(raw: ET.Element) -> dict:
    """Extrait les champs utiles d'un <result> GMP (une vulnérabilité détectée)."""
    nvt      = raw.find("nvt")
    qod      = raw.find("qod/value")
    severite = raw.findtext("severity")
    return {
        "id":             raw.get("id"),
        "hote":           raw.findtext("host"),
        "port":           raw.findtext("port"),
        "nvt_oid":        nvt.get("oid") if nvt is not None else None,
        "nom":            (nvt.findtext("name") if nvt is not None else None) or raw.findtext("name"),
        "famille":        nvt.findtext("family") if nvt is not None else None,
        "cve":            nvt.findtext("cve") if nvt is not None else None,
        "menace":         raw.findtext("threat"),
        "severite_cvss":  float(severite) if severite else None,
        "qod":            qod.text if qod is not None else None,
        "description":    raw.findtext("description"),
    }


def main():
    check_config()

    try:
        with tunnel_ssh() as local_socket:
            conn = UnixSocketConnection(path=local_socket)
            with Gmp(connection=conn) as gmp:
                try:
                    gmp.authenticate(GMP_USER, GMP_PASSWORD)
                except GvmError as e:
                    print(f"Erreur d'authentification GMP : {e}")
                    print("Vérifie OPENVAS_GMP_USER et OPENVAS_GMP_PASSWORD dans .env.")
                    sys.exit(1)
                print(f"Authentifié en GMP en tant que {GMP_USER}.")

                taches_xml = ET.fromstring(gmp.get_tasks())
                taches = [format_tache(t) for t in taches_xml.findall("task")]
                print(f"{len(taches)} tâche(s) de scan trouvée(s).")

                resultats_xml = ET.fromstring(gmp.get_results(details=True))
                resultats = [format_resultat(r) for r in resultats_xml.findall("result")]
                print(f"{len(resultats)} résultat(s) de vulnérabilité trouvé(s).")
    except GvmError as e:
        print(f"Erreur de connexion GMP : {e}")
        sys.exit(1)

    # Comptage par niveau de menace pour un résumé rapide
    par_menace: dict[str, int] = {}
    for r in resultats:
        m = r["menace"] or "inconnu"
        par_menace[m] = par_menace.get(m, 0) + 1

    nb_eleves = sum(1 for r in resultats if (r["severite_cvss"] or 0) >= SEUIL_CVSS_ELEVE)

    output = {
        "source":                       "OpenVAS/Greenbone",
        "hote_ssh":                     SSH_HOST,
        "date_extraction":              datetime.now(timezone.utc).isoformat(),
        "nombre_taches":                len(taches),
        "taches":                       taches,
        "nombre_resultats":             len(resultats),
        "resultats_cvss_eleve_ou_plus": nb_eleves,
        "resume_par_menace":            par_menace,
        "resultats":                    resultats,
    }

    # connecteur-api est un compte lecture seule (rôle Observer) : il ne peut
    # pas distinguer "aucun scan n'existe" de "un scan existe mais n'a pas été
    # partagé en observer" (voir NOTES_OPENVAS.md). On ne masque pas ce doute.
    if len(taches) == 0:
        output["avertissement"] = (
            "0 tâche visible par connecteur-api. Ceci peut signifier soit qu'aucun "
            "scan n'a été créé, soit qu'un scan existe mais n'a pas été partagé en "
            "observer avec connecteur-api (modify_task observers=[...] manquant). "
            "Ne PAS interpréter ce résultat comme 'aucune vulnérabilité détectée' "
            "sans vérification manuelle."
        )

    Path(OUTPUT_FILE).write_text(
        json.dumps(output, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Résultats sauvegardés dans {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
