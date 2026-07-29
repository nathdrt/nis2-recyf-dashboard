#!/usr/bin/env python3
"""
Connecteur Wazuh — Alertes de sécurité (résumé agrégé, 24h par défaut)

Les alertes Wazuh sont stockées dans OpenSearch/Indexer (port 9200),
pas dans l'API Manager (port 55000). Ce connecteur interroge directement
l'Indexer via des requêtes d'agrégation.

OpenSearch écoute uniquement sur localhost du serveur Wazuh. Si la variable
WAZUH_INDEXER_SSH_HOST est définie, un tunnel SSH est créé automatiquement
pour rendre le port accessible depuis la machine qui exécute ce script.

Approche RGPD : on ne collecte QUE des comptages agrégés.
Aucun champ utilisateur (data.srcuser, data.win.eventdata.*) n'est extrait.
Les champs collectés sont : rule.level, rule.id, rule.description,
rule.groups, agent.name — tous génériques, sans donnée personnelle.
"""

import json
import os
import sys
import urllib3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

INDEXER_URL   = os.getenv("WAZUH_INDEXER_URL", "").rstrip("/")
INDEXER_USER  = os.getenv("WAZUH_INDEXER_USER", "")
INDEXER_PASS  = os.getenv("WAZUH_INDEXER_PASSWORD", "")
FENETRE_H     = int(os.getenv("WAZUH_ALERTES_FENETRE_HEURES", "24"))
OUTPUT_FILE   = os.getenv("WAZUH_ALERTES_OUTPUT", "alertes_wazuh.json")
SSH_HOST      = os.getenv("WAZUH_INDEXER_SSH_HOST", "")   # alias SSH (ex: "wazuh")

TOP_REGLES    = int(os.getenv("WAZUH_ALERTES_TOP_REGLES", "20"))
TOP_AGENTS    = int(os.getenv("WAZUH_ALERTES_TOP_AGENTS", "20"))
SEUIL_CRITIQUE = 7


def check_config():
    missing = [v for v in ["WAZUH_INDEXER_URL", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD"]
               if not os.getenv(v)]
    if missing:
        print(f"Erreur : variables manquantes dans .env : {', '.join(missing)}")
        sys.exit(1)


def libelle_niveau(niveau: int) -> str:
    if niveau <= 3:
        return "bas"
    if niveau <= 6:
        return "moyen"
    if niveau <= 11:
        return "élevé"
    if niveau <= 14:
        return "critique"
    return "maximum"


@contextmanager
def tunnel_ssh_si_necessaire():
    """
    Si WAZUH_INDEXER_SSH_HOST est défini, crée un tunnel SSH via le binaire ssh
    (utilise la config ~/.ssh/config) pour rendre le port 9200 distant accessible
    localement sur 127.0.0.1:19200, puis le ferme proprement en sortie du contexte.
    Sinon, retourne l'URL d'origine sans rien faire.
    """
    if not SSH_HOST:
        yield INDEXER_URL
        return

    import re
    import subprocess
    import time

    m = re.search(r":(\d+)$", INDEXER_URL)
    remote_port = int(m.group(1)) if m else 9200
    local_port  = 19200  # port local dédié au tunnel

    print(f"Tunnel SSH : {SSH_HOST} → localhost:{local_port} (distant:{remote_port})...")
    proc = subprocess.Popen(
        ["ssh", "-N", "-L", f"127.0.0.1:{local_port}:127.0.0.1:{remote_port}", SSH_HOST],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)  # laisser le temps au tunnel de s'établir
    local_url = f"https://127.0.0.1:{local_port}"
    try:
        yield local_url
    finally:
        proc.terminate()
        proc.wait()


def requete_alertes(url: str) -> dict:
    """
    Envoie une requête d'agrégation à OpenSearch.
    Retourne uniquement des comptages — aucun document individuel.
    """
    query = {
        "size": 0,
        "query": {
            "range": {
                "timestamp": {"gte": f"now-{FENETRE_H}h"}
            }
        },
        "aggs": {
            "par_niveau": {
                "terms": {"field": "rule.level", "size": 20}
            },
            "par_regle": {
                "terms": {"field": "rule.id", "size": TOP_REGLES},
                "aggs": {
                    "meta": {
                        "top_hits": {
                            "size": 1,
                            # Seuls les champs génériques de la règle — jamais data.*
                            "_source": {
                                "includes": [
                                    "rule.id",
                                    "rule.level",
                                    "rule.description",
                                    "rule.groups"
                                ]
                            }
                        }
                    }
                }
            },
            "par_agent": {
                "terms": {"field": "agent.name", "size": TOP_AGENTS}
            },
            "alertes_critiques": {
                "filter": {
                    "range": {"rule.level": {"gte": SEUIL_CRITIQUE}}
                }
            }
        }
    }

    resp = requests.post(
        f"{url}/wazuh-alerts-*/_search",
        auth=(INDEXER_USER, INDEXER_PASS),
        json=query,
        verify=False,
        timeout=30,
    )

    if resp.status_code == 401:
        print("Erreur : identifiants OpenSearch refusés. Vérifie WAZUH_INDEXER_USER et WAZUH_INDEXER_PASSWORD.")
        sys.exit(1)
    if resp.status_code == 403:
        print("Erreur : accès interdit. Le compte OpenSearch n'a pas les droits sur wazuh-alerts-*.")
        sys.exit(1)
    resp.raise_for_status()
    return resp.json()


def formater_resultats(raw: dict) -> dict:
    aggs  = raw.get("aggregations", {})
    total = raw.get("hits", {}).get("total", {}).get("value", 0)

    par_niveau = []
    for bucket in aggs.get("par_niveau", {}).get("buckets", []):
        niveau = bucket["key"]
        par_niveau.append({
            "niveau": niveau,
            "libelle": libelle_niveau(niveau),
            "nb": bucket["doc_count"],
        })
    par_niveau.sort(key=lambda x: x["niveau"], reverse=True)

    par_regle = []
    for bucket in aggs.get("par_regle", {}).get("buckets", []):
        hits   = bucket.get("meta", {}).get("hits", {}).get("hits", [])
        source = hits[0].get("_source", {}) if hits else {}
        rule   = source.get("rule", {})
        par_regle.append({
            "regle_id":      bucket["key"],
            "niveau":        rule.get("level"),
            "libelle_niveau": libelle_niveau(rule.get("level", 0)),
            "description":   rule.get("description", "—"),
            "groupes":       rule.get("groups", []),
            "nb":            bucket["doc_count"],
        })
    par_regle.sort(key=lambda x: x["nb"], reverse=True)

    par_agent = [
        {"agent": b["key"], "nb": b["doc_count"]}
        for b in aggs.get("par_agent", {}).get("buckets", [])
    ]
    par_agent.sort(key=lambda x: x["nb"], reverse=True)

    nb_critiques = aggs.get("alertes_critiques", {}).get("doc_count", 0)

    return {
        "source":                      "Wazuh-Indexer",
        "url":                         INDEXER_URL,
        "date_extraction":             datetime.now(timezone.utc).isoformat(),
        "periode_heures":              FENETRE_H,
        "total_alertes":               total,
        "alertes_niveau_eleve_ou_plus": nb_critiques,
        "par_niveau":                  par_niveau,
        "par_regle":                   par_regle,
        "par_agent":                   par_agent,
    }


def main():
    check_config()
    print(f"Connexion à {INDEXER_URL} (fenêtre : {FENETRE_H}h)...")

    with tunnel_ssh_si_necessaire() as url_effective:
        raw = requete_alertes(url_effective)

    resume = formater_resultats(raw)

    total     = resume["total_alertes"]
    critiques = resume["alertes_niveau_eleve_ou_plus"]
    print(f"{total} alerte(s) sur {FENETRE_H}h — dont {critiques} de niveau ≥ {SEUIL_CRITIQUE} (élevé/critique).")

    Path(OUTPUT_FILE).write_text(
        json.dumps(resume, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Résumé sauvegardé dans {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
