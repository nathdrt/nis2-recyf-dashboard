#!/usr/bin/env python3
"""
Moteur d'exécution des scans : lance chaque connecteur actif configuré en
base, puis moteur_scoring.py, dans un cycle isolé.

Réutilise les scripts existants (connecteur_glpi.py, connecteur_wazuh.py,
connecteur_wazuh_alertes.py, connecteur_openvas.py, moteur_scoring.py) tels
quels, en sous-processus — aucune logique de collecte ou de scoring n'est
dupliquée ici. Le sous-processus isole aussi les sys.exit() internes à ces
scripts : un échec de connecteur ne peut pas faire tomber le serveur web.

Chaque exécution tourne dans un répertoire temporaire dédié, pour ne jamais
laisser un fichier JSON d'un cycle précédent être lu comme s'il était frais
si un connecteur échoue ce cycle-ci (un fichier absent = source réellement
indisponible pour CE cycle, jamais une donnée périmée réutilisée en silence).

Les identifiants déchiffrés ne transitent que le temps de construire les
variables d'environnement du sous-processus concerné puis sont abandonnés
(best-effort : CPython ne garantit pas l'effacement immédiat de la mémoire).
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import db

WEBAPP_DIR = Path(__file__).resolve().parent
REPO_ROOT = WEBAPP_DIR.parent
CONNECTEURS_PYTHON = REPO_ROOT / "venv" / "bin" / "python3"

# Même limite connue que test_connexion.py : chemin du socket gvmd propre à
# ce déploiement Greenbone (docker-compose community edition), absent du
# schéma openvas (voir NOTES_OPENVAS.md).
OPENVAS_SOCKET_REMOTE = "/var/lib/docker/volumes/greenbone-community-edition_gvmd_socket_vol/_data/gvmd.sock"

TIMEOUT_CONNECTEUR = 90  # secondes, par connecteur
TIMEOUT_SCORING = 30

# Objectifs ReCyF qui dépendent de chaque source — pour basculer en "Non
# vérifiable" (pas "Non couvert") si le connecteur EST configuré mais a
# échoué pendant ce cycle précis. Un connecteur simplement absent de la
# config garde le statut habituel de moteur_scoring.py (inchangé).
OBJECTIFS_PAR_SOURCE = {
    "glpi": ["IDE-1", "IDE-2"],
    "wazuh_agents": ["DET-1", "DET-2"],
    "wazuh_alertes": ["DET-1", "DET-2"],
    "openvas": ["PRO-2", "PRO-3", "PRO-4"],
}

STATUT_NON_VERIFIABLE = "Non vérifiable - source ambiguë"

# Reflète POIDS de moteur_scoring.py (nécessaire pour recalculer le score
# après une éventuelle bascule en Non vérifiable — pas une réimplémentation
# du moteur, juste l'application du même barème déclaratif).
POIDS = {
    "Couvert": 1.0,
    "Partiel": 0.5,
    "Non couvert - connecteur à venir": 0.0,
    "Non couvert - action manuelle requise": 0.0,
    STATUT_NON_VERIFIABLE: 0.0,
}


def _construire_env(type_: str, config_publique: dict, secrets: dict, temp_dir: Path):
    """Retourne (nom_script, variables_environnement, chemin_sortie_attendu)."""
    env = os.environ.copy()

    if type_ == "glpi":
        sortie = temp_dir / "inventaire.json"
        env.update({
            "GLPI_URL": config_publique["url"],
            "GLPI_APP_TOKEN": secrets["app_token"],
            "GLPI_USER_TOKEN": secrets["user_token"],
            "OUTPUT_FILE": str(sortie),
        })
        return "connecteur_glpi.py", env, sortie

    if type_ == "wazuh_agents":
        sortie = temp_dir / "agents_wazuh.json"
        env.update({
            "WAZUH_URL": f"https://{config_publique['host']}:{config_publique.get('port', 55000)}",
            "WAZUH_USER": config_publique["user"],
            "WAZUH_PASSWORD": secrets["password"],
            "WAZUH_OUTPUT_FILE": str(sortie),
        })
        return "connecteur_wazuh.py", env, sortie

    if type_ == "wazuh_alertes":
        sortie = temp_dir / "alertes_wazuh.json"
        env.update({
            "WAZUH_INDEXER_URL": f"https://{config_publique['host']}:{config_publique.get('port', 9200)}",
            "WAZUH_INDEXER_USER": config_publique["user"],
            "WAZUH_INDEXER_PASSWORD": secrets["password"],
            "WAZUH_INDEXER_SSH_HOST": config_publique.get("ssh_host") or "",
            "WAZUH_ALERTES_OUTPUT": str(sortie),
        })
        return "connecteur_wazuh_alertes.py", env, sortie

    if type_ == "openvas":
        sortie = temp_dir / "vulnerabilites_openvas.json"
        env.update({
            "OPENVAS_SSH_HOST": config_publique["ssh_host"],
            "OPENVAS_SOCKET_REMOTE": OPENVAS_SOCKET_REMOTE,
            "OPENVAS_GMP_USER": config_publique.get("gmp_user", "connecteur-api"),
            "OPENVAS_GMP_PASSWORD": secrets["gmp_password"],
            "OPENVAS_OUTPUT_FILE": str(sortie),
        })
        return "connecteur_openvas.py", env, sortie

    raise ValueError(f"Type de connecteur inconnu : {type_}")


def _executer_connecteur(type_: str, config_publique: dict, secrets: dict, temp_dir: Path) -> tuple[bool, str]:
    script, env, sortie = _construire_env(type_, config_publique, secrets, temp_dir)
    try:
        resultat = subprocess.run(
            [str(CONNECTEURS_PYTHON), str(REPO_ROOT / script)],
            env=env,
            cwd=str(temp_dir),
            capture_output=True,
            text=True,
            timeout=TIMEOUT_CONNECTEUR,
        )
    except subprocess.TimeoutExpired:
        return False, f"Timeout après {TIMEOUT_CONNECTEUR}s"
    finally:
        del secrets, env  # abandon best-effort des identifiants déchiffrés

    if resultat.returncode != 0:
        sortie_texte = (resultat.stdout + resultat.stderr).strip()
        return False, sortie_texte[-2000:] or f"Échec (code {resultat.returncode})"
    if not sortie.exists():
        return False, "Le connecteur s'est terminé sans erreur mais n'a produit aucun fichier."
    return True, ""


def _recalculer_score(rapport: dict):
    objectifs = rapport["objectifs"]
    total = len(objectifs)
    score = sum(POIDS.get(o["statut"], 0.0) for o in objectifs) / total * 100 if total else 0
    rapport["score"]["score_global"] = round(score, 1)
    par_statut = {s: 0 for s in POIDS}
    for o in objectifs:
        par_statut[o["statut"]] = par_statut.get(o["statut"], 0) + 1
    rapport["score"]["par_statut"] = par_statut


def executer_scan(execution_id: int):
    temp_dir = Path(tempfile.mkdtemp(prefix="scan_"))
    erreurs = []
    echecs_par_type = {}

    try:
        connecteurs_actifs = [c for c in db.lister_connecteurs() if c["actif"]]
        for resume in connecteurs_actifs:
            complet = db.obtenir_connecteur_avec_secrets(resume["id"])
            ok, message = _executer_connecteur(
                complet["type"], complet["config_publique"], complet["secrets"], temp_dir
            )
            db.enregistrer_resultat_test(
                resume["id"], f"{'OK' if ok else 'ECHEC'} — {message}" if not ok else "OK — collecte réussie"
            )
            if not ok:
                erreurs.append(f"{complet['nom']} ({complet['type']}) : {message}")
                echecs_par_type[complet["type"]] = message
            del complet

        resultat_scoring = subprocess.run(
            [str(CONNECTEURS_PYTHON), str(REPO_ROOT / "moteur_scoring.py")],
            cwd=str(temp_dir),
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SCORING,
        )
        rapport_path = temp_dir / "rapport_conformite.json"
        if not rapport_path.exists():
            raise RuntimeError(
                "moteur_scoring.py n'a pas produit de rapport : "
                f"{(resultat_scoring.stdout + resultat_scoring.stderr)[-2000:]}"
            )
        rapport = json.loads(rapport_path.read_text(encoding="utf-8"))

        # Un connecteur configuré mais en échec CE cycle → "Non vérifiable"
        # sur les objectifs qu'il alimente, jamais "Non couvert" par défaut.
        for type_, message in echecs_par_type.items():
            for obj_id in OBJECTIFS_PAR_SOURCE.get(type_, []):
                for obj in rapport["objectifs"]:
                    if obj["id"] == obj_id:
                        obj["statut"] = STATUT_NON_VERIFIABLE
                        obj["justification"] = (
                            f"Le connecteur configuré a échoué pendant cette exécution : {message}"
                        )

        if echecs_par_type:
            _recalculer_score(rapport)

        db.terminer_execution(
            execution_id,
            statut="termine",
            score_global=rapport["score"]["score_global"],
            details=rapport,
            erreurs="\n".join(erreurs) if erreurs else None,
        )
    except Exception as e:
        db.terminer_execution(
            execution_id,
            statut="erreur",
            score_global=None,
            details={"erreur": str(e)},
            erreurs="\n".join(erreurs) if erreurs else str(e),
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
