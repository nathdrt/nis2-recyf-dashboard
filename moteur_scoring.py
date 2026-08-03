#!/usr/bin/env python3
"""
Moteur de scoring ReCyF V2
Lit les fichiers produits par les connecteurs et évalue la conformité
objectif par objectif selon le référentiel ReCyF de l'ANSSI.

Avertissement sur la numérotation : le référentiel ReCyF est encore un
document de travail. Les identifiants utilisés ici (GOV-x, IDE-x, etc.)
sont des codes fonctionnels stables pour ce projet, volontairement génériques
plutôt que liés à une version figée du document ANSSI.

V2 — données couvertes : GLPI (inventaire), Wazuh Manager (agents),
                          Wazuh Indexer (alertes de sécurité 24h),
                          OpenVAS/Greenbone (résultats de scan de vulnérabilités).
"""

import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


# ─── Modèle de données ────────────────────────────────────────────────────────

class Statut(str, Enum):
    COUVERT              = "Couvert"
    PARTIEL              = "Partiel"
    NON_COUVERT_CONNECTEUR = "Non couvert - connecteur à venir"
    NON_COUVERT_MANUEL   = "Non couvert - action manuelle requise"
    NON_VERIFIABLE       = "Non vérifiable - source ambiguë"


# Contribution au score global (sur 1.0)
# NON_VERIFIABLE pèse 0.0 comme les statuts non couverts : une source ambiguë
# ne doit JAMAIS faire progresser le score, même par accident.
POIDS = {
    Statut.COUVERT:               1.0,
    Statut.PARTIEL:               0.5,
    Statut.NON_COUVERT_CONNECTEUR: 0.0,
    Statut.NON_COUVERT_MANUEL:     0.0,
    Statut.NON_VERIFIABLE:         0.0,
}

# Libellé court pour le tableau terminal
LABEL_COURT = {
    Statut.COUVERT:               "Couvert           ",
    Statut.PARTIEL:               "Partiel           ",
    Statut.NON_COUVERT_CONNECTEUR: "Non couvert (tech)",
    Statut.NON_COUVERT_MANUEL:     "Non couvert (doc) ",
    Statut.NON_VERIFIABLE:         "Non vérifiable    ",
}


@dataclass
class ObjectifReCyF:
    id:            str
    bloc:          str
    libelle:       str
    statut:        Statut
    justification: str
    source:        Optional[str] = None   # fichier(s) source utilisé(s)


# ─── Chargement des fichiers ──────────────────────────────────────────────────

def charger(chemin: str) -> Optional[dict]:
    p = Path(chemin)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"Erreur lecture {chemin} : {e}", file=sys.stderr)
        return None


# ─── Analyse des données sources ─────────────────────────────────────────────

def analyser_inventaire(data: Optional[dict]) -> dict:
    """Extrait les métriques utiles de inventaire.json."""
    if not data:
        return {"disponible": False}
    machines = data.get("ordinateurs", [])
    # Un inventaire utile = nom renseigné (GLPI basique ne retourne pas les IPs
    # via l'endpoint /Computer — les interfaces réseau sont dans un endpoint séparé)
    with_nom = [m for m in machines if m.get("nom")]
    with_os  = [m for m in machines if m.get("systeme_exploitation")]
    return {
        "disponible":    True,
        "nb_total":      len(machines),
        "nb_avec_nom":   len(with_nom),
        "nb_avec_os":    len(with_os),
        "date_extraction": data.get("date_extraction"),
    }


def analyser_agents(data: Optional[dict]) -> dict:
    """Extrait les métriques utiles de agents_wazuh.json."""
    if not data:
        return {"disponible": False}
    agents  = data.get("agents", [])
    # Le connecteur filtre déjà le manager (id=000), donc tous les agents listés
    # sont de vrais endpoints surveillés.
    actifs  = [a for a in agents if a.get("statut") == "active"]
    os_list = list({a["os_plateforme"] for a in actifs if a.get("os_plateforme")})
    return {
        "disponible":      True,
        "nb_agents":       len(agents),
        "nb_actifs":       len(actifs),
        "plateformes_os":  os_list,
        "resume_statuts":  data.get("resume_statuts", {}),
        "date_extraction": data.get("date_extraction"),
    }


def analyser_alertes(data: Optional[dict]) -> dict:
    """Extrait les métriques utiles de alertes_wazuh.json."""
    if not data:
        return {"disponible": False}
    date_str = data.get("date_extraction", "")
    recentes = False
    if date_str:
        # Données considérées récentes si extraites il y a moins de 48h
        delta = datetime.now(timezone.utc) - datetime.fromisoformat(date_str)
        recentes = delta.total_seconds() < 48 * 3600
    return {
        "disponible":      True,
        "total_alertes":   data.get("total_alertes", 0),
        "nb_elevees":      data.get("alertes_niveau_eleve_ou_plus", 0),
        "donnees_recentes": recentes,
        "date_extraction": date_str,
        "periode_heures":  data.get("periode_heures", 24),
    }


def analyser_vulnerabilites(data: Optional[dict]) -> dict:
    """
    Extrait les métriques utiles de vulnerabilites_openvas.json.

    Le connecteur OpenVAS ajoute un champ "avertissement" quand
    nombre_taches == 0 de façon ambiguë (voir NOTES_OPENVAS.md) : le rôle
    Observer de connecteur-api ne peut pas distinguer "aucun scan n'existe"
    de "un scan existe mais n'a pas été partagé en observer". Ce cas est
    remonté ici comme "ambigu", jamais comme une absence de vulnérabilité.
    """
    if not data:
        return {"disponible": False, "ambigu": False}
    if "avertissement" in data:
        return {
            "disponible":          True,
            "ambigu":              True,
            "message_avertissement": data["avertissement"],
            "date_extraction":     data.get("date_extraction"),
        }
    # Nombre d'hôtes distincts réellement couverts par le scan — calculé à partir
    # des résultats individuels (champ "hote"), pas supposé. Un scan qui ne
    # couvre qu'une seule machine ne peut pas prouver un durcissement ou une
    # segmentation à l'échelle du parc, quel que soit le nombre de résultats.
    resultats = data.get("resultats", [])
    hotes = {r.get("hote") for r in resultats if r.get("hote")}

    return {
        "disponible":                  True,
        "ambigu":                      False,
        "nombre_taches":               data.get("nombre_taches", 0),
        "nombre_resultats":            data.get("nombre_resultats", 0),
        "resultats_cvss_eleve_ou_plus": data.get("resultats_cvss_eleve_ou_plus", 0),
        "resume_par_menace":           data.get("resume_par_menace", {}),
        "nb_hotes_scannes":            len(hotes),
        "date_extraction":             data.get("date_extraction"),
    }


# ─── Évaluation objectif par objectif ────────────────────────────────────────

def statut_openvas_indisponible(vul: dict) -> Optional[tuple[Statut, str]]:
    """
    Statut/justification communs quand la source OpenVAS ne peut pas être
    exploitée pour faire progresser un objectif. Retourne None quand les
    données sont exploitables (scan réel, nombre_taches > 0 sans ambiguïté).
    """
    if not vul["disponible"]:
        return (
            Statut.NON_COUVERT_CONNECTEUR,
            "vulnerabilites_openvas.json absent. Relancer connecteur_openvas.py.",
        )
    if vul["ambigu"]:
        return (
            Statut.NON_VERIFIABLE,
            f"Source OpenVAS ambiguë pour ce cycle : {vul['message_avertissement']}",
        )
    if vul["nombre_taches"] == 0:
        # Ne devrait pas arriver (nombre_taches==0 sans le champ "avertissement"
        # du connecteur) — filet de sécurité pour ne jamais interpréter un 0
        # comme "aucune vulnérabilité" par défaut.
        return (
            Statut.NON_VERIFIABLE,
            "Aucune tâche de scan trouvée, sans avertissement explicite du "
            "connecteur — état incohérent, à vérifier manuellement.",
        )
    return None


def evaluer(inv: dict, agt: dict, alt: dict, vul: dict) -> list[ObjectifReCyF]:
    """
    Retourne la liste des objectifs ReCyF évalués.
    Règle fondamentale : on ne marque JAMAIS "Couvert" quelque chose
    qu'on ne peut pas prouver avec les données disponibles.
    """
    obj = []

    # ── BLOC GOUVERNANCE ──────────────────────────────────────────────────────
    # Les objectifs de gouvernance (PSSI, risques, organisation) sont par nature
    # documentaires : aucun connecteur technique ne peut les couvrir.

    obj.append(ObjectifReCyF(
        id="GOV-1", bloc="Gouvernance",
        libelle="Politique de sécurité du SI (PSSI)",
        statut=Statut.NON_COUVERT_MANUEL,
        justification="Nécessite la rédaction et l'approbation d'une PSSI formalisée.",
    ))
    obj.append(ObjectifReCyF(
        id="GOV-2", bloc="Gouvernance",
        libelle="Analyse et traitement des risques",
        statut=Statut.NON_COUVERT_MANUEL,
        justification="Nécessite une analyse de risques formalisée (EBIOS RM ou équivalente).",
    ))
    obj.append(ObjectifReCyF(
        id="GOV-3", bloc="Gouvernance",
        libelle="Responsabilités et organisation de la sécurité (RSSI, rôles)",
        statut=Statut.NON_COUVERT_MANUEL,
        justification="Nécessite la désignation formelle d'un RSSI et la documentation des rôles.",
    ))
    obj.append(ObjectifReCyF(
        id="GOV-4", bloc="Gouvernance",
        libelle="Sensibilisation et formation du personnel",
        statut=Statut.NON_COUVERT_MANUEL,
        justification="Nécessite un programme de sensibilisation documenté. Aucune donnée technique disponible.",
    ))

    # ── BLOC IDENTIFICATION ───────────────────────────────────────────────────

    # IDE-1 : cartographie matérielle — couvert si au moins une machine avec nom.
    # Nuance : GLPI /Computer ne retourne pas les IPs des interfaces réseau
    # (endpoint séparé /NetworkPort non interrogé par ce connecteur).
    if inv["disponible"] and inv["nb_avec_nom"] > 0:
        if inv["nb_avec_os"] > 0:
            # Nom + OS : couverture solide pour un inventaire de base
            statut_ide1 = Statut.COUVERT
            just_ide1 = (
                f"{inv['nb_avec_nom']}/{inv['nb_total']} machine(s) inventoriée(s) avec "
                f"nom dans GLPI. Note : les adresses IP ne sont pas retournées par "
                f"l'endpoint /Computer (interfaces réseau hors scope V1)."
            )
        else:
            # Nom présent mais OS absent : inventaire incomplet
            statut_ide1 = Statut.PARTIEL
            just_ide1 = (
                f"{inv['nb_avec_nom']} machine(s) avec nom dans GLPI, mais "
                f"système d'exploitation non renseigné. Inventaire à compléter."
            )
    elif inv["disponible"]:
        statut_ide1 = Statut.PARTIEL
        just_ide1 = f"{inv['nb_total']} machine(s) dans GLPI mais sans nom renseigné."
    else:
        statut_ide1 = Statut.NON_COUVERT_CONNECTEUR
        just_ide1 = "inventaire.json absent. Relancer connecteur_glpi.py."

    obj.append(ObjectifReCyF(
        id="IDE-1", bloc="Identification",
        libelle="Inventaire des actifs matériels (cartographie du SI)",
        statut=statut_ide1, justification=just_ide1,
        source="inventaire.json",
    ))

    # IDE-2 : inventaire logiciel — le connecteur GLPI remonte l'OS mais pas les
    # logiciels installés (endpoint /Software non interrogé en V1).
    if inv["disponible"] and inv["nb_avec_nom"] > 0:
        statut_ide2 = Statut.PARTIEL
        just_ide2 = (
            "L'OS est partiellement récupéré via GLPI, mais les logiciels installés "
            "nécessitent l'interrogation de l'endpoint /Computer/{id}/Software "
            "(non implémenté en V1)."
        )
    else:
        statut_ide2 = Statut.NON_COUVERT_CONNECTEUR
        just_ide2 = "Dépend de inventaire.json — voir IDE-1."

    obj.append(ObjectifReCyF(
        id="IDE-2", bloc="Identification",
        libelle="Inventaire des actifs logiciels et versions",
        statut=statut_ide2, justification=just_ide2,
        source="inventaire.json",
    ))

    obj.append(ObjectifReCyF(
        id="IDE-3", bloc="Identification",
        libelle="Classification et criticité des actifs",
        statut=Statut.NON_COUVERT_MANUEL,
        justification=(
            "La classification (critique / standard / non critique) doit être "
            "renseignée manuellement dans GLPI ou dans un document dédié."
        ),
    ))

    # ── BLOC PROTECTION ───────────────────────────────────────────────────────

    obj.append(ObjectifReCyF(
        id="PRO-1", bloc="Protection",
        libelle="Gestion des accès et des identités (IAM, MFA)",
        statut=Statut.NON_COUVERT_MANUEL,
        justification="Nécessite un audit IAM (comptes, droits, MFA). Aucun connecteur IAM disponible en V1.",
    ))
    base_openvas = statut_openvas_indisponible(vul)

    if base_openvas:
        statut_pro2, just_pro2 = base_openvas
        statut_pro3, just_pro3 = base_openvas
        statut_pro4, just_pro4 = base_openvas
    else:
        nb_taches = vul["nombre_taches"]
        nb_res    = vul["nombre_resultats"]
        nb_eleves = vul["resultats_cvss_eleve_ou_plus"]
        nb_hotes  = vul["nb_hotes_scannes"]

        # PRO-4 : gestion des vulnérabilités — objectif le plus directement lié
        # aux résultats OpenVAS : un scan actif + absence de vulnérabilité
        # CVSS élevée est la preuve la plus directe qu'on puisse avoir en V2.
        if nb_eleves > 0:
            statut_pro4 = Statut.PARTIEL
            just_pro4 = (
                f"Scan OpenVAS actif ({nb_taches} tâche(s), {nb_res} résultat(s)) : "
                f"{nb_eleves} vulnérabilité(s) de sévérité élevée (CVSS ≥ 7) à corriger."
            )
        else:
            statut_pro4 = Statut.COUVERT
            just_pro4 = (
                f"Scan OpenVAS actif ({nb_taches} tâche(s), {nb_res} résultat(s)), "
                f"aucune vulnérabilité de sévérité élevée détectée sur le périmètre scanné."
            )

        # PRO-2 et PRO-3 : un scan de vulnérabilités donne une visibilité technique
        # (bannières, ports, en-têtes HTTP...), mais un scan mono-hôte ne peut pas
        # prouver un durcissement ou une segmentation à l'échelle du parc — le
        # nombre d'hôtes réellement couverts est calculé dynamiquement (voir
        # analyser_vulnerabilites), pas supposé. Le plafond se lève dès que
        # plusieurs hôtes distincts sont couverts par le scan.
        if nb_hotes <= 1:
            statut_pro2 = Statut.PARTIEL
            just_pro2 = (
                f"Scan OpenVAS actif ({nb_res} résultat(s) technique(s) collecté(s)) sur "
                f"{nb_hotes} hôte(s) : visibilité partielle (bannières, en-têtes HTTP...), mais "
                f"un scan mono-hôte ne prouve pas un durcissement systématique du parc."
            )
            statut_pro3 = Statut.PARTIEL
            just_pro3 = (
                f"Scan OpenVAS actif ({nb_res} résultat(s)) sur {nb_hotes} hôte(s) : détection de "
                f"ports/services en place, mais un scan mono-hôte ne prouve pas la segmentation "
                f"réseau du parc."
            )
        elif nb_eleves > 0:
            statut_pro2 = statut_pro3 = Statut.PARTIEL
            just_pro2 = just_pro3 = (
                f"Scan OpenVAS actif sur {nb_hotes} hôtes distincts ({nb_res} résultat(s)) : "
                f"{nb_eleves} vulnérabilité(s) de sévérité élevée à corriger avant de considérer "
                f"le durcissement/la segmentation comme acquis."
            )
        else:
            statut_pro2 = statut_pro3 = Statut.COUVERT
            just_pro2 = just_pro3 = (
                f"Scan OpenVAS actif sur {nb_hotes} hôtes distincts ({nb_res} résultat(s)), "
                f"aucune vulnérabilité de sévérité élevée détectée sur le périmètre scanné."
            )

    obj.append(ObjectifReCyF(
        id="PRO-2", bloc="Protection",
        libelle="Durcissement des systèmes et des configurations",
        statut=statut_pro2, justification=just_pro2,
        source="vulnerabilites_openvas.json",
    ))
    obj.append(ObjectifReCyF(
        id="PRO-3", bloc="Protection",
        libelle="Sécurité réseau et segmentation",
        statut=statut_pro3, justification=just_pro3,
        source="vulnerabilites_openvas.json",
    ))
    obj.append(ObjectifReCyF(
        id="PRO-4", bloc="Protection",
        libelle="Gestion des vulnérabilités et des correctifs",
        statut=statut_pro4, justification=just_pro4,
        source="vulnerabilites_openvas.json",
    ))
    obj.append(ObjectifReCyF(
        id="PRO-5", bloc="Protection",
        libelle="Protection des données et chiffrement",
        statut=Statut.NON_COUVERT_MANUEL,
        justification="Nécessite un audit des pratiques de chiffrement (données au repos et en transit).",
    ))

    # ── BLOC DÉTECTION ────────────────────────────────────────────────────────
    # Wazuh couvre la détection : agents actifs + alertes récentes = base solide.

    agents_ok = agt["disponible"] and agt["nb_actifs"] > 0
    alertes_ok = alt["disponible"] and alt["donnees_recentes"]

    if agents_ok and alertes_ok:
        statut_det1 = Statut.COUVERT
        just_det1 = (
            f"{agt['nb_actifs']} agent(s) Wazuh actif(s) "
            f"({', '.join(agt['plateformes_os']) or 'plateforme inconnue'}). "
            f"{alt['total_alertes']} événement(s) remontés sur "
            f"{alt['periode_heures']}h, données extraites le "
            f"{alt['date_extraction'][:10]}."
        )
    elif agents_ok:
        statut_det1 = Statut.PARTIEL
        just_det1 = (
            f"{agt['nb_actifs']} agent(s) actif(s), mais alertes_wazuh.json "
            f"absent ou données non récentes (> 48h)."
        )
    elif alertes_ok:
        statut_det1 = Statut.PARTIEL
        just_det1 = "Données d'alertes présentes, mais aucun agent Wazuh actif répertorié."
    else:
        statut_det1 = Statut.NON_COUVERT_CONNECTEUR
        just_det1 = "Aucun agent actif et aucune donnée d'alertes récente."

    obj.append(ObjectifReCyF(
        id="DET-1", bloc="Détection",
        libelle="Surveillance des événements de sécurité (collecte de logs)",
        statut=statut_det1, justification=just_det1,
        source="agents_wazuh.json + alertes_wazuh.json",
    ))

    # DET-2 : détection d'incidents réels — différencier "Wazuh tourne" de
    # "Wazuh a effectivement détecté quelque chose de significatif".
    if agents_ok and alertes_ok and alt["nb_elevees"] > 0:
        statut_det2 = Statut.COUVERT
        just_det2 = (
            f"Wazuh a remonté {alt['nb_elevees']} alerte(s) de niveau élevé "
            f"ou critique sur {alt['periode_heures']}h. La chaîne de détection "
            f"est opérationnelle."
        )
    elif agents_ok and alertes_ok:
        # Wazuh tourne et surveille, mais aucune alerte significative sur la période
        statut_det2 = Statut.PARTIEL
        just_det2 = (
            f"Wazuh surveille ({alt['total_alertes']} événements remontés) mais "
            f"aucune alerte de niveau élevé sur la période. La détection fonctionne "
            f"mais n'a pas encore qualifié d'incident significatif."
        )
    else:
        statut_det2 = statut_det1
        just_det2 = just_det1

    obj.append(ObjectifReCyF(
        id="DET-2", bloc="Détection",
        libelle="Détection et qualification des incidents de sécurité",
        statut=statut_det2, justification=just_det2,
        source="alertes_wazuh.json",
    ))

    obj.append(ObjectifReCyF(
        id="DET-3", bloc="Détection",
        libelle="Gestion des indicateurs de compromission (IoC / CTI)",
        statut=Statut.NON_COUVERT_MANUEL,
        justification=(
            "Nécessite un processus CTI et une base d'IoC intégrée. "
            "Wazuh supporte les listes d'IoC mais la configuration est à réaliser."
        ),
    ))

    # ── BLOC RÉPONSE ──────────────────────────────────────────────────────────

    obj.append(ObjectifReCyF(
        id="REP-1", bloc="Réponse",
        libelle="Plan de réponse aux incidents de sécurité (IRP)",
        statut=Statut.NON_COUVERT_MANUEL,
        justification="Nécessite la rédaction d'un plan de réponse aux incidents (IRP). Document à produire.",
    ))
    obj.append(ObjectifReCyF(
        id="REP-2", bloc="Réponse",
        libelle="Notification des incidents (ANSSI, clients, autorités)",
        statut=Statut.NON_COUVERT_MANUEL,
        justification=(
            "Nécessite une procédure de notification formalisée (ANSSI/CERT-FR, "
            "clients, CNIL si données personnelles concernées)."
        ),
    ))
    obj.append(ObjectifReCyF(
        id="REP-3", bloc="Réponse",
        libelle="Investigation et analyse post-incident (forensique)",
        statut=Statut.NON_COUVERT_MANUEL,
        justification=(
            "Les logs Wazuh peuvent alimenter une analyse, mais la procédure "
            "forensique formalisée est à documenter."
        ),
    ))

    # ── BLOC RÉSILIENCE / CONTINUITÉ ─────────────────────────────────────────

    obj.append(ObjectifReCyF(
        id="RES-1", bloc="Résilience",
        libelle="Plan de continuité d'activité (PCA)",
        statut=Statut.NON_COUVERT_MANUEL,
        justification="Nécessite la rédaction et le test d'un PCA. Aucune donnée technique disponible.",
    ))
    obj.append(ObjectifReCyF(
        id="RES-2", bloc="Résilience",
        libelle="Plan de reprise d'activité (PRA) et politique de sauvegardes",
        statut=Statut.NON_COUVERT_MANUEL,
        justification=(
            "Nécessite un audit des sauvegardes et un PRA documenté. "
            "Un connecteur de monitoring de sauvegardes est envisageable en V3."
        ),
    ))
    obj.append(ObjectifReCyF(
        id="RES-3", bloc="Résilience",
        libelle="Tests de continuité et exercices de gestion de crise",
        statut=Statut.NON_COUVERT_MANUEL,
        justification="Nécessite la planification et la réalisation d'exercices documentés.",
    ))

    return obj


# ─── Calcul du score global ───────────────────────────────────────────────────

def calculer_score(objectifs: list[ObjectifReCyF]) -> dict:
    total = len(objectifs)
    scores = [POIDS[o.statut] for o in objectifs]
    score_global = sum(scores) / total * 100 if total else 0

    comptage = {s: 0 for s in Statut}
    for o in objectifs:
        comptage[o.statut] += 1

    return {
        "nb_objectifs":  total,
        "score_global":  round(score_global, 1),
        "par_statut": {s.value: comptage[s] for s in Statut},
    }


# ─── Affichage terminal ───────────────────────────────────────────────────────

def afficher_rapport(objectifs: list[ObjectifReCyF], score: dict):
    LARGEUR = 100
    print()
    print("=" * LARGEUR)
    print("  RAPPORT DE CONFORMITÉ ReCyF — V2")
    print(f"  Généré le : {datetime.now().strftime('%d/%m/%Y %H:%M')}")
    print("=" * LARGEUR)

    bloc_courant = None
    for o in objectifs:
        if o.bloc != bloc_courant:
            bloc_courant = o.bloc
            print()
            print(f"  ▶ {o.bloc.upper()}")
            print(f"  {'─' * 96}")
            print(f"  {'ID':<8} {'Libellé':<50} {'Statut':<22} {'Source'}")
            print(f"  {'─' * 96}")

        source = o.source or "—"
        libelle = o.libelle[:48] + ".." if len(o.libelle) > 50 else o.libelle
        print(f"  {o.id:<8} {libelle:<50} {LABEL_COURT[o.statut]} {source}")

    print()
    print("=" * LARGEUR)
    print("  SCORE GLOBAL")
    print("=" * LARGEUR)
    nb = score["nb_objectifs"]
    for statut, count in score["par_statut"].items():
        pct = count / nb * 100 if nb else 0
        barre = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        print(f"  {statut:<40} {count:>2}/{nb}  [{barre}] {pct:5.1f}%")
    print()
    pct_global = score["score_global"]
    print(f"  Score de conformité global : {pct_global:.1f}%")
    if pct_global < 25:
        print("  Niveau : Insuffisant — priorité aux connecteurs V2 et documents de gouvernance")
    elif pct_global < 50:
        print("  Niveau : Faible — la détection technique est en place, compléter la gouvernance")
    elif pct_global < 75:
        print("  Niveau : Moyen — renforcer la protection et la résilience")
    else:
        print("  Niveau : Bon — maintenir et affiner")
    print("=" * LARGEUR)
    print()

    # Détail des justifications
    print("  DÉTAIL DES JUSTIFICATIONS")
    print("=" * LARGEUR)
    for o in objectifs:
        icone = {"Couvert": "✓", "Partiel": "~",
                 "Non couvert - connecteur à venir": "○",
                 "Non couvert - action manuelle requise": "✗",
                 "Non vérifiable - source ambiguë": "⚠"}[o.statut.value]
        print(f"\n  [{icone}] {o.id} — {o.libelle}")
        # Découpe la justification pour ne pas dépasser 94 caractères par ligne
        mots, ligne = o.justification.split(), ""
        for mot in mots:
            if len(ligne) + len(mot) + 1 > 94:
                print(f"       {ligne}")
                ligne = mot
            else:
                ligne = (ligne + " " + mot).strip()
        if ligne:
            print(f"       {ligne}")
    print()
    print("=" * LARGEUR)
    print()


# ─── Sauvegarde JSON ──────────────────────────────────────────────────────────

def sauvegarder(objectifs: list[ObjectifReCyF], score: dict, chemin: str):
    rapport = {
        "version":         "2.0",
        "date_generation": datetime.now(timezone.utc).isoformat(),
        "score":           score,
        "objectifs": [
            {**asdict(o), "statut": o.statut.value}
            for o in objectifs
        ],
    }
    Path(chemin).write_text(
        json.dumps(rapport, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Rapport sauvegardé dans {chemin}")


# ─── Point d'entrée ───────────────────────────────────────────────────────────

def main():
    inv_data = charger("inventaire.json")
    agt_data = charger("agents_wazuh.json")
    alt_data = charger("alertes_wazuh.json")
    vul_data = charger("vulnerabilites_openvas.json")

    inv = analyser_inventaire(inv_data)
    agt = analyser_agents(agt_data)
    alt = analyser_alertes(alt_data)
    vul = analyser_vulnerabilites(vul_data)

    objectifs = evaluer(inv, agt, alt, vul)
    score     = calculer_score(objectifs)

    afficher_rapport(objectifs, score)
    sauvegarder(objectifs, score, "rapport_conformite.json")


if __name__ == "__main__":
    main()
