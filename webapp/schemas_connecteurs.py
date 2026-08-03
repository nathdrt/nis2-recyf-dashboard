#!/usr/bin/env python3
"""
Schéma déclaratif des 4 types de connecteurs supportés : quels champs sont
publics (stockés en clair dans config_publique) et lesquels sont secrets
(chiffrés en Fernet dans config_secrete).

Chaque champ : nom (clé JSON), label (affiché), type (text/password/number),
requis (bool), defaut (valeur pré-remplie côté formulaire, optionnel).
"""

SCHEMAS = {
    "glpi": {
        "libelle": "GLPI",
        "champs_publics": [
            {"nom": "url", "label": "URL GLPI", "type": "text", "requis": True},
        ],
        "champs_secrets": [
            {"nom": "app_token", "label": "App-Token", "requis": True},
            {"nom": "user_token", "label": "User-Token", "requis": True},
        ],
    },
    "wazuh_agents": {
        "libelle": "Wazuh — Agents",
        "champs_publics": [
            {"nom": "host", "label": "Hôte", "type": "text", "requis": True},
            {"nom": "port", "label": "Port", "type": "number", "defaut": 55000, "requis": True},
            {"nom": "user", "label": "Utilisateur", "type": "text", "requis": True},
        ],
        "champs_secrets": [
            {"nom": "password", "label": "Mot de passe", "requis": True},
        ],
    },
    "wazuh_alertes": {
        "libelle": "Wazuh — Alertes (Indexer)",
        "champs_publics": [
            {"nom": "host", "label": "Hôte", "type": "text", "requis": True},
            {"nom": "port", "label": "Port", "type": "number", "defaut": 9200, "requis": True},
            {"nom": "user", "label": "Utilisateur", "type": "text", "defaut": "readall", "requis": True},
            # L'Indexer OpenSearch n'écoute qu'en local sur la VM Wazuh (voir
            # connecteur_wazuh_alertes.py). Optionnel dans le formulaire, mais
            # en pratique requis pour que le test/l'exécution aboutisse.
            {"nom": "ssh_host", "label": "Hôte SSH (tunnel, alias ~/.ssh/config)", "type": "text", "requis": False},
        ],
        "champs_secrets": [
            {"nom": "password", "label": "Mot de passe", "requis": True},
        ],
    },
    "openvas": {
        "libelle": "OpenVAS/Greenbone",
        "champs_publics": [
            {"nom": "ssh_host", "label": "Hôte SSH", "type": "text", "requis": True},
            {"nom": "gmp_user", "label": "Utilisateur GMP", "type": "text", "defaut": "connecteur-api", "requis": True},
        ],
        "champs_secrets": [
            {"nom": "gmp_password", "label": "Mot de passe GMP", "requis": True},
        ],
    },
}


def valider_type(type_: str):
    if type_ not in SCHEMAS:
        raise ValueError(f"Type de connecteur inconnu : {type_}")
