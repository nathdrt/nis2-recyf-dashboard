#!/bin/bash
# ===========================================================================
# setup_glpi_connector.sh
# Configure un compte GLPI dédié "lecture seule" pour le connecteur NIS2.
# À exécuter en SSH sur le conteneur GLPI (root@192.168.1.105), une seule fois.
#
# Ce script :
#   1. Active l'API REST GLPI en base de données
#   2. Crée un client API (App-Token) dans glpi_api_clients
#   3. Crée un profil "API-ReadOnly-NIS2" avec droits de lecture uniquement
#   4. Crée l'utilisateur "connecteur-api" avec ce profil
#   5. Affiche les valeurs à copier dans .env
#
# Sécurité : aucun droit d'écriture accordé. Lecture seule sur l'inventaire.
# ===========================================================================

set -e  # Arrêter immédiatement en cas d'erreur

# --- Pré-requis ---
if ! command -v php &>/dev/null; then
    echo "ERREUR : PHP introuvable. Ce script doit tourner sur le conteneur GLPI."
    exit 1
fi

if ! mysql glpi -e "SELECT 1;" &>/dev/null 2>&1; then
    echo "ERREUR : Impossible de se connecter à MySQL (base 'glpi')."
    echo "Essaie : mysql -u root -p glpi"
    exit 1
fi

echo ""
echo "========================================"
echo "  Setup connecteur API GLPI — NIS2"
echo "========================================"
echo ""

# --- Génération des secrets ---
PASSWORD=$(openssl rand -base64 18 | tr -d '/+=' | head -c 24)
HASH=$(php -r "echo password_hash('${PASSWORD}', PASSWORD_DEFAULT);")
USER_TOKEN=$(php -r "echo bin2hex(random_bytes(32));")
APP_TOKEN=$(php -r "echo bin2hex(random_bytes(32));")
NOW=$(date '+%Y-%m-%d %H:%M:%S')

# --- 1. Activer l'API REST ---
mysql glpi -e "UPDATE glpi_configs SET value='1' WHERE name='enable_api' AND context='core';"
# enable_api_login_credentials : autorise auth login/pass (on laisse à 0, on utilise user_token)
echo "[1/6] API REST activée"

# --- 2. Créer le client API (App-Token) ---
# glpi_api_clients existe depuis GLPI 9.1. Si ton GLPI est plus ancien, cette
# étape échouera — signale-le pour adapter.
EXISTING_CLIENT=$(mysql glpi -sN -e "SELECT COUNT(*) FROM glpi_apiclients WHERE name='connecteur-nis2';")
if [ "$EXISTING_CLIENT" -gt 0 ]; then
    mysql glpi -e "
        UPDATE glpi_apiclients
        SET app_token='${APP_TOKEN}', app_token_date='${NOW}', is_active=1, date_mod='${NOW}'
        WHERE name='connecteur-nis2';
    "
    echo "[2/6] Client API mis à jour (existait déjà)"
else
    mysql glpi -e "
        INSERT INTO glpi_apiclients
            (name, is_active, app_token, app_token_date, entities_id, is_recursive, date_creation, date_mod)
        VALUES
            ('connecteur-nis2', 1, '${APP_TOKEN}', '${NOW}', 0, 1, '${NOW}', '${NOW}');
    "
    echo "[2/6] Client API créé"
fi

# --- 3. Créer le profil lecture seule ---
EXISTING_PROFILE=$(mysql glpi -sN -e "SELECT COUNT(*) FROM glpi_profiles WHERE name='API-ReadOnly-NIS2';")
if [ "$EXISTING_PROFILE" -gt 0 ]; then
    PROFILE_ID=$(mysql glpi -sN -e "SELECT id FROM glpi_profiles WHERE name='API-ReadOnly-NIS2';")
    echo "[3/6] Profil déjà existant (id=${PROFILE_ID})"
else
    mysql glpi -e "
        INSERT INTO glpi_profiles (name, interface, is_default, date_creation, date_mod)
        VALUES ('API-ReadOnly-NIS2', 'central', 0, '${NOW}', '${NOW}');
    "
    PROFILE_ID=$(mysql glpi -sN -e "SELECT id FROM glpi_profiles WHERE name='API-ReadOnly-NIS2';")
    echo "[3/6] Profil créé (id=${PROFILE_ID})"
fi

# --- 4. Affecter les droits de LECTURE uniquement au profil ---
# Dans GLPI, les droits sont un bitmask : 1=Lecture, 2=Modif, 4=Création, 8=Suppression, 16=Purge
# On n'attribue que la valeur 1 (lecture seule) sur chaque ressource.
mysql glpi -e "DELETE FROM glpi_profilerights WHERE profiles_id=${PROFILE_ID};"
mysql glpi -e "
    INSERT INTO glpi_profilerights (profiles_id, name, rights) VALUES
    (${PROFILE_ID}, 'computer',      1),
    (${PROFILE_ID}, 'software',      1),
    (${PROFILE_ID}, 'networking',    1),
    (${PROFILE_ID}, 'internet',      1),
    (${PROFILE_ID}, 'infocom',       1),
    (${PROFILE_ID}, 'location',      1),
    (${PROFILE_ID}, 'state',         1),
    (${PROFILE_ID}, 'manufacturer',  1),
    (${PROFILE_ID}, 'operatingsystem', 1);
"
echo "[4/6] Droits lecture seule assignés (9 ressources, aucun droit d'écriture)"

# --- 5. Créer l'utilisateur connecteur-api ---
EXISTING_USER=$(mysql glpi -sN -e "SELECT COUNT(*) FROM glpi_users WHERE name='connecteur-api';")
if [ "$EXISTING_USER" -gt 0 ]; then
    USER_ID=$(mysql glpi -sN -e "SELECT id FROM glpi_users WHERE name='connecteur-api';")
    mysql glpi -e "
        UPDATE glpi_users
        SET password='${HASH}',
            api_token='${USER_TOKEN}',
            api_token_date='${NOW}',
            is_active=1,
            is_deleted=0,
            date_mod='${NOW}'
        WHERE id=${USER_ID};
    "
    echo "[5/6] Utilisateur mis à jour (existait déjà, id=${USER_ID})"
else
    mysql glpi -e "
        INSERT INTO glpi_users
            (name, password, firstname, realname, is_active, is_deleted,
             api_token, api_token_date, date_creation, date_mod)
        VALUES
            ('connecteur-api', '${HASH}', 'Connecteur', 'API NIS2', 1, 0,
             '${USER_TOKEN}', '${NOW}', '${NOW}', '${NOW}');
    "
    USER_ID=$(mysql glpi -sN -e "SELECT id FROM glpi_users WHERE name='connecteur-api';")
    echo "[5/6] Utilisateur créé (id=${USER_ID})"
fi

# --- 6. Assigner le profil à l'utilisateur ---
EXISTING_ASSIGN=$(mysql glpi -sN -e "
    SELECT COUNT(*) FROM glpi_profiles_users
    WHERE profiles_id=${PROFILE_ID} AND users_id=${USER_ID};
")
if [ "$EXISTING_ASSIGN" -eq 0 ]; then
    mysql glpi -e "
        INSERT INTO glpi_profiles_users (profiles_id, users_id, entities_id, is_recursive, is_dynamic)
        VALUES (${PROFILE_ID}, ${USER_ID}, 0, 1, 0);
    "
fi
echo "[6/6] Profil assigné à l'utilisateur"

# --- Vérification finale ---
echo ""
API_STATUS=$(mysql glpi -sN -e "SELECT value FROM glpi_configs WHERE name='enable_api' AND context='core';")
echo "Vérification — API activée : ${API_STATUS} (doit être 1)"
echo ""

# --- Résumé à copier dans .env ---
echo "========================================"
echo "  VALEURS À COPIER DANS .env"
echo "========================================"
echo ""
echo "GLPI_URL=http://192.168.1.105"
echo "GLPI_APP_TOKEN=${APP_TOKEN}"
echo "GLPI_USER_TOKEN=${USER_TOKEN}"
echo ""
echo "========================================"
echo "  MOT DE PASSE DU COMPTE connecteur-api"
echo "  (pour référence, inutile dans .env)"
echo "========================================"
echo "${PASSWORD}"
echo ""
echo "Script terminé. Copie les valeurs ci-dessus dans ton fichier .env."
