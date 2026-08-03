#!/bin/bash
# ===========================================================================
# setup_dashboard.sh
# Initialise le compte admin unique et les secrets applicatifs du dashboard
# NIS2/ReCyF. À exécuter UNE FOIS, depuis webapp/, dans le venv du projet.
#
# Ce script :
#   1. Génère le mot de passe admin (openssl rand), jamais en dur dans le code
#   2. Le hashe en bcrypt et l'insère dans la base SQLite (table utilisateurs)
#   3. Génère la clé de session (signature des cookies, SessionMiddleware)
#   4. Génère la clé Fernet applicative — destinée au chiffrement futur des
#      identifiants de connecteurs saisis via l'interface (pas encore utilisée)
#   5. Affiche le mot de passe admin généré (à noter, jamais réaffiché ensuite)
#
# Sécurité : data/ et secrets/ ne sont jamais committés (voir .gitignore).
# Le mot de passe en clair n'est jamais stocké, uniquement son hash bcrypt.
# ===========================================================================

set -e

cd "$(dirname "$0")"

if ! python3 -c "import bcrypt, cryptography" &>/dev/null; then
    echo "ERREUR : dépendances Python manquantes."
    echo "Lance d'abord : python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

echo ""
echo "========================================"
echo "  Setup Dashboard NIS2/ReCyF"
echo "========================================"
echo ""

mkdir -p data secrets
chmod 700 secrets

# --- 1. Mot de passe admin ---
PASSWORD=$(openssl rand -base64 18 | tr -d '/+=' | head -c 24)
echo "[1/4] Mot de passe admin généré"

# --- 2. Hash bcrypt + insertion SQLite (idempotent : met à jour si "admin" existe déjà) ---
python3 <<PYEOF
import bcrypt, sqlite3

conn = sqlite3.connect("data/dashboard.db")
conn.execute("""
    CREATE TABLE IF NOT EXISTS utilisateurs (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
    )
""")
hash_ = bcrypt.hashpw("${PASSWORD}".encode(), bcrypt.gensalt()).decode()
conn.execute(
    "INSERT INTO utilisateurs (username, password_hash) VALUES (?, ?) "
    "ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash",
    ("admin", hash_),
)
conn.commit()
conn.close()
PYEOF
echo "[2/4] Compte admin créé/mis à jour dans data/dashboard.db"

# --- 3. Clé de session ---
if [ ! -f secrets/session_secret.key ]; then
    openssl rand -hex 32 > secrets/session_secret.key
    chmod 600 secrets/session_secret.key
    echo "[3/4] Clé de session générée"
else
    echo "[3/4] Clé de session déjà présente, conservée"
fi

# --- 4. Clé Fernet (chiffrement futur des identifiants de connecteurs) ---
if [ ! -f secrets/fernet.key ]; then
    python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > secrets/fernet.key
    chmod 600 secrets/fernet.key
    echo "[4/4] Clé Fernet générée (préparation V-suivante, pas encore utilisée)"
else
    echo "[4/4] Clé Fernet déjà présente, conservée"
fi

echo ""
echo "========================================"
echo "  MOT DE PASSE ADMIN (à noter maintenant)"
echo "========================================"
echo "Identifiant  : admin"
echo "Mot de passe : ${PASSWORD}"
echo ""
echo "Ce mot de passe n'est stocké nulle part en clair — uniquement son hash bcrypt"
echo "dans data/dashboard.db. Il ne sera plus jamais réaffiché par ce script."
echo ""
echo "Script terminé."
