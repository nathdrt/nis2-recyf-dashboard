# NIS2 / ReCyF Compliance Dashboard

Tableau de bord de conformité NIS2, basé sur le référentiel **ReCyF de l'ANSSI**.  
Aggrège des données depuis des outils open source (GLPI, Wazuh, OpenVAS à venir)  
et les remappe sur les 20 objectifs ReCyF pour produire un score de conformité  
et un rapport exportable.

Destiné aux MSPs qui souhaitent offrir un service de suivi NIS2 à leurs clients PME.

---

## Prérequis

- Python 3.10+
- Un virtualenv : `python -m venv venv && source venv/bin/activate`
- Dépendances : `pip install -r requirements.txt`
- Un fichier `.env` rempli (copier `.env.example` et renseigner les valeurs)

---

## Connecteur GLPI

**Fichier :** `connecteur_glpi.py`  
**Sortie :** `inventaire.json`

Récupère la liste des ordinateurs depuis l'API REST GLPI et la sauvegarde localement.

### Variables `.env` nécessaires

```
GLPI_URL=http://<ip-glpi>
GLPI_APP_TOKEN=<app_token>
GLPI_USER_TOKEN=<user_token>
OUTPUT_FILE=inventaire.json       # optionnel
```

### Créer le compte dédié GLPI

Utiliser le script `setup_glpi_connector.sh` directement sur le serveur GLPI :

```bash
scp setup_glpi_connector.sh root@<ip-glpi>:/tmp/
ssh root@<ip-glpi> "bash /tmp/setup_glpi_connector.sh"
```

Le script :
- Active l'API REST GLPI en base de données
- Crée un client API (`connecteur-nis2`) et génère l'`App-Token`
- Crée un profil `API-ReadOnly-NIS2` (lecture seule sur 9 ressources, aucun droit d'écriture)
- Crée l'utilisateur `connecteur-api` avec ce profil et génère le `User-Token`
- Affiche les valeurs à copier dans `.env`

> **Note technique (GLPI 10.x) :** la table des clients API s'appelle `glpi_apiclients`
> (sans underscore), et le token d'authentification API est la colonne `api_token`
> dans `glpi_users` (pas `personal_token`).

### Lancer le connecteur

```bash
source venv/bin/activate
python connecteur_glpi.py
```

---

## Connecteur Wazuh

**Fichier :** `connecteur_wazuh.py`  
**Sortie :** `agents_wazuh.json`

Récupère la liste des agents Wazuh et leur statut (actif / déconnecté / jamais connecté)
depuis l'API REST du Wazuh Manager.

### Variables `.env` nécessaires

```
WAZUH_URL=https://<ip-wazuh>:55000
WAZUH_USER=connecteur-api
WAZUH_PASSWORD=<mot_de_passe>
WAZUH_OUTPUT_FILE=agents_wazuh.json   # optionnel
```

### Créer le compte dédié Wazuh

L'API Wazuh gère les accès avec un système RBAC (rôles → politiques → utilisateurs).
Le rôle intégré **`agents_readonly`** donne exactement les droits nécessaires :
lecture des agents uniquement, aucune écriture.

Depuis le serveur Wazuh (en SSH), avec le mot de passe de l'admin API (`wazuh`) :

```bash
# 1. Obtenir un token JWT admin
TOKEN=$(curl -sk -X GET 'https://localhost:55000/security/user/authenticate' \
  -u 'wazuh:<mot_de_passe_admin>' | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['token'])")

# 2. Créer l'utilisateur
curl -sk -X POST 'https://localhost:55000/security/users' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username": "connecteur-api", "password": "<mot_de_passe_fort>"}'

# 3. Récupérer l'ID du rôle agents_readonly
ROLE_ID=$(curl -sk 'https://localhost:55000/security/roles' \
  -H "Authorization: Bearer $TOKEN" | \
  python3 -c "import json,sys; roles=json.load(sys.stdin)['data']['affected_items']; \
  print([r['id'] for r in roles if r['name']=='agents_readonly'][0])")

# 4. Assigner le rôle à l'utilisateur (adapter USER_ID selon la réponse de l'étape 2)
curl -sk -X POST "https://localhost:55000/security/users/<USER_ID>/roles?role_ids=$ROLE_ID" \
  -H "Authorization: Bearer $TOKEN"
```

> **Note :** L'API Wazuh utilise un certificat TLS auto-signé. Le connecteur
> désactive la vérification du certificat (`verify=False`) et supprime les warnings
> associés. En production, remplacer par le vrai certificat de l'AC Wazuh.

> **Note technique (Wazuh 4.14+) :** Le champ `allow_run_as` n'existe plus dans
> le payload de création d'utilisateur. Le mot de passe doit contenir majuscule,
> minuscule, chiffre et caractère spécial.

### Lancer le connecteur

```bash
source venv/bin/activate
python connecteur_wazuh.py
```

---

## Structure du projet

```
nis2-dashboard/
├── connecteur_glpi.py         # Connecteur GLPI (inventaire)
├── connecteur_wazuh.py        # Connecteur Wazuh (agents)
├── setup_glpi_connector.sh    # Script de setup GLPI (à exécuter sur le serveur)
├── requirements.txt
├── .env.example               # Template des variables d'environnement
├── .env                       # Variables réelles — NE PAS COMMITTER
├── .gitignore
└── README.md
```

## Roadmap

- [x] Connecteur GLPI — inventaire des ordinateurs
- [x] Connecteur Wazuh — état des agents
- [ ] Connecteur Wazuh — alertes de sécurité
- [ ] Connecteur OpenVAS — vulnérabilités
- [ ] Moteur de scoring ReCyF (20 objectifs)
- [ ] Export rapport PDF/HTML
