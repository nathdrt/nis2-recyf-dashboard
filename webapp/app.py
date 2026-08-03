#!/usr/bin/env python3
"""
Dashboard NIS2/ReCyF — squelette applicatif FastAPI.

Jalon 1 : infrastructure et authentification uniquement. La configuration
des connecteurs, le lancement des scans et la visualisation des scores
sont des jalons séparés, pas encore implémentés ici.

Aucun secret en dur : le compte admin et les clés (session, Fernet) sont
générés par setup_dashboard.sh et lus depuis data/ et secrets/ (jamais
committés, voir .gitignore).
"""

import sqlite3
from pathlib import Path

import bcrypt
from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

import db
import schemas_connecteurs
import test_connexion

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "dashboard.db"
SESSION_SECRET_FILE = BASE_DIR / "secrets" / "session_secret.key"

if not SESSION_SECRET_FILE.exists() or not DB_PATH.exists():
    raise RuntimeError(
        "Configuration manquante (secrets/session_secret.key ou data/dashboard.db). "
        "Lance setup_dashboard.sh avant de démarrer l'application."
    )

SESSION_SECRET = SESSION_SECRET_FILE.read_text().strip()

app = FastAPI(title="NIS2/ReCyF Dashboard")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, session_cookie="nis2_session")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

db.init_connecteurs_table()


def verifier_identifiants(username: str, password: str) -> bool:
    """Vérifie un couple identifiant/mot de passe contre la base SQLite."""
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT password_hash FROM utilisateurs WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return False
    return bcrypt.checkpw(password.encode(), row[0].encode())


@app.get("/")
def racine():
    return RedirectResponse(url="/dashboard")


@app.get("/login")
def afficher_login(request: Request):
    if request.session.get("user"):
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse(request, "login.html", {"erreur": None})


@app.post("/login")
def traiter_login(request: Request, username: str = Form(...), password: str = Form(...)):
    if verifier_identifiants(username, password):
        request.session["user"] = username
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"erreur": "Identifiant ou mot de passe incorrect."},
        status_code=401,
    )


@app.get("/logout")
def deconnexion(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login")


@app.get("/dashboard")
def afficher_dashboard(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse(request, "dashboard.html", {"user": user})


# ─── Connecteurs ──────────────────────────────────────────────────────────────

@app.get("/connecteurs")
def liste_connecteurs(request: Request):
    if not request.session.get("user"):
        return RedirectResponse(url="/login")
    connecteurs = db.lister_connecteurs()
    for c in connecteurs:
        c["libelle_type"] = schemas_connecteurs.SCHEMAS[c["type"]]["libelle"]
    return templates.TemplateResponse(request, "connecteurs_liste.html", {"connecteurs": connecteurs})


@app.get("/connecteurs/nouveau")
def nouveau_connecteur_form(request: Request):
    if not request.session.get("user"):
        return RedirectResponse(url="/login")
    return templates.TemplateResponse(
        request,
        "connecteur_form.html",
        {"schemas": schemas_connecteurs.SCHEMAS, "connecteur": None, "mode": "creation"},
    )


@app.post("/connecteurs/nouveau")
async def creer_connecteur_route(request: Request):
    if not request.session.get("user"):
        return RedirectResponse(url="/login")
    form = await request.form()
    type_ = form.get("type")
    schemas_connecteurs.valider_type(type_)
    schema = schemas_connecteurs.SCHEMAS[type_]
    nom = form.get("nom", "").strip()

    config_publique = {}
    for champ in schema["champs_publics"]:
        valeur = form.get(f"{type_}__{champ['nom']}", "").strip()
        if not valeur and "defaut" in champ:
            valeur = champ["defaut"]
        config_publique[champ["nom"]] = valeur

    secrets = {champ["nom"]: form.get(f"{type_}__{champ['nom']}", "") for champ in schema["champs_secrets"]}

    db.creer_connecteur(type_, nom, config_publique, secrets)
    return RedirectResponse(url="/connecteurs", status_code=303)


@app.get("/connecteurs/{connecteur_id}/modifier")
def modifier_connecteur_form(request: Request, connecteur_id: int):
    if not request.session.get("user"):
        return RedirectResponse(url="/login")
    connecteur = db.obtenir_connecteur(connecteur_id)
    if connecteur is None:
        return RedirectResponse(url="/connecteurs")
    return templates.TemplateResponse(
        request,
        "connecteur_form.html",
        {"schemas": schemas_connecteurs.SCHEMAS, "connecteur": connecteur, "mode": "edition"},
    )


@app.post("/connecteurs/{connecteur_id}/modifier")
async def modifier_connecteur_route(request: Request, connecteur_id: int):
    if not request.session.get("user"):
        return RedirectResponse(url="/login")
    existant = db.obtenir_connecteur_avec_secrets(connecteur_id)
    if existant is None:
        return RedirectResponse(url="/connecteurs")

    form = await request.form()
    type_ = existant["type"]  # le type n'est jamais modifiable après création
    schema = schemas_connecteurs.SCHEMAS[type_]
    nom = form.get("nom", "").strip()

    config_publique = {}
    for champ in schema["champs_publics"]:
        valeur = form.get(f"{type_}__{champ['nom']}", "").strip()
        if not valeur and "defaut" in champ:
            valeur = champ["defaut"]
        config_publique[champ["nom"]] = valeur

    # Un champ secret laissé vide = on conserve la valeur déjà enregistrée.
    secrets_fusionnes = dict(existant["secrets"])
    for champ in schema["champs_secrets"]:
        valeur = form.get(f"{type_}__{champ['nom']}", "")
        if valeur:
            secrets_fusionnes[champ["nom"]] = valeur

    db.modifier_connecteur(connecteur_id, nom, config_publique, secrets_fusionnes)
    return RedirectResponse(url="/connecteurs", status_code=303)


@app.post("/connecteurs/{connecteur_id}/supprimer")
def supprimer_connecteur_route(request: Request, connecteur_id: int):
    if not request.session.get("user"):
        return RedirectResponse(url="/login")
    db.supprimer_connecteur(connecteur_id)
    return RedirectResponse(url="/connecteurs", status_code=303)


@app.post("/connecteurs/{connecteur_id}/tester")
def tester_connecteur_route(request: Request, connecteur_id: int):
    if not request.session.get("user"):
        return RedirectResponse(url="/login")
    connecteur = db.obtenir_connecteur_avec_secrets(connecteur_id)
    if connecteur is None:
        return RedirectResponse(url="/connecteurs")
    ok, message = test_connexion.tester_connecteur(
        connecteur["type"], connecteur["config_publique"], connecteur["secrets"]
    )
    db.enregistrer_resultat_test(connecteur_id, f"{'OK' if ok else 'ECHEC'} — {message}")
    return RedirectResponse(url="/connecteurs", status_code=303)
