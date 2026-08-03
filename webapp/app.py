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
