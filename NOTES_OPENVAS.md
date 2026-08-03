# Notes — Connecteur OpenVAS/Greenbone

## ⚠️ Le rôle Observer ne voit rien par défaut

Sur cette instance Greenbone, le compte `connecteur-api` a le rôle **Observer**
(lecture seule, volontairement — jamais de droits d'écriture).

Contrairement à ce qu'on pourrait attendre d'un rôle "admin", **le rôle GMP
"Admin" lui-même n'a aucune visibilité automatique sur les objets créés par
d'autres comptes** — seul le rôle "Super Admin" l'a. Ce n'est donc pas
spécifique à Observer : c'est le modèle de permissions de Greenbone.
Conséquence vérifiée en pratique : une tâche de scan créée par `admin` est
**invisible** pour `connecteur-api` tant qu'elle n'a pas été explicitement
partagée.

Vérifié en direct (03/08/2026) :
- `create_permission(...)` échoue avec `404 Failed to find subject` quand on
  l'appelle depuis le compte `admin` (rôle Admin) pour référencer
  `connecteur-api` comme sujet — `admin` ne peut même pas "voir" l'existence
  du compte `connecteur-api` via GMP.
- `modify_task(task_id=..., observers=['connecteur-api'])` fonctionne
  (200 OK) — c'est le mécanisme natif GMP conçu pour ce cas : le
  propriétaire d'une tâche peut la partager en lecture à un utilisateur
  précis, sans que ce dernier ait besoin d'être "visible" comme sujet de
  permission générique.

## Règle à respecter pour toute nouvelle tâche de scan

**Peu importe la méthode utilisée pour créer une tâche de scan sur cette
instance** (interface web GSA, script GMP, autre session) — il faut
explicitement partager la tâche avec `connecteur-api` :

```python
gmp.modify_task(task_id="<uuid-de-la-tache>", observers=["connecteur-api"])
```

ou, si le partage est fait dès la création :

```python
gmp.create_task(..., observers=["connecteur-api"])
```

Sans cette étape, `connecteur_openvas.py` produira un JSON avec
`nombre_taches: 0` et `nombre_resultats: 0` — **ce n'est pas la preuve qu'il
n'y a aucune vulnérabilité**, seulement que le connecteur ne voit rien. Le
script ajoute un champ `"avertissement"` dans le JSON de sortie précisément
dans ce cas, pour ne pas laisser croire à un parc sans vulnérabilité alors
que le vrai problème est un défaut de partage.

## Pourquoi pas une solution plus automatique ?

- Élever `connecteur-api` en rôle Admin/Super Admin casserait la contrainte
  stricte de lecture seule imposée pour ce compte.
- Élever `admin` en Super Admin résoudrait le problème de visibilité côté
  admin, mais n'a pas été fait ici : ça reste une option à évaluer si la
  gestion manuelle des `observers` devient contraignante à l'usage.
