import requests

reponse = requests.get("https://jsonplaceholder.typicode.com/todos?_limit=5")

if reponse.status_code == 200:
    taches = reponse.json()
    for tache in taches:
        print(tache["title"])
else:
    print("Erreur, code reçu :")
    print(reponse.status_code)
