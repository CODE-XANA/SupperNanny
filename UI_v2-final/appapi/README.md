# API

Gérer des fichiers `.env` et communiquer avec un script de règles. L'API est accessible à l'adresse :  
`http://127.0.0.1:8080`

## Table des matières

- [Endpoints de Gestion des Fichiers .env](#endpoints-de-gestion-des-fichiers-env)
- [Endpoints pour la Communication avec le Script Interactif](#endpoints-pour-la-communication-avec-le-script)
- [Exemples de Curl](#exemples-de-curl)

---

## Endpoints de Gestion des Fichiers .env

### 1. Lister les fichiers .env
**GET** `/envs`

```bash
curl http://127.0.0.1:8080/envs
```

### 2. Lire le contenu d'un fichier .env
**GET** `/env/{program}`

Remplacez `{program}` par le nom du programme (ex. `cat`).

```bash
curl http://127.0.0.1:8080/env/cat
```

### 3. Créer un fichier .env
**POST** `/env`

```bash
curl -X POST http://127.0.0.1:8080/env   -H "Content-Type: application/json"   -d '{
        "program": "cat",
        "ll_fs_ro": "/bin:/usr",
        "ll_fs_rw": "/tmp",
        "ll_tcp_bind": "9418",
        "ll_tcp_connect": "80:443"
      }'
```

### 4. Mettre à jour un fichier .env existant
**PUT** `/env/{program}`

```bash
curl -X PUT http://127.0.0.1:8080/env/cat   -H "Content-Type: application/json"   -d '{
        "ll_fs_ro": ["/bin", "/usr"],
        "ll_fs_rw": ["/tmp"],
        "ll_tcp_bind": "9418",
        "ll_tcp_connect": "80:443"
      }'
```

### 5. Supprimer un fichier .env
**DELETE** `/env/{program}`

```bash
curl -X DELETE http://127.0.0.1:8080/env/cat
```

---

## Endpoints pour la Communication avec le Script

Ces endpoints permettent au script de communiquer avec l'API pour attendre et récupérer une réponse (r, w ou s).

### 1. Envoyer un Prompt depuis le Script
**POST** `/script_prompt`

Le script envoie un prompt en spécifiant le nom de l'application et le chemin concerné.

```bash
curl -X POST http://127.0.0.1:8080/script_prompt   -H "Content-Type: application/json"   -d '{"app": "cat", "path": "test"}'
```

*L'API répondra : "Prompt enregistré" et affichera un log indiquant que le script attend une réponse.*

### 2. Récupérer le Choix (GET)
Le script interroge régulièrement cet endpoint pour obtenir la réponse définie par l'utilisateur.

**GET** `/get_choice?app=cat&path=test`

```bash
curl "http://127.0.0.1:8080/get_choice?app=cat&path=test"
```

*Au départ, cette commande renverra une chaîne vide tant qu'aucun choix n'a été défini.*

### 3. Définir le Choix (POST)
Pour définir le choix (par exemple "r" pour read-only), utiliser l'endpoint suivant. Cet appel sera fait par l'utilisateur (ou via le frontend).

**POST** `/set_choice`

```bash
curl -X POST http://127.0.0.1:8080/set_choice   -H "Content-Type: application/json"   -d '{"app": "cat", "path": "test", "choice": "r"}'
```

*L'API répondra : "Réponse enregistrée" et le script récupérera ce choix lors de sa prochaine interrogation.*

---

## Résumé du Workflow

1. **Lancer le Script Externe**  
   Dans un terminal, exécuter :
   ```bash
   ./truc.sh cat test.txt
   ```
   Avec truc.sh (le script), et un cat test.txt (pour tester les permerssions qu'à le cat sur test.txt)
   Le script s'exécute et lorsqu'il arrive à la demande de choix il envoie automatiquement un POST à `/script_prompt`.

2. **Vérifier le Prompt dans l'API**  
   Dans la console de l'API, on doit voir :
   ```
   [API] Reçu prompt: Le script pour l'app 'cat' et path 'test' attend une réponse.
   ```
   Et le script continue d'interroger `/get_choice` en attendant une réponse.

3. **Fournir le Choix**  
   Dans un autre terminal, envoie du choix avec :
   ```bash
   curl -X POST http://127.0.0.1:8080/set_choice      -H "Content-Type: application/json"      -d '{"app": "cat", "path": "test", "choice": "r"}'
   ```
   L'API enregistre le choix et le script récupère ce choix pour continuer.

---