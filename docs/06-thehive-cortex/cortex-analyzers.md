# Cortex Analyzers — tutoriel complet (VirusTotal + AbuseIPDB)

Ce projet utilise deux analyzers Cortex, confirmés dans le code (`soc_config.py` — `CortexResult._extract_score()` reconnaît spécifiquement `"VT"` et `"ABUSE"` dans le nom de l'analyzer pour calculer un score de malveillance) :

- **VirusTotal_GetReport** — réputation IP/hash/domaine via VirusTotal
- **AbuseIPDB** — score de réputation IP via AbuseIPDB

## Étape 0 — Récupérer le code des analyzers sur l'hôte (prérequis souvent oublié)

Le [docker-compose.yml](docker-compose.yml) monte `/opt/Cortex-Analyzers` **depuis l'hôte** vers le conteneur (`- /opt/Cortex-Analyzers:/opt/Cortex-Analyzers`). Ce dossier doit donc exister et contenir le code **avant** de démarrer les conteneurs — sinon Cortex ne trouve aucun analyzer.

```bash
sudo git clone https://github.com/TheHive-Project/Cortex-Analyzers.git /opt/Cortex-Analyzers
```

> Si les conteneurs tournaient déjà sans ce dossier, redémarre `cortex.local` après le clone : `docker compose restart cortex.local`.

## Étape 1 — Obtenir les clés API

| Service | Où l'obtenir | Limite gratuite |
|---|---|---|
| VirusTotal | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) → Profil → API Key | ~4 requêtes/min (compte gratuit) |
| AbuseIPDB | [abuseipdb.com/register](https://www.abuseipdb.com/register) → Account → API | 1000 requêtes/jour (compte gratuit) |

## Étape 2 — Installer les dépendances Python *dans le conteneur*

Les analyzers sont des scripts Python exécutés **dans le conteneur** `cortex.local`, pas sur l'hôte. Chacun a son propre `requirements.txt` à installer séparément.

```bash
docker exec -it cortex.local bash

# Installer python3 si absent dans l'image
apt update && apt install -y python3 python3-pip

# VirusTotal
cd /opt/Cortex-Analyzers/analyzers/VirusTotal
pip3 install -r requirements.txt

# AbuseIPDB
cd /opt/Cortex-Analyzers/analyzers/AbuseIPDB
pip3 install -r requirements.txt

exit
```

> ⚠️ Sans cette étape : l'analyzer échoue avec `ModuleNotFoundError` dans le rapport Cortex. Comme `/opt/Cortex-Analyzers` est monté depuis l'hôte, le *code* survit à un `docker compose down/up`, mais les paquets `pip3 install` faits *dans* le conteneur sont perdus si le conteneur est recréé — à refaire dans ce cas (`apt install python3-pip` + les deux `pip3 install -r requirements.txt`).

## Étape 3 — Activer les analyzers

> ⚡ **Raccourci scripté** : une fois un compte org-admin créé (Étape 3 manuelle ci-dessous, incontournable au moins une fois — Cortex n'expose aucun autre moyen de créer le tout premier compte), `bash activate-analyzers.sh` fait le `+ Create` + collage de clé à ta place via l'API Cortex, pour les deux analyzers. Il te demande ta clé API Cortex et tes clés VirusTotal/AbuseIPDB. Best-effort : si l'appel échoue, il affiche l'erreur HTTP exacte et tu retombes sur les étapes manuelles ci-dessous.

### Manuellement, dans l'interface Cortex

1. Se connecter à Cortex (`http://IP_VM:9001`) avec un compte `orgadmin`.
2. Aller dans **Organization → Analyzers**.
3. Chercher `VirusTotal_GetReport_3_1` (ou la version la plus récente listée) → **+ Create**.
   - Champ `key` → coller la clé API VirusTotal.
   - Laisser les autres réglages par défaut, **Create**.
4. Chercher `AbuseIPDB_1_0` → **+ Create**.
   - Champ `key` → coller la clé API AbuseIPDB.
   - **Create**.

## Étape 4 — Vérifier que ça marche vraiment (ne pas sauter cette étape)

Avant de compter dessus dans le pipeline automatique, teste chaque analyzer manuellement :

1. Dans Cortex : **Analyzers** (menu du haut) → choisir le type d'observable `ip` → coller une IP publique connue (ex. `8.8.8.8`) → **Run all**.
2. Attendre la fin du job (icône qui passe de "En cours" à un statut final).
3. **Statuts possibles** :
   - ✅ **Success** avec un rapport rempli → l'analyzer fonctionne.
   - ❌ **Failure** → clique sur le job pour voir l'erreur exacte (`Get Report`). Les causes les plus fréquentes :
     - `ModuleNotFoundError` → retourne à l'Étape 2, les dépendances ne sont pas installées.
     - `401 Unauthorized` / `Invalid API key` → clé API mal renseignée à l'Étape 3.
     - `429 Too Many Requests` → quota API dépassé (VirusTotal gratuit = 4 req/min, attends 1 minute).
   - ⏳ **Timeout** → augmente `CORTEX_TIMEOUT` dans `.env` du script (`soc-automation/.env`) si le job dépasse la valeur configurée côté Cortex, ou vérifie la connectivité sortante du conteneur vers Internet (`docker exec -it cortex.local curl -s https://www.virustotal.com`).

Si les deux analyzers renvoient **Success** sur ce test manuel, l'intégration avec `soc-automation/response_soc.py` (qui appelle `analyze_observable()` dans `soc_clients.py`) fonctionnera de la même façon — le script ne fait rien de plus qu'automatiser exactement cette même requête API.

## Diagnostiquer depuis les logs du conteneur

```bash
docker compose logs -f cortex.local
```

Utile si un job reste bloqué en "En cours" indéfiniment, ou pour voir la trace Python complète d'une erreur qui n'apparaît pas en entier dans l'interface.

## Lien avec le reste du pipeline

Voir [source-des-donnees.md](../08-automatisation-soc/source-des-donnees.md) et [classification-alertes.md](../08-automatisation-soc/classification-alertes.md) pour comment `response_soc.py` déclenche ces analyzers automatiquement sur chaque nouveau case TheHive, puis synthétise les deux rapports (VirusTotal + AbuseIPDB) via Groq avant de renvoyer le résultat sur Telegram.
