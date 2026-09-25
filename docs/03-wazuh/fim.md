# File Integrity Monitoring (FIM)

## Rôle dans le pipeline

Le FIM Wazuh (module `syscheck`) surveille des fichiers/répertoires sur les agents. Les événements (création, modification, suppression) sont récupérés par `surveillance_soc.py` via `WazuhClient.get_fim_events()`, qui interroge l'[Indexer](../08-automatisation-soc/source-des-donnees.md) sur les événements `syscheck` des dernières minutes uniquement (jamais l'historique complet, pour éviter le flood).

📖 Doc officielle — présentation générale : [File Integrity Monitoring overview](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

## Traitement (`process_fim_event` dans `surveillance_soc.py`)

| Type d'événement | Action |
|---|---|
| Fichier **créé** | Notification Telegram + analyse automatique (voir ci-dessous) |
| Fichier **modifié** | Notification Telegram (avec hash avant/après si disponible) + analyse automatique |
| Fichier **supprimé** | Notification Telegram uniquement (pas d'analyse possible, plus de fichier) |

## Analyse automatique (`_fim_auto_analyze`)

Pour un fichier créé ou modifié **avec un hash SHA256 exploitable** :

1. Un **Case TheHive** est créé automatiquement (`thehive.create_fim_case()`), avec le hash en observable.
2. Le case est mis en file pour `response_soc.py`, qui lance les analyzers Cortex (VirusTotal...) et synthétise le résultat via Groq.
3. Le résultat final est renvoyé sur Telegram.

## Anti-spam spécifique au FIM

Deux niveaux de throttle indépendants (1h chacun, via `should_alert()`) :
- **Notification** (`fim_notif:{agent}:{file}:{action}`) : évite de spammer Telegram si un fichier change en boucle (ex. log applicatif réécrit en continu).
- **Analyse** (`fim_analyze:{agent}:{file}`) : évite de recréer un case TheHive à chaque cycle pour le même fichier.

## Lien avec Active Response

Si l'analyse Cortex/Groq identifie le fichier comme malveillant, la suite du traitement peut relever de `remove-threat` côté Wazuh — voir [Active Response](active-response.md) et la catégorie `THREAT_REMOVED` dans [classification-alertes.md](../08-automatisation-soc/classification-alertes.md).

## Configuration réelle (`/var/ossec/etc/ossec.conf`)

```xml
<syscheck>
  <disabled>no</disabled>

  <!-- Fréquence de scan complet : toutes les 12h -->
  <frequency>43200</frequency>

  <scan_on_start>yes</scan_on_start>

  <!-- Génère une alerte quand un nouveau fichier est détecté -->
  <alert_new_files>yes</alert_new_files>

  <!-- Ne pas ignorer les fichiers qui changent souvent -->
  <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

  <!-- Dossiers surveillés (vérification complète) -->
  <directories>/etc,/usr/bin,/usr/sbin</directories>
</syscheck>
```

Points clés pour comprendre le comportement observé :
- **`scan_on_start=yes`** : un scan complet se lance dès le démarrage de l'agent, en plus du cycle de 12h — utile pour une démo (pas besoin d'attendre 12h pour voir un premier scan).
- **`auto_ignore=no`** : contrairement au comportement par défaut de Wazuh, un fichier qui change en boucle continue à générer des événements FIM au lieu d'être mis en sourdine après 10 changements/heure — c'est le mécanisme anti-spam **côté script** (`fim_notif` / `fim_analyze` throttle, voir plus haut) qui gère ça, pas Wazuh.
- **Dossiers surveillés** : `/etc`, `/usr/bin`, `/usr/sbin` — binaires système et configuration, pas de surveillance temps réel (`realtime`/`whodata`) activée ici, donc la détection dépend du cycle de scan (immédiat au démarrage, puis toutes les 12h).

📖 Syntaxe complète du bloc `<syscheck>` : [Syscheck reference (ossec.conf)](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html)

## Documentation officielle

- [File Integrity Monitoring — vue d'ensemble](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Syscheck — référence de configuration `ossec.conf`](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html)
- [Guide pratique FIM (proof of concept)](https://documentation.wazuh.com/current/proof-of-concept-guide/index.html)
