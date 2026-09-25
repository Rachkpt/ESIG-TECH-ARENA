# Wazuh Active Response

## Pourquoi Active Response plutôt que le blocage local du script

Le SOC bloque les IPs malveillantes de deux façons :

1. **Blocage local via `iptables`**, exécuté par `surveillance_soc.py` lui-même — utilisé pour les catégories d'alertes non couvertes nativement par Wazuh.
2. **Wazuh Active Response** (`firewall-drop`) — méthode **préférée**, car elle s'exécute **directement sur l'agent Wazuh attaqué**, et protège donc la vraie machine ciblée. Le blocage local du script, lui, ne protège que le serveur qui héberge le script d'automatisation — pas la machine réellement visée par l'attaquant si elle est différente.

📖 Doc officielle — présentation générale : [Active Response overview](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)

## Réponses actives utilisées

| Réponse | Usage | Doc officielle |
|---|---|---|
| `firewall-drop` | Bloque l'IP source sur l'agent attaqué (règle firewall locale à l'agent) | [Default active response scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/default-active-response-scripts.html) |
| `remove-threat` | Suppression d'un fichier identifié comme malveillant (lié au FIM + VirusTotal, voir [FIM](fim.md)) | [Default active response scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/default-active-response-scripts.html) |

## Règles déclenchant une réponse active

Confirmé dans le code du script (`soc_config.py`, `soc_clients.py`) pour `firewall-drop` — ces `rules_id` sont bloqués **nativement côté Wazuh Manager**, donc exclus du blocage local du script (voir `NATIVE_AR_CATEGORIES` dans [classification-alertes.md](../08-automatisation-soc/classification-alertes.md)) :

| `rules_id` | Réponse | Catégorie |
|---|---|---|
| `5710`, `5712`, `5716`, `5720` | `firewall-drop` | Brute force SSH |
| `86601` | `firewall-drop` | Scans réseau détectés via Suricata (décodeur Wazuh intégré) |
| `87105` | `remove-threat` | Fichier identifié malveillant (voir [FIM](fim.md) et [VirusTotal](virustotal-integration.md)) |

## Configuration réelle (`/var/ossec/etc/ossec.conf`)

Trois blocs `<active-response>` sont déployés sur le Manager :

```xml
<!-- Suppression de fichier malveillant (voir FIM + VirusTotal) -->
<active-response>
  <disabled>no</disabled>
  <command>remove-threat</command>
  <location>local</location>
  <rules_id>87105</rules_id>
</active-response>

<!-- Brute force SSH — bloque l'IP sur l'agent attaqué -->
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5710,5712,5716,5720</rules_id>
  <timeout>7200</timeout>
</active-response>

<!-- Scans réseau détectés via Suricata — bloque sur l'agent scanné -->
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>86601</rules_id>
  <timeout>7200</timeout>
</active-response>
```

- Les deux blocs `firewall-drop` bloquent l'IP pendant **7200s (2h)**, puis Wazuh la débloque automatiquement.
- Le bloc `remove-threat` (rule `87105`) n'a **pas de `<timeout>`** : la suppression d'un fichier n'est pas une action réversible/temporaire, contrairement à un blocage IP.

📖 Syntaxe complète du bloc `<active-response>` : [Active response reference (ossec.conf)](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html)

## Déclenchement manuel depuis Telegram

Les blocs `<active-response>` ci-dessus ne se déclenchent que **nativement**, quand Wazuh matche lui-même une des `rules_id` listées. Un blocage **manuel** via `/block` ou `/ban` sur Telegram passait donc, jusqu'ici, uniquement par le blocage local du script (`iptables`/`nftables` + `fail2ban`) — qui ne protège que le serveur d'automatisation, pas forcément la machine réellement visée par l'attaquant (voir la justification en haut de cette page).

`WazuhClient.run_active_response()` (`soc_clients.py`) referme ce trou : sur `/block` et `/ban`, en plus du blocage local, le bot appelle l'API Wazuh (`PUT /active-response`) pour déclencher `firewall-drop0` sur **tous les agents actuellement connectés** (`status: active`), pas seulement celui qui a levé l'alerte — puisqu'un blocage manuel n'a par définition pas de `rules_id` pour savoir quel agent cibler.

📖 Doc officielle : [Active Response API reference](https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Active-response)

- Config : `WAZUH_AR_COMMAND` (défaut `firewall-drop0`) et `WAZUH_AR_ON_MANUAL_BLOCK` (défaut `true`) dans `soc-automation/.env`.
- ⚠️ **Best-effort, à valider en conditions réelles** : le nom de commande AR utilisable via l'API dépend de ce qui est enregistré dans `ar.conf` sur le manager — pas garanti identique sur toutes les versions/installations Wazuh. Si `/block` répond "firewall-drop Wazuh non déclenché", vérifie `ar.conf` et les logs (`journalctl -u soc-telegram` ou le fichier de log configuré).
- ⚠️ **Pas de réversion automatique côté Wazuh** : `/unblock` lève le blocage local, mais un `firewall-drop` déclenché manuellement via l'API n'est pas automatiquement annulé (contrairement au déclenchement natif par règle, qui respecte le `<timeout>` du bloc `<active-response>`). À vérifier/lever à la main côté agent si besoin.

## Documentation officielle

- [Active Response — vue d'ensemble](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
- [Active Response — référence de configuration `ossec.conf`](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html)
- [Scripts de réponse par défaut (`firewall-drop`, `remove-threat`...)](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/default-active-response-scripts.html)
- [Cas d'usage — bloquer un brute force SSH](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/ar-use-cases/blocking-ssh-brute-force.html)
