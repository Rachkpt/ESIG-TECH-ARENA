# Source des données — Indexer vs API Manager

`surveillance_soc.py` interroge en continu l'**Indexer Wazuh** (OpenSearch) pour récupérer les alertes, pas l'API du Manager.

📖 Doc officielle : [Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/api/reference.html) · [Wazuh Manager API](https://documentation.wazuh.com/current/user-manual/api/reference.html) · [OpenSearch Query DSL (syntaxe des requêtes `_search`)](https://opensearch.org/docs/latest/query-dsl/)

## Indexer vs Manager API — les deux sont utilisées, mais pour des choses différentes

| | Indexer (OpenSearch) | API Manager |
|---|---|---|
| Port | **9200** | **55000** |
| Variables `.env` | `WAZUH_INDEXER_URL/_USER/_PASS` | `WAZUH_URL/_USER/_PASS` |
| Contenu | Index `wazuh-alerts-*` — les alertes elles-mêmes | Liste des agents, gestion, configuration |
| Utilisé pour | Récupérer les alertes (`get_alerts`, `get_ssh_alerts`, `get_scan_alerts`, `get_fim_events`) | Lister les agents (`get_agents`, commande `/agents` du bot) |

## Pourquoi

L'API Manager (port 55000) n'expose **pas** le flux d'alertes. Les alertes générées par le Manager sont indexées dans OpenSearch, sous l'index `wazuh-alerts-*`, accessible via l'Indexer sur le port 9200. Le script utilise donc les deux APIs Wazuh, chacune pour son usage réel.

## Implémentation (`soc_clients.py` — `WazuhClient`)

Toutes les requêtes d'alertes passent par une méthode commune :

```python
def _indexer_search(self, query_body: dict, size: int = 100) -> list:
    """Interroge l'Indexer Wazuh (OpenSearch) sur l'index wazuh-alerts-*."""
    r = requests.post(
        f"{Config.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(Config.WAZUH_INDEXER_USER, Config.WAZUH_INDEXER_PASS),
        json=query_body, ...
    )
```

Quatre méthodes s'appuient dessus, chacune avec un filtre différent :

| Méthode | Filtre |
|---|---|
| `get_alerts()` | Alertes de niveau ≥ `WAZUH_MIN_LEVEL` (défaut 5) — pipeline principal → classification → blocage |
| `get_ssh_alerts()` | Connexions SSH/PAM de **faible** niveau (réussies, niveau 3), volontairement sous le seuil global, pour ne jamais intercepter un vrai brute force qui doit suivre le pipeline normal |
| `get_scan_alerts()` | Alertes Suricata-via-Wazuh (scan nmap, etc.) — Wazuh applique un niveau générique bas (3) à toutes les alertes Suricata ingérées via son décodeur intégré (`rule.id` 86601 et similaires), quelle que soit leur gravité réelle |
| `get_fim_events()` | Événements `syscheck` (FIM) des dernières minutes uniquement, voir [FIM](../03-wazuh/fim.md) |

Toutes utilisent un paramètre `since_ts` pour ne récupérer que les alertes postérieures au dernier cycle — évite de renvoyer tout l'historique à chaque redémarrage.

## Suricata — deux chemins d'ingestion

En plus des alertes Suricata relayées par Wazuh (`get_scan_alerts`, `rule.id` 86601), `surveillance_soc.py` lit aussi **directement** `eve.json` (`read_suricata_eve()`, `SURICATA_EVE` dans `.env`) — voir [Suricata](../04-suricata/README.md).
