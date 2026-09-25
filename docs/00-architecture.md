# Architecture globale

## Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────┐
│                      SOURCES DE DONNÉES                      │
│     Suricata (IDS)   │   Fail2ban   │   Wazuh Agent (EDR)    │
└──────────────┬───────────────┬───────────────┬───────────────┘
               │               │               │
               ▼               ▼               ▼
┌─────────────────────────────────────────────────────────────┐
│                  Wazuh Manager + Indexer                     │
│         (OpenSearch, index wazuh-alerts-*, port 9200)        │
└──────────────────────────────┬───────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│              soc-automation/surveillance_soc.py               │
│   Interroge l'Indexer en continu, classe les alertes par      │
│   catégorie (scan réseau, force brute, malware, exploitation) │
│   déclenche les actions immédiates (blocage local, alerte)    │
└──────────────────────────────┬───────────────────────────────┘
                                │ soc_state.json (état partagé)
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                    TheHive 5  ◄────────►  Cortex               │
│         Alert → Case (workflow standard)   Analyzers           │
└──────────────────────────────┬───────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│               soc-automation/response_soc.py                  │
│   Traite les cas TheHive en attente, lance les analyzers       │
│   Cortex, synthétise les résultats via un LLM (API Groq),      │
│   renvoie vers TheHive et Telegram                             │
└──────────────────────────────┬───────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│               soc-automation/telegram_bot.py                  │
│      Bot d'administration à distance (/status, /blocked,       │
│      /cases, /report...)                                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                        MONITORING                             │
│              Prometheus  ◄────────►  Grafana                  │
└─────────────────────────────────────────────────────────────┘
```

## Les deux volets du projet

1. **La stack SOC** (Wazuh, Suricata, Fail2ban, TheHive, Cortex, Grafana/Prometheus) — détection et centralisation des incidents. Voir [docs/03](03-wazuh/README.md) à [docs/07](07-monitoring/README.md).
2. **Le script d'automatisation** (`soc-automation/`) — le cœur du projet : 3 processus Python indépendants qui tournent en permanence via systemd et partagent un état commun. Voir [docs/08](08-automatisation-soc/README.md).

## Les 3 processus d'automatisation

| Script | Rôle |
|---|---|
| `surveillance_soc.py` | Interroge en continu l'**Indexer Wazuh** (OpenSearch, port 9200, index `wazuh-alerts-*`) — **pas** l'API manager (port 55000), qui n'expose pas les alertes. Classe les alertes par catégorie et déclenche les actions immédiates. |
| `response_soc.py` | Traite la file des cas TheHive en attente, lance tous les analyzers Cortex disponibles, synthétise les résultats via un LLM (API Groq), renvoie le tout vers TheHive et Telegram. |
| `telegram_bot.py` | Bot d'administration à distance, avec un clavier de commandes fixe (`/status`, `/blocked`, `/cases`, `/report`...). |

Les 3 scripts sont indépendants (processus systemd séparés) mais partagent un fichier d'état commun `soc_state.json`, et s'appuient sur 3 modules communs :

- `soc_config.py` — catégories et règles de classification des alertes
- `soc_utils.py` — état persistant, blocage IP, anti-spam
- `soc_clients.py` — clients API (Wazuh, TheHive, Cortex, Telegram, Gmail)

## Points d'architecture importants

- **Blocage réseau à deux niveaux** :
  - blocage local via `iptables` (le script) pour les catégories non couvertes nativement par Wazuh ;
  - blocage natif via **Wazuh Active Response** (`firewall-drop`), qui s'exécute directement sur l'agent attaqué — préférable, car il protège la vraie machine ciblée, pas seulement le serveur qui héberge le script. Voir [Active Response](03-wazuh/active-response.md).
- **Anti-spam** : chaque type d'alerte est limité à une notification par heure par IP/fichier, pour ne pas saturer Telegram.
- **Auto-surveillance** : le SOC s'alerte lui-même immédiatement si l'un des 3 services plante (détecté via l'alerte systemd que Wazuh remonte).
- **Workflow TheHive** : les cas sont créés via le workflow standard (Alert d'abord, puis promotion automatique en Case) — jamais directement en Case.
- **Organisation TheHive dédiée** : le compte utilisé par le script appartient à une organisation dédiée, pas à l'organisation `admin` (qui n'a pas les droits de gestion de cas). Voir [organisation-setup.md](06-thehive-cortex/organisation-setup.md).
- **Analyzers Cortex** : ce sont des scripts Python exécutés *dans* le conteneur Cortex — ils nécessitent l'installation manuelle de python3 et des dépendances de chaque analyzer (`requirements.txt`), sinon `ModuleNotFoundError`. Voir [cortex-analyzers.md](06-thehive-cortex/cortex-analyzers.md).
