# 🤖 Automatisation SOC (`soc-automation/`)

> Le cœur du projet : 3 processus Python indépendants qui tournent en permanence via **systemd**, et partagent un fichier d'état commun (`soc_state.json`).

Voir aussi : [Architecture globale](../00-architecture.md)

## Les 3 scripts

| Script | Rôle |
|---|---|
| [`surveillance_soc.py`](../../soc-automation/surveillance_soc.py) | Interroge en continu l'**Indexer Wazuh** (voir [source-des-données](source-des-donnees.md)), classe les alertes (voir [classification](classification-alertes.md)), déclenche les actions immédiates. |
| `response_soc.py` | Traite la file des cas TheHive en attente, lance tous les analyzers Cortex disponibles, synthétise les résultats via un LLM (API Groq), renvoie le tout vers TheHive et Telegram. |
| [`telegram_bot.py`](telegram-bot.md) | Bot d'administration à distance. |

## Modules communs

| Module | Rôle |
|---|---|
| `soc_config.py` | Configuration centralisée (`.env`), modèles de données, règles de classification (voir [classification-alertes.md](classification-alertes.md)) |
| `soc_utils.py` | État persistant (`soc_state.json`), blocage iptables/nftables/fail2ban, anti-spam, envoi Telegram |
| `soc_clients.py` | Clients API : Wazuh (manager + indexer), TheHive, Cortex, Groq, Gmail |

## Mécanismes clés

- **Anti-spam** : une seule notification par heure par IP/fichier et par type d'alerte, pour ne pas saturer Telegram.
- **Auto-surveillance** : le SOC détecte si l'un de ses 3 propres services plante, via l'alerte systemd remontée par Wazuh, et alerte immédiatement.
- **Blocage réseau à deux niveaux** :
  - `iptables` local (le script), pour les catégories non couvertes nativement par Wazuh ;
  - **Wazuh Active Response** (`firewall-drop`), qui bloque directement sur l'agent attaqué — méthode préférée. Voir [Active Response](../03-wazuh/active-response.md).
- **Workflow TheHive** : Alert créée d'abord, puis promue automatiquement en Case — jamais de Case créé directement.
- L'organisation TheHive utilisée par le script doit être **dédiée** (pas l'organisation `admin`). Voir [organisation-setup.md](../06-thehive-cortex/organisation-setup.md).

## Installation

Voir [installation.md](installation.md).

## Fichiers du script

```
soc-automation/
├── soc_config.py
├── soc_utils.py
├── soc_clients.py
├── surveillance_soc.py
├── response_soc.py
├── telegram_bot.py
├── install.sh
├── .env.example
└── README.md
```

## Documentation officielle des APIs utilisées

- [Wazuh Indexer API (OpenSearch)](https://documentation.wazuh.com/current/user-manual/api/reference.html) — voir aussi [source-des-donnees.md](source-des-donnees.md)
- [TheHive API](https://docs.strangebee.com/thehive/api/)
- [Cortex API](https://docs.strangebee.com/cortex/api/)
- [Groq API (LLM)](https://console.groq.com/docs/quickstart)
- [Telegram Bot API](https://core.telegram.org/bots/api) — appelée directement en HTTP via `requests`, pas de lib `python-telegram-bot`
