# soc-automation

Documentation complète : [docs/08-automatisation-soc/](../docs/08-automatisation-soc/README.md)

## Fichiers

```
soc-automation/
├── soc_config.py         # configuration centralisée (charge .env) + modèles de données + règles de classification
├── soc_utils.py           # état persistant (soc_state.json), blocage iptables/nftables/fail2ban, anti-spam, Telegram
├── soc_clients.py         # clients API : Wazuh (manager + indexer), TheHive, Cortex, Groq, Gmail
├── surveillance_soc.py    # Script 1 — surveillance Wazuh + Suricata (eve.json), classification, actions immédiates
├── response_soc.py        # Script 2 — traitement des cas TheHive, analyzers Cortex, synthèse Groq
├── telegram_bot.py        # Script 3 — bot d'administration (commandes slash)
├── install.sh              # installation (dépendances, services systemd, jail Fail2ban)
├── .env.example
└── README.md
```

## Installation

Voir [docs/08-automatisation-soc/installation.md](../docs/08-automatisation-soc/installation.md).

```bash
cp .env.example .env
nano .env   # renseigner les clés API et endpoints
sudo bash install.sh
```
