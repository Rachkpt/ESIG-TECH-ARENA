# Prérequis

## Recommandation générale

Le SOC complet est lourd : il est recommandé de répartir les composants sur **plusieurs VMs séparées**, en particulier Wazuh (lourd) et TheHive/Cortex, plutôt que de tout installer sur une seule machine.

## Par composant

| Composant | OS | RAM min | CPU | Disque |
|---|---|---|---|---|
| Wazuh (manager + indexer + dashboard) | Ubuntu 22.04 LTS 64-bit | 4 GB (8 GB recommandé) | 2 vCPU | 50 GB |
| TheHive 5 + Cortex (Docker) | Ubuntu 22.04 LTS 64-bit | 4 GB minimum | 2 vCPU | 30 GB |
| Grafana + Prometheus | Ubuntu 22.04 LTS 64-bit | 512 MB (léger) | 1 vCPU | 10 GB |
| Suricata | Ubuntu 22.04 LTS / Debian 11 | — | — | — |
| Fail2ban | Ubuntu 22.04 LTS / Debian 11 | — | — | — |
| `soc-automation/` (script Python) | Même machine que TheHive/Cortex, ou VM séparée avec accès réseau à Wazuh Indexer + TheHive + Cortex | — | — | — |

## Logiciel commun

- Docker 24.x+ et Docker Compose plugin v2+ (pour TheHive/Cortex)
- Python 3.10+ (pour `soc-automation/`)
- Accès réseau entre les VMs : le script d'automatisation doit pouvoir joindre le port 9200 (Wazuh Indexer), le port 9000 (TheHive), le port 9001 (Cortex), et Internet pour les API externes (Groq, Telegram, VirusTotal via Cortex).

## Comptes / clés API à préparer avant de commencer

- Compte [Groq](https://console.groq.com/) (API pour la synthèse LLM)
- Bot Telegram (via [@BotFather](https://t.me/BotFather)) + chat ID
- Clé API VirusTotal (pour l'analyzer Cortex)
- Clé API AbuseIPDB (optionnel, selon les analyzers activés)
