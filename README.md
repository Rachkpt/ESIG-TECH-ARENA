# 🛡️ SOC Automatisé — Détection et Réponse aux Incidents de Sécurité

> Projet académique ESIG (Master Cybersécurité) — SOC complet basé sur Wazuh, Suricata, Fail2ban, TheHive 5, Cortex, Grafana/Prometheus, et un script Python d'automatisation (surveillance, réponse, bot Telegram).

## Structure du dépôt

- [`docs/`](docs/) — documentation complète d'installation et de configuration de chaque brique du SOC.
- [`soc-automation/`](soc-automation/) — code Python du script d'automatisation (le cœur du projet).

## Documentation

| # | Sujet |
|---|---|
| [00](docs/00-architecture.md) | Architecture globale |
| [01](docs/01-prerequis.md) | Prérequis matériels et logiciels |
| [02](docs/02-installation-docker.md) | Installation Docker |
| [03](docs/03-wazuh/README.md) | Wazuh (SIEM/EDR) — [FIM](docs/03-wazuh/fim.md), [intégration VirusTotal](docs/03-wazuh/virustotal-integration.md), [Active Response](docs/03-wazuh/active-response.md) |
| [04](docs/04-suricata/README.md) | Suricata (IDS/IPS) |
| [05](docs/05-fail2ban/README.md) | Fail2ban / détection de scan de ports |
| [06](docs/06-thehive-cortex/README.md) | TheHive & Cortex — [organisation](docs/06-thehive-cortex/organisation-setup.md), [analyzers](docs/06-thehive-cortex/cortex-analyzers.md) |
| [07](docs/07-monitoring/README.md) | Monitoring (Grafana / Prometheus) |
| [08](docs/08-automatisation-soc/README.md) | Script Python d'automatisation SOC |
| [09](docs/09-depannage-general.md) | Dépannage général |

## Stack technique

| Outil | Rôle | Documentation officielle |
|---|---|---|
| **Wazuh** | SIEM / EDR — détection sur les endpoints | [documentation.wazuh.com](https://documentation.wazuh.com/current/index.html) |
| **Suricata** | IDS/IPS réseau | [docs.suricata.io](https://docs.suricata.io/en/latest/) |
| **Fail2ban** | Protection contre force brute et scans de ports | [wiki fail2ban](https://github.com/fail2ban/fail2ban/wiki) |
| **TheHive 5** | Gestion des incidents de sécurité | [docs.strangebee.com/thehive](https://docs.strangebee.com/thehive/) |
| **Cortex** | Analyse automatique (VirusTotal, AbuseIPDB...) et réponse | [docs.strangebee.com/cortex](https://docs.strangebee.com/cortex/) |
| **Grafana** | Dashboards temps réel | [grafana.com/docs](https://grafana.com/docs/grafana/latest/) |
| **Prometheus** | Collecte de métriques | [prometheus.io/docs](https://prometheus.io/docs/introduction/overview/) |
| **Docker / Compose** | Déploiement TheHive/Cortex | [docs.docker.com](https://docs.docker.com/engine/) |
| **Groq (LLM)** | Synthèse IA des analyses | [console.groq.com/docs](https://console.groq.com/docs/quickstart) |
| **Telegram Bot API** | Bot d'administration à distance | [core.telegram.org/bots/api](https://core.telegram.org/bots/api) |
| **Script Python (`soc-automation/`)** | Corrélation, classification, réponse automatique, bot Telegram | voir [docs/08](docs/08-automatisation-soc/README.md) |

## Auteur

**12ak_H4ck** — Projet académique ESIG · Blue Team / SOC
