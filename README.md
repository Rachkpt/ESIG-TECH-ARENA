# 🛡️ ESIG Tech Arena — SOC pour infrastructures critiques

> 🏆 **Projet réalisé dans le cadre du hackathon ESIG Tech Arena** par la team **NetForce4**.
>
> **Thème : Sécurité des infrastructures critiques** (hôpitaux, banques, énergie/CEET).
> SOC automatisé et souverain basé sur Wazuh, Suricata, Fail2ban, TheHive 5, Cortex, Grafana/Prometheus et un script Python d'automatisation (surveillance, réponse, bot Telegram).
> Sa spécificité : une **réponse graduée par criticité** qui détecte les attaques informatiques **et industrielles (SCADA/Modbus)** sans jamais couper un service vital — l'humain reste dans la boucle pour les équipements critiques.

## 👥 Équipe — NetForce4

Projet développé pour le **hackathon ESIG Tech Arena** par :

| Membre |
|---|
| ALEDJI Ar-Rachad |
| AMEGAN-AYEH Bénédicte |
| DASSANOU Emery Stéphane |
| LAMBA Karol Steve |

## Ce qui distingue ce SOC (infrastructures critiques)

- 🏥🏦⚡ **Multi-secteurs** : santé, banque, énergie (CEET), chaque alerte étiquetée par secteur.
- 🎚️ **Réponse graduée** : blocage automatique sur un équipement standard, **validation humaine Telegram** sur un équipement critique (préserver la disponibilité).
- 🏭 **Surveillance industrielle (OT)** : détection d'attaques Modbus/SCADA + [automate simulé](ot-lab/README.md) pour la démo.
- 🧠 **Analyse IA** et bot Telegram d'administration à distance.

👉 **Voir la brique dédiée : [10 — Sécurité des infrastructures critiques](docs/10-infrastructures-critiques/README.md).**

## Structure du dépôt

- [`docs/`](docs/) — documentation complète d'installation et de configuration de chaque brique du SOC.
- [`soc-automation/`](soc-automation/) — code Python du script d'automatisation (le cœur du projet).
- [`ot-lab/`](ot-lab/) — lab industriel : automate Modbus simulé (CEET) et scénario d'attaque pour la démonstration.

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
| [10](docs/10-infrastructures-critiques/README.md) | **Sécurité des infrastructures critiques** — réponse graduée, validation humaine, OT/SCADA |

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

## Auteurs

Team **NetForce4** — Hackathon **ESIG Tech Arena** · Blue Team / SOC

- ALEDJI Ar-Rachad
- AMEGAN-AYEH Bénédicte
- DASSANOU Emery Stéphane
- LAMBA Karol Steve
