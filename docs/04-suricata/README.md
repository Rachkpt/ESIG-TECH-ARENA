# 🚨 Suricata — IDS/IPS réseau

> Module SOC — détection d'intrusion réseau, mode IDS passif (af-packet), avec règles custom SOC + jeu Emerging Threats Open.

## Installation automatisée

```bash
sudo bash install-suricata-soc.sh
# ou en forçant l'interface / le réseau surveillé :
sudo IFACE=eth1 HOMENET='[10.0.0.0/8]' bash install-suricata-soc.sh
```

À lancer sur la machine capteur (celle qui voit le trafic). Sur un bridge Proxmox sans port-mirroring, c'est la machine **cible** de l'attaque elle-même.

Ce que fait le script :
- installe Suricata (PPA OISF sur Ubuntu, dépôt officiel sur Debian 11/12) ;
- déploie **toutes** les règles `*.rules` présentes dans [`rules/`](rules/) vers `/etc/suricata/rules/` et les charge dans `suricata.yaml` ;
- configure `HOME_NET`, l'interface d'écoute (af-packet) et `community-id` (pour corréler les alertes avec les autres outils du SOC) ;
- désactive les règles `*-events.rules` (decoder/stream/app-layer) — bruit L2 propre au bridge Proxmox sans port-mirroring, à réactiver si ton capteur est sur un vrai SPAN/TAP réseau ;
- active le jeu **Emerging Threats Open** via `suricata-update` ;
- valide la config (`suricata -T`) avant de redémarrer le service.

### Ajouter d'autres règles custom

Dépose n'importe quel fichier `*.rules` dans [`rules/`](rules/) et relance le script — il est repris automatiquement, sans toucher au script lui-même.

## Règles custom SOC actuelles

[`rules/soc-custom.rules`](rules/soc-custom.rules) — détection de scans Nmap par technique et vitesse (`T1`-`T5`), calibrée sur une liste de ports courants :

| Détection | SID | Technique Nmap |
|---|---|---|
| SYN scan | 3400001, 3400002 | `-sS` |
| Connect scan (3-way) | 3400003 | `-sT` |
| ACK scan | 3400004 | `-sA` |
| Christmas tree scan | 3400005 | `-sX` |
| Scan fragmenté | 3400006 | `-f` |
| UDP scan | 3400007, 3400008 | `-sU` |
| Brute force SSH | 3400030 | connexions répétées port 22 |
| Scan shell Metasploit (port 4444) | 3400020, 3400021 | TCP/UDP |

Chaque règle utilise `threshold` (track by_src/by_dst) pour ne déclencher qu'au-delà d'un seuil de tentatives sur une fenêtre de temps — évite le bruit d'un simple `curl` ou d'une connexion isolée.

## Vérifier les alertes en temps réel

```bash
sudo tail -f /var/log/suricata/fast.log
sudo tail -f /var/log/suricata/eve.json | jq .
```

📖 Format des logs : [fast.log](https://docs.suricata.io/en/latest/output/log-file-formats.html) · [eve.json](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html) (utilisé par `surveillance_soc.py`, voir [source-des-donnees.md](../08-automatisation-soc/source-des-donnees.md))

## Test rapide

Depuis une **autre** machine :
```bash
nmap -sS -p1-1000 <ip-du-capteur>
```
Puis sur le capteur :
```bash
grep 'POSSBL' /var/log/suricata/fast.log
```

## Intégration avec Wazuh

L'agent Wazuh lit `eve.json` via `<localfile>` (type `json`) — voir [Localfile reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html) et [Wazuh + Suricata integration guide](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-network-vulnerabilities-suricata.html). Les alertes Suricata remontent ensuite dans `surveillance_soc.py` sous la catégorie "exploitation"/"scan réseau" — voir [classification-alertes.md](../08-automatisation-soc/classification-alertes.md).

## Documentation officielle

- [Suricata — documentation officielle](https://docs.suricata.io/en/latest/)
- [Suricata — gestion des règles](https://docs.suricata.io/en/latest/rule-management/index.html)
- [Suricata — format des logs eve.json](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
- [Wazuh — intégration avec Suricata](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-network-vulnerabilities-suricata.html)
