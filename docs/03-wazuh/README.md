# 🛡️ Installation Wazuh — SIEM / EDR

> Module SOC — Wazuh est une plateforme open source de détection des menaces, surveillance des endpoints et réponse aux incidents.

---

## 📋 Prérequis matériels

| Ressource | Minimum |
|---|---|
| OS | Ubuntu 22.04 LTS 64-bit |
| RAM | **4 GB minimum** (8 GB recommandé) |
| CPU | 2 vCPU |
| Disque | 50 GB |

> ⚠️ Wazuh est lourd. Il est conseillé de l'installer sur une VM séparée de TheHive/Cortex.

---

## 🔗 Documentation officielle

- [Wazuh — Quickstart](https://documentation.wazuh.com/current/quickstart.html) — c'est sur cette page que tu trouveras toujours la commande d'installation la plus à jour.
- [Wazuh — Guide pratique FIM (proof of concept)](https://documentation.wazuh.com/current/proof-of-concept-guide/index.html) — voir aussi [FIM](fim.md)
- [Wazuh — Active Response, cas d'usage brute force SSH](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/ar-use-cases/blocking-ssh-brute-force.html) — voir aussi [Active Response](active-response.md)
- [Wazuh — Intégration VirusTotal](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html) — voir aussi [virustotal-integration.md](virustotal-integration.md)

---

## Étape 1 — Commande magique d'installation (tout en un)

La commande suivante installe tous les composants Wazuh (manager, indexer, dashboard) en une seule fois :

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

> Cette commande installe automatiquement :
> - **Wazuh Manager** — moteur de détection et corrélation
> - **Wazuh Indexer** — stockage des alertes (basé sur OpenSearch)
> - **Wazuh Dashboard** — interface web de visualisation

L'installation dure environ **15 à 20 minutes** selon la connexion.

---

## Étape 2 — Récupérer les mots de passe générés

Une fois l'installation terminée, récupère les identifiants auto-générés avec cette commande :

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Note bien le mot de passe affiché — il sera nécessaire pour accéder au dashboard.

---

## Étape 3 — Accéder au dashboard

Ouvre ton navigateur et accède à :

```
https://IP_DU_SERVEUR
```

- **Login** : `admin`
- **Password** : celui récupéré à l'étape 2

> ⚠️ Wazuh utilise HTTPS avec un certificat auto-signé. Accepte l'exception de sécurité dans le navigateur.

---

## Étape 4 — Vérifier que les services tournent

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

Tous les services doivent afficher `active (running)`.

---

## Étape 5 — Installer un agent Wazuh sur une autre machine

Depuis le dashboard Wazuh :

1. Aller dans **Server Management → Endpoint Summary**
2. Cliquer **Deploy new agent**
3. Choisir le système (Linux / Windows / macOS)
4. Copier la commande générée et l'exécuter sur la machine cible

Ou manuellement sur Ubuntu :

```bash
# Remplace IP_MANAGER par l'IP de ton serveur Wazuh
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.0-1_amd64.deb
sudo WAZUH_MANAGER='IP_MANAGER' dpkg -i ./wazuh-agent_4.14.0-1_amd64.deb
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo systemctl status wazuh-agent
```

---

## Étape 6 — Intégrer les logs Fail2ban dans Wazuh

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Ajoute dans la section `<ossec_config>` :

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/fail2ban.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/kern.log</location>
</localfile>
```

Redémarre l'agent :

```bash
sudo systemctl restart wazuh-agent
```

---

## Désactiver les mises à jour automatiques (recommandé)

```bash
# Évite les upgrades accidentels qui cassent l'environnement
sudo sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
sudo apt update
```

---

## Déboguer si le service ne démarre pas

```bash
sudo journalctl -u wazuh-manager -n 50 --no-pager
sudo tail -f /var/ossec/logs/ossec.log
```

---

## 🚑 Dépannage — Problèmes rencontrés et résolus

### Problème 1 — Le dashboard échoue à l'installation (`dpkg returned an error code (1)`)

**Symptôme** : `wazuh-install.sh` réussit pour l'indexer et le manager, mais échoue sur le dashboard, puis désinstalle tout automatiquement.

**Cause possible** : résidu d'une tentative précédente qui bloque `dpkg` (scripts `prerm`/`postrm` cassés du paquet `wazuh-manager`).

**Diagnostic** :
```bash
grep -n -B 5 "Wazuh dashboard installation failed" /var/log/wazuh-install.log
sudo journalctl -u wazuh-dashboard -n 100 --no-pager
dpkg -l | grep wazuh
```

**Solution** — si `dpkg --purge wazuh-manager` échoue avec `script pre-removal/post-removal a renvoyé un état de sortie d'erreur 127` (ou `1`), neutralise temporairement les scripts cassés :
```bash
# Neutraliser le script prerm cassé
sudo mv /var/lib/dpkg/info/wazuh-manager.prerm /var/lib/dpkg/info/wazuh-manager.prerm.bak
sudo bash -c 'echo "#!/bin/sh" > /var/lib/dpkg/info/wazuh-manager.prerm'
sudo chmod 755 /var/lib/dpkg/info/wazuh-manager.prerm

# Neutraliser le script postrm cassé (si l'erreur réapparaît dessus)
sudo mv /var/lib/dpkg/info/wazuh-manager.postrm /var/lib/dpkg/info/wazuh-manager.postrm.bak
sudo bash -c 'echo "#!/bin/sh" > /var/lib/dpkg/info/wazuh-manager.postrm'
sudo chmod 755 /var/lib/dpkg/info/wazuh-manager.postrm

# Refaire la purge (doit réussir cette fois)
sudo dpkg --purge wazuh-manager
sudo rm -rf /var/ossec
```

---

### Problème 2 — `ENOSPC: no space left on device` au démarrage du dashboard

**Symptôme** : dans `journalctl -u wazuh-dashboard`, erreur `Error: ENOSPC: no space left on device, mkdir '/usr/share/wazuh-dashboard/data/wazuh'`. L'indexer plante aussi avec `Caused by: java.io.IOException: No space left on device`.

**Cause** : le disque est rempli à 100%. Le principal coupable identifié sur ce projet : le module *Vulnerability Detection* de Wazuh télécharge un flux de vulnérabilités (`vd_feed`) qui peut peser plusieurs Go, combiné à un fichier `.tar` temporaire de plusieurs Go laissé dans `/var/ossec/tmp/`.

**Diagnostic** :
```bash
df -h /
sudo du -h /var | sort -hr | head -20
sudo du -sh /var/ossec/tmp/*
```

**Solution** :
```bash
# Supprimer les archives temporaires volumineuses du module Vulnerability Detection
sudo rm -f /var/ossec/tmp/vd_1.0.0_vd_4.13.0.tar
sudo rm -f /var/ossec/tmp/vd_1.0.0_vd_4.13.0.tar.xz

# Nettoyer le cache apt (peut peser 1-2 Go après plusieurs tentatives)
sudo apt clean

# Vérifier l'espace libéré
df -h /

# Redémarrer les services dans l'ordre (indexer d'abord, puis dashboard)
sudo systemctl restart wazuh-indexer
sleep 30
sudo systemctl restart wazuh-dashboard
```

> 💡 Si le problème revient régulièrement, pense à surveiller `/var/ossec/queue/vd/feed/` (base de données du module Vulnerability Detection) qui peut grossir avec le temps.

---

### Problème 3 — Port déjà utilisé / réinstallation qui boucle en échec

**Symptôme** : `ERROR: Port 1515 is being used by another process` ou `Port 55000 is being used`, le script annule l'installation en boucle.

**Solution** — reset complet avant de relancer :
```bash
# Arrêter tous les services Wazuh
sudo systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null

# Tuer les process accrochés aux ports Wazuh
sudo fuser -k 1515/tcp 55000/tcp 9200/tcp 443/tcp 2>/dev/null

# Purger tous les paquets
sudo apt-get purge -y wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null
sudo dpkg --purge wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null

# Supprimer tous les dossiers résiduels
sudo rm -rf /var/ossec
sudo rm -rf /etc/wazuh-indexer /var/lib/wazuh-indexer /var/log/wazuh-indexer
sudo rm -rf /usr/share/wazuh-dashboard /etc/wazuh-dashboard /var/log/wazuh-dashboard
sudo rm -rf /etc/filebeat /var/lib/filebeat /var/log/filebeat
sudo rm -f wazuh-install-files.tar wazuh-passwords.txt

# Retirer le dépôt et la clé GPG
sudo rm -f /etc/apt/sources.list.d/wazuh.list
sudo rm -f /usr/share/keyrings/wazuh.gpg

# Nettoyer apt
sudo apt-get clean
sudo dpkg --configure -a
sudo apt-get autoremove -y
sudo apt-get update

# Vérification finale : tout doit être propre avant de relancer l'installation
dpkg -l | grep wazuh
ls /var/ossec 2>/dev/null && echo "RESTE DES FICHIERS" || echo "PROPRE"
sudo ss -tulpn | grep -E ':1515|:55000|:9200|:443'
df -h /
```

Une fois la vérification finale propre (aucun paquet `wazuh` listé, `/var/ossec` absent, ports libres), relance l'installation depuis l'**Étape 1**.

---

## Accès rapide

| Service | URL / Commande |
|---|---|
| Dashboard | `https://IP_SERVEUR` |
| Logs manager | `/var/ossec/logs/ossec.log` |
| Config principale | `/var/ossec/etc/ossec.conf` |
| Status | `sudo systemctl status wazuh-manager` |

---

## Auteur

**12ak_H4ck** — Projet académique ESIG · Blue Team / SOC
