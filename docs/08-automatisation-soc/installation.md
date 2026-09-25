# Installation de `soc-automation/`

## 1. Copier les fichiers sur le serveur

```bash
sudo mkdir -p /opt/soc-automation
sudo cp -r soc-automation/* /opt/soc-automation/
cd /opt/soc-automation
```

## 2. Configurer les secrets

```bash
cp .env.example .env
nano .env   # renseigner les clés API et endpoints réels
```

Voir [.env.example](../../soc-automation/.env.example) pour la liste complète des variables (Wazuh manager + Indexer, TheHive, Cortex, Groq, Gmail, Telegram, firewall).

## 3. Lancer l'installation

```bash
sudo bash install.sh
```

`install.sh` :
- installe les dépendances Python (`requests`, `python-dotenv`) — le bot Telegram appelle l'API directement en HTTP (`requests`), pas de lib `python-telegram-bot`
- copie `.env.example` vers `.env` s'il n'existe pas déjà (sans écraser un `.env` existant)
- crée la jail Fail2ban `soc-auto` (`/etc/fail2ban/jail.d/soc-auto.conf`) — voir [Fail2ban](../05-fail2ban/README.md)
- crée et active 3 services systemd : `soc-script1`, `soc-script2`, `soc-telegram` — voir [systemd.service reference](https://www.freedesktop.org/software/systemd/man/systemd.service.html)

## 4. Éditer `.env` puis démarrer les services

```bash
nano /opt/soc-automation/.env
sudo systemctl start soc-script1 soc-script2 soc-telegram
sudo systemctl status soc-script1 soc-script2 soc-telegram
```

## 5. Vérifier le fonctionnement

```bash
tail -f /var/log/soc_automation.log
sudo journalctl -u soc-script1 -f    # surveillance_soc.py
sudo journalctl -u soc-script2 -f    # response_soc.py
sudo journalctl -u soc-telegram -f   # telegram_bot.py
```

Depuis Telegram : envoyer `/status` au bot pour confirmer que Wazuh, TheHive et Cortex sont bien joignables.

## Correspondance service ↔ script

| Service systemd | Script |
|---|---|
| `soc-script1` | `surveillance_soc.py` |
| `soc-script2` | `response_soc.py` |
| `soc-telegram` | `telegram_bot.py` |
