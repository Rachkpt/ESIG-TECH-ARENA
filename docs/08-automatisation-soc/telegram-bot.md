# Bot Telegram d'administration

`telegram_bot.py` fournit un bot d'administration à distance du SOC, avec un clavier de commandes persistant en plus des commandes slash.

📖 Doc officielle : [Telegram Bot API](https://core.telegram.org/bots/api) — appelée directement en HTTP via `requests`, pas de lib `python-telegram-bot`.

## Commandes

| Commande | Rôle |
|---|---|
| `/status` | État des connexions (Wazuh, TheHive, Cortex), nombre d'IPs bloquées (script + Active Response natif), cases en attente |
| `/logs` | Dernières actions effectuées par le SOC |
| `/blocked` | Liste des IPs actuellement bloquées |
| `/block IP MIN` | Bloquer une IP manuellement pour N minutes — double blocage : local (iptables/nftables + fail2ban) **et** `firewall-drop` Wazuh déclenché sur tous les agents actifs, voir [active-response.md](../03-wazuh/active-response.md#déclenchement-manuel-depuis-telegram) |
| `/unblock IP` | Débloquer une IP — lève le blocage local ; le `firewall-drop` Wazuh déclenché manuellement n'est **pas** annulé automatiquement (voir active-response.md) |
| `/ban IP` | Bannir une IP de façon permanente (même double blocage que `/block`) |
| `/whitelist IP` | Ajouter une IP à la liste blanche (jamais bloquée) |
| `/cases` | Liste des cases TheHive |
| `/analyze IP` | Lancer manuellement les analyzers Cortex sur une IP |
| `/createcase IP` | Créer un case TheHive manuellement |
| `/stats` | Statistiques (alertes du jour/semaine, blocages, malwares...) |
| `/report` | Génère un rapport de synthèse via Groq (IA) |
| `/silence MIN` | Coupe les notifications pendant N minutes |
| `/check` | Force la vérification des blocages expirés |
| `/agents` | État (en ligne / hors ligne / jamais connecté) de tous les agents Wazuh |
| `/alerts` | 10 dernières alertes |
| `/scan` | IPs ayant fait l'objet d'un ping/scan nmap |
| `/malicious` | IPs identifiées comme malveillantes |

Un clavier de boutons persistant (`persistent_keyboard()`) reproduit l'essentiel de ces commandes pour un usage mobile rapide, en plus du clavier inline du menu principal. Les boutons "10 Dernières Alertes", "IPs Ping & NMAP", "IPs Malveillantes/Logs" ont été retirés du clavier persistant (pour l'alléger) mais restent accessibles via `/alerts`, `/scan`, `/malicious` et le menu inline.

## Fiabilité au redémarrage

Au démarrage, `telegram_bot.py` purge le backlog Telegram (`getUpdates` avec `offset=-1`) avant d'activer le menu — ça évite de rejouer d'anciennes commandes accumulées pendant que le bot était arrêté.

📖 [Telegram Bot API — méthode `getUpdates`](https://core.telegram.org/bots/api#getupdates)

## Configuration

Voir [.env.example](../../soc-automation/.env.example) — variables `TELEGRAM_TOKEN` et `TELEGRAM_CHAT` (bot créé via [@BotFather](https://t.me/BotFather)).

## Notifications sortantes

En plus de répondre aux commandes, le bot reçoit les notifications poussées par `surveillance_soc.py` et `response_soc.py` (nouvelles alertes, synthèse Groq des cas, blocages). Un mécanisme anti-spam (`should_alert()` dans `soc_utils.py`) limite chaque type d'alerte à une notification par heure par IP/fichier (fenêtre glissante de 3600s).
