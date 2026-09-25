# 🔒 Détection et Blocage Automatique de Scan de Ports

> Module de sécurité du projet SOC — Détection des scans de ports via iptables et bannissement automatique des IPs malveillantes avec Fail2ban.

---

## 📋 Comportement attendu

| Situation | Résultat |
|---|---|
| Ping normal vers le serveur | ✅ Autorisé |
| Trafic normal des autres IPs | ✅ Non affecté |
| Scan de ports détecté (nmap) | 🚨 IP scanner enregistrée |
| Ping après scan détecté | ❌ Uniquement l'IP scanner bannie — 100% packet loss |

> ⚠️ Seule l'IP qui a effectué le scan est bloquée. Toutes les autres IPs continuent à accéder normalement au serveur.

---

## Prérequis

```bash
sudo apt update
sudo apt install -y iptables iptables-persistent fail2ban
```

---

## Étape 1 — Configurer iptables

### Vider les règles existantes

```bash
sudo iptables -F INPUT
sudo iptables -F
```

### Appliquer les règles de détection et de blocage

```bash
# Autoriser loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Autoriser les connexions déjà établies
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Autoriser SSH (éviter de se couper du serveur)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# ============================================
# SCAN NULL (aucun flag) — nmap -sN
# ============================================
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE \
  -m recent --name PORTSCAN --set \
  -j LOG --log-prefix "PORTSCAN-NULL: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# ============================================
# SCAN XMAS (FIN+PSH+URG) — nmap -sX
# ============================================
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG \
  -m recent --name PORTSCAN --set \
  -j LOG --log-prefix "PORTSCAN-XMAS: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP

# ============================================
# SCAN FIN — nmap -sF
# ============================================
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN \
  -m recent --name PORTSCAN --set \
  -j LOG --log-prefix "PORTSCAN-FIN: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN -j DROP

# ============================================
# SCAN SYN/RST invalide (technique d'évasion)
# ============================================
sudo iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST \
  -m recent --name PORTSCAN --set \
  -j LOG --log-prefix "PORTSCAN-SYNRST: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# ============================================
# SCAN SYN/FIN invalide (technique d'évasion)
# ============================================
sudo iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN \
  -m recent --name PORTSCAN --set \
  -j LOG --log-prefix "PORTSCAN-SYNFIN: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# ============================================
# SCAN UDP — nmap -sU
# ============================================
sudo iptables -A INPUT -p udp \
  -m multiport --dports 53,67,68,69,123,161,500,1900 \
  -m recent --name PORTSCAN --set \
  -j LOG --log-prefix "PORTSCAN-UDP: " --log-level 4

# ============================================
# SCAN LENT -T0 / -T1 (évasion par timing)
# Détecté sur fenêtre large : 20 hits en 300 secondes
# ============================================
sudo iptables -A INPUT -p tcp --syn \
  -m multiport --dports 20,21,23,25,80,443,3306,8080,9000,9001,9200 \
  -m recent --name SLOWSCAN --set

sudo iptables -A INPUT -p tcp --syn \
  -m recent --name SLOWSCAN --rcheck --seconds 300 --hitcount 20 \
  -j LOG --log-prefix "PORTSCAN-SLOW: " --log-level 4

sudo iptables -A INPUT -p tcp --syn \
  -m recent --name SLOWSCAN --rcheck --seconds 300 --hitcount 20 \
  -j DROP

# ============================================
# SCAN RAPIDE -T4 / -T5 — nmap -sS
# Détecté : 5 SYN en 5 secondes
# ============================================
sudo iptables -A INPUT -p tcp --syn \
  -m multiport --dports 20,21,23,25,80,443,3306,8080,9000,9001,9200 \
  -m recent --name PORTSCAN --set

sudo iptables -A INPUT -p tcp --syn \
  -m recent --name PORTSCAN --rcheck --seconds 5 --hitcount 5 \
  -j LOG --log-prefix "PORTSCAN-FAST: " --log-level 4

sudo iptables -A INPUT -p tcp --syn \
  -m recent --name PORTSCAN --rcheck --seconds 5 --hitcount 5 \
  -j DROP

# ============================================
# BLOQUER TOUTE IP DÉTECTÉE pendant 1 heure
# TCP + UDP + ICMP — seule l'IP scanner est bloquée
# ============================================
sudo iptables -A INPUT \
  -m recent --name PORTSCAN --rcheck --seconds 3600 --hitcount 5 \
  -j DROP

sudo iptables -A INPUT \
  -m recent --name SLOWSCAN --rcheck --seconds 3600 --hitcount 20 \
  -j DROP
```

### Sauvegarder les règles (survivent au redémarrage)

```bash
sudo netfilter-persistent save
```

---

## Étape 2 — Configurer Fail2ban

### Créer le filtre de détection

```bash
sudo nano /etc/fail2ban/filter.d/portscan.conf
```

```ini
[Definition]
failregex = PORTSCAN.* SRC=<HOST>
            PORTSCAN-NULL.* SRC=<HOST>
            PORTSCAN-XMAS.* SRC=<HOST>
            PORTSCAN-FIN.* SRC=<HOST>
            PORTSCAN-SYNRST.* SRC=<HOST>
            PORTSCAN-SYNFIN.* SRC=<HOST>
            PORTSCAN-UDP.* SRC=<HOST>
            PORTSCAN-SLOW.* SRC=<HOST>
            PORTSCAN-FAST.* SRC=<HOST>

ignoreregex =

[Init]
datepattern = {^LN-BEG}
```

### Créer la jail Fail2ban

```bash
sudo nano /etc/fail2ban/jail.d/portscan.conf
```

```ini
[portscan]
enabled      = true
filter       = portscan
backend      = systemd
journalmatch = _TRANSPORT=kernel
maxretry     = 5
findtime     = 60
bantime      = 3600
action       = iptables-allports[name=portscan, protocol=all]
```

### Configurer jail.local global

```bash
sudo nano /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
bantime  = 3600
findtime = 60
maxretry = 5
backend  = systemd
ignoreip = 127.0.0.1/8 ::1
banaction = iptables-multiport
banaction_allports = iptables-allports

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 86400
```

### Démarrer Fail2ban

```bash
sudo systemctl enable fail2ban
sudo systemctl restart fail2ban
```

---

## Étape 3 — Vérification

### Vérifier que les jails sont actives

```bash
sudo fail2ban-client status
sudo fail2ban-client status portscan
```

### Vérifier les règles iptables en place

```bash
sudo iptables -L INPUT -n -v
```

### Voir les IPs actuellement bannies

```bash
sudo cat /proc/net/xt_recent/PORTSCAN
sudo cat /proc/net/xt_recent/SLOWSCAN
```

---

## Démonstration (scénario de test)

### Depuis la machine attaquante — avant le scan

```bash
ping IP_SERVEUR
# Résultat attendu : réponse normale ✅
```

### Tester les différents types de scans

```bash
# Scan SYN rapide (T4 par défaut)
nmap -sS IP_SERVEUR

# Scan lent évasion timing
nmap -sS -T1 IP_SERVEUR

# Scan NULL
nmap -sN IP_SERVEUR

# Scan XMAS
nmap -sX IP_SERVEUR

# Scan FIN
nmap -sF IP_SERVEUR

# Scan UDP
sudo nmap -sU IP_SERVEUR
```

### Depuis la machine attaquante — après le scan

```bash
ping IP_SERVEUR
# Résultat attendu : 100% packet loss ❌ IP bannie
```

### Sur le serveur — vérifier le bannissement

```bash
# Voir les paquets droppés
sudo iptables -L INPUT -n -v | grep DROP

# Voir l'IP bannie avec horodatage
sudo cat /proc/net/xt_recent/PORTSCAN

# Voir les logs de détection en direct
sudo journalctl -k --since "5 minutes ago" | grep PORTSCAN
```

---

## Débannir une IP manuellement

```bash
# Vider la liste PORTSCAN
echo / | sudo tee /proc/net/xt_recent/PORTSCAN

# Vider la liste SLOWSCAN
echo / | sudo tee /proc/net/xt_recent/SLOWSCAN

# Via Fail2ban
sudo fail2ban-client set portscan unbanip IP_A_DEBANNIR
```

---

## Types de scans détectés

| Type de scan | Commande nmap | Préfixe log | Technique |
|---|---|---|---|
| Scan SYN rapide | `nmap -sS -T4` | `PORTSCAN-FAST` | 5 SYN en 5 secondes |
| Scan SYN lent | `nmap -sS -T1` | `PORTSCAN-SLOW` | 20 SYN en 300 secondes |
| Scan NULL | `nmap -sN` | `PORTSCAN-NULL` | Aucun flag TCP |
| Scan XMAS | `nmap -sX` | `PORTSCAN-XMAS` | FIN + PSH + URG |
| Scan FIN | `nmap -sF` | `PORTSCAN-FIN` | Flag FIN uniquement |
| Scan UDP | `nmap -sU` | `PORTSCAN-UDP` | Ports UDP courants |
| SYN+RST invalide | évasion manuelle | `PORTSCAN-SYNRST` | Combinaison invalide |
| SYN+FIN invalide | évasion manuelle | `PORTSCAN-SYNFIN` | Combinaison invalide |

---

## Documentation officielle

- [Fail2ban — documentation officielle](https://github.com/fail2ban/fail2ban/wiki)
- [Fail2ban — manuel des jails et filtres](https://github.com/fail2ban/fail2ban/wiki/HOWTO-configure-and-use-filters)
- [iptables — Netfilter documentation](https://netfilter.org/documentation/)

## Auteur

**12ak_H4ck** — Projet académique ESIG · Blue Team / SOC
