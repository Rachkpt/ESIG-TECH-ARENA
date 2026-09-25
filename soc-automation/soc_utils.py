#!/usr/bin/env python3
"""
soc_utils.py — Fonctions communes SOC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Gestion : Firewall (iptables/nftables), État JSON, Logs, Telegram
"""

import os
import json
import fcntl
import subprocess
import logging
import threading
import ipaddress
import time
import requests
from datetime import datetime, timedelta
from typing import Optional

from soc_config import Config, BlockedIP, SOCState, SOCLog, Severity

# ╔══════════════════════════════════════════════════════════╗
# ║                       LOGGING                            ║
# ╚══════════════════════════════════════════════════════════╝

_log_dir = os.path.dirname(Config.LOG_FILE)
if _log_dir:
    os.makedirs(_log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)-15s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(Config.LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("soc")
_lock = threading.Lock()          # verrou intra-process (threads/timers)
_active_timers: dict = {}

# ── VERROU INTER-PROCESS (script1 + script2 + telegram_bot) ──────
# Le threading.Lock ci-dessus ne protège QUE les threads d'un même
# process. Les 3 services écrivent le MÊME soc_state.json → sans
# verrou fichier, un load→modif→save concurrent perd des données
# (last-write-wins). fcntl.flock sérialise les accès entre process.
_STATE_LOCK_PATH = Config.STATE_FILE + ".lock"


class _FileLock:
    """Verrou exclusif inter-process basé sur fcntl.flock."""
    def __init__(self, path: str):
        self.path = path
        self.fd = None

    def __enter__(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            self.fd = open(self.path, "w")
            fcntl.flock(self.fd, fcntl.LOCK_EX)
        except Exception:
            self.fd = None  # dégradé : on continue sans verrou plutôt que crasher
        return self

    def __exit__(self, *exc):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
                self.fd.close()
            except Exception:
                pass


def _state_lock() -> "_FileLock":
    return _FileLock(_STATE_LOCK_PATH)


# ╔══════════════════════════════════════════════════════════╗
# ║              VALIDATION IP                               ║
# ╚══════════════════════════════════════════════════════════╝

def is_valid_ip(ip: str) -> bool:
    """Vérifie si l'IP est valide (IPv4 ou IPv6)."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Retourne True si l'IP est privée/réservée."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_whitelisted(ip: str) -> bool:
    """Retourne True si l'IP est en whitelist."""
    if ip in Config.WHITELIST_IPS:
        return True
    state = load_state()
    return ip in state.get("whitelist", [])


def get_ip_type(ip: str) -> str:
    """Retourne le type d'IP : 'private', 'public', 'invalid'."""
    if not is_valid_ip(ip):
        return "invalid"
    if is_private_ip(ip):
        return "private"
    return "public"


# ╔══════════════════════════════════════════════════════════╗
# ║                   ÉTAT PARTAGÉ JSON                      ║
# ╚══════════════════════════════════════════════════════════╝

def _default_state() -> dict:
    return SOCState().to_dict()


def load_state() -> dict:
    """Charge l'état depuis le fichier JSON (verrouillé inter-process)."""
    with _lock, _state_lock():
        if not os.path.exists(Config.STATE_FILE):
            os.makedirs(os.path.dirname(Config.STATE_FILE), exist_ok=True)
            _write_state(_default_state())
            return _default_state()
        try:
            with open(Config.STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
            # Assurer que toutes les clés existent
            default = _default_state()
            for key in default:
                if key not in state:
                    state[key] = default[key]
            return state
        except (json.JSONDecodeError, Exception) as e:
            log.error(f"État corrompu, réinitialisation: {e}")
            _write_state(_default_state())
            return _default_state()


def _write_state(state: dict):
    """Écrit l'état de façon atomique."""
    os.makedirs(os.path.dirname(Config.STATE_FILE), exist_ok=True)
    tmp = Config.STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    os.replace(tmp, Config.STATE_FILE)


def save_state(state: dict):
    """Sauvegarde l'état (verrouillé inter-process)."""
    with _lock, _state_lock():
        _write_state(state)


# ╔══════════════════════════════════════════════════════════╗
# ║                    JOURNALISATION                        ║
# ╚══════════════════════════════════════════════════════════╝

def should_alert(key: str, window_seconds: int = 3600) -> bool:
    """
    Anti-spam : retourne True si une alerte pour cette `key` (ex: "brute_force:1.2.3.4")
    n'a PAS déjà été envoyée dans la fenêtre `window_seconds` (défaut 1h).
    Si True, marque aussi la clé comme envoyée maintenant.
    Empêche de saturer Telegram avec la même alerte répétée en boucle.
    """
    import time as _time
    now = _time.time()
    state = load_state()
    throttle = state.get("alert_throttle", {})

    last = throttle.get(key, 0)
    if now - last < window_seconds:
        return False

    throttle[key] = now
    # Nettoyage : purge les entrées de plus de 24h pour ne pas grossir indéfiniment
    cutoff = now - 86400
    throttle = {k: v for k, v in throttle.items() if v >= cutoff}
    state["alert_throttle"] = throttle
    save_state(state)
    return True


def clear_throttle(key: str):
    """
    Annule une réservation de throttle — à utiliser quand l'action qui a
    consommé le throttle a ÉCHOUÉ (ex: création de Case TheHive en erreur).
    Sans ça, un échec temporaire (mauvaise config, API down) bloquerait
    tout nouvel essai pendant 1h même après correction du problème.
    """
    state = load_state()
    throttle = state.get("alert_throttle", {})
    if key in throttle:
        del throttle[key]
        state["alert_throttle"] = throttle
        save_state(state)


def add_log(action: str, detail: str, ip: str = "", category: str = ""):
    """Ajoute une entrée dans le journal SOC (max 500 entrées)."""
    entry = SOCLog(
        timestamp=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        action=action,
        detail=detail[:200],
        ip=ip,
        category=category
    ).to_dict()
    
    state = load_state()
    state["logs"].insert(0, entry)
    state["logs"] = state["logs"][:500]
    save_state(state)
    log.info(f"[{action}] {detail}")


def get_last_logs(n: int = 20) -> list:
    """Retourne les n dernières entrées de log."""
    return load_state()["logs"][:n]


def is_alert_processed(alert_id: str) -> bool:
    """Vérifie si une alerte a déjà été traitée."""
    state = load_state()
    return alert_id in state.get("processed_alerts", [])


def mark_alert_processed(alert_id: str):
    """Marque une alerte comme traitée."""
    state = load_state()
    if "processed_alerts" not in state:
        state["processed_alerts"] = []
    state["processed_alerts"].append(alert_id)
    # Garder seulement les 10000 derniers
    state["processed_alerts"] = state["processed_alerts"][-10000:]
    save_state(state)


def get_processed_set() -> set:
    """
    Charge processed_alerts UNE SEULE FOIS sous forme de set (lookup O(1)
    au lieu de O(n) sur une liste). À utiliser en début de cycle pour
    éviter un load_state() par alerte individuelle.
    """
    state = load_state()
    return set(state.get("processed_alerts", []))


def commit_processed_ids(new_ids: set):
    """
    Persiste en UNE SEULE écriture disque tous les IDs traités pendant
    un cycle, au lieu d'un save_state() par alerte. processed_alerts
    n'est modifié que par surveillance_soc.py — aucun risque de
    désynchronisation avec telegram_bot.py / response_soc.py qui ne
    touchent jamais ce champ.
    """
    if not new_ids:
        return
    state = load_state()
    existing = state.get("processed_alerts", [])
    existing.extend(new_ids)
    state["processed_alerts"] = existing[-10000:]
    save_state(state)


# ╔══════════════════════════════════════════════════════════╗
# ║              FIREWALL — IPTABLES                         ║
# ╚══════════════════════════════════════════════════════════╝

def _iptables_run(cmd: list, check: bool = False) -> bool:
    """Exécute une commande iptables."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        if check and result.returncode != 0:
            log.error(f"iptables erreur: {' '.join(cmd)} — {result.stderr.strip()}")
            return False
        return True
    except subprocess.TimeoutExpired:
        log.error(f"iptables timeout: {' '.join(cmd)}")
        return False
    except Exception as e:
        log.error(f"iptables exception: {e}")
        return False


def iptables_setup_chain():
    """Initialise la chaîne iptables SOC_GUARD."""
    chain = Config.IPTABLES_CHAIN
    
    # Vérifier si la chaîne existe
    result = subprocess.run(
        ["/sbin/iptables", "-L", chain, "-n"],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        subprocess.run(["/sbin/iptables", "-N", chain], capture_output=True)
        log.info(f"Chaîne iptables '{chain}' créée")
    
    # Ajouter aux hooks
    for hook in ["INPUT", "FORWARD"]:
        res = subprocess.run(
            ["/sbin/iptables", "-C", hook, "-j", chain],
            capture_output=True
        )
        if res.returncode != 0:
            subprocess.run(
                ["/sbin/iptables", "-I", hook, "1", "-j", chain],
                capture_output=True
            )
            log.info(f"Chaîne '{chain}' ajoutée à {hook}")
    
    log.info(f"Chaîne iptables '{chain}' prête")


def iptables_block(ip: str) -> bool:
    """Bloque une IP via iptables."""
    # Vérifier si la règle existe déjà
    check = subprocess.run(
        ["/sbin/iptables", "-C", Config.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"],
        capture_output=True
    )
    if check.returncode == 0:
        return True
    
    return _iptables_run([
        "/sbin/iptables", "-A", Config.IPTABLES_CHAIN,
        "-s", ip, "-j", "DROP", "-m", "comment",
        "--comment", "SOC_GUARD"
    ], check=True)


def iptables_unblock(ip: str) -> bool:
    """Débloque une IP via iptables."""
    return _iptables_run([
        "/sbin/iptables", "-D", Config.IPTABLES_CHAIN,
        "-s", ip, "-j", "DROP"
    ])


def iptables_list_blocked() -> list:
    """Liste les IPs bloquées via iptables."""
    result = subprocess.run(
        ["/sbin/iptables", "-L", Config.IPTABLES_CHAIN, "-n", "--line-numbers"],
        capture_output=True, text=True
    )
    blocked = []
    for line in result.stdout.split("\n"):
        if "DROP" in line:
            parts = line.split()
            if len(parts) >= 4:
                blocked.append(parts[3])
    return blocked


# ╔══════════════════════════════════════════════════════════╗
# ║              FIREWALL — NFTABLES                         ║
# ╚══════════════════════════════════════════════════════════╝

def nftables_setup():
    """Initialise la table et chaîne nftables."""
    table = Config.NFTABLES_TABLE
    chain = Config.NFTABLES_CHAIN
    
    # Créer la table si elle n'existe pas
    subprocess.run(
        ["nft", "add", "table", "ip", table],
        capture_output=True
    )
    
    # Créer la chaîne
    subprocess.run(
        ["nft", "add", "chain", "ip", table, chain,
         "{ type filter hook input priority 0 ; policy accept ; }"],
        capture_output=True
    )
    
    log.info(f"Table nftables '{table}' prête")


def nftables_block(ip: str) -> bool:
    """Bloque une IP via nftables."""
    result = subprocess.run(
        ["nft", "add", "rule", "ip", Config.NFTABLES_TABLE,
         Config.NFTABLES_CHAIN, "ip", "saddr", ip, "drop"],
        capture_output=True, text=True
    )
    return result.returncode == 0


def nftables_unblock(ip: str) -> bool:
    """Débloque une IP via nftables."""
    result = subprocess.run(
        ["nft", "delete", "rule", "ip", Config.NFTABLES_TABLE,
         Config.NFTABLES_CHAIN, "ip", "saddr", ip, "drop"],
        capture_output=True, text=True
    )
    return result.returncode == 0


def nftables_list_blocked() -> list:
    """Liste les IPs bloquées via nftables."""
    result = subprocess.run(
        ["nft", "list", "chain", "ip", Config.NFTABLES_TABLE, Config.NFTABLES_CHAIN],
        capture_output=True, text=True
    )
    blocked = []
    for line in result.stdout.split("\n"):
        if "saddr" in line and "drop" in line:
            parts = line.split()
            try:
                idx = parts.index("saddr")
                if idx + 1 < len(parts):
                    blocked.append(parts[idx + 1])
            except ValueError:
                pass
    return blocked


# ╔══════════════════════════════════════════════════════════╗
# ║              FIREWALL — INTERFACE UNIFIÉE                ║
# ╚══════════════════════════════════════════════════════════╝

def firewall_setup():
    """Initialise le firewall (iptables ou nftables)."""
    if Config.FIREWALL_BACKEND == "nftables":
        nftables_setup()
    else:
        iptables_setup_chain()


def firewall_block(ip: str) -> bool:
    """Bloque une IP via le firewall configuré."""
    if Config.FIREWALL_BACKEND == "nftables":
        return nftables_block(ip)
    return iptables_block(ip)


def firewall_unblock(ip: str) -> bool:
    """Débloque une IP via le firewall configuré."""
    if Config.FIREWALL_BACKEND == "nftables":
        return nftables_unblock(ip)
    return iptables_unblock(ip)


def firewall_list_blocked() -> list:
    """Liste les IPs bloquées."""
    if Config.FIREWALL_BACKEND == "nftables":
        return nftables_list_blocked()
    return iptables_list_blocked()


# ╔══════════════════════════════════════════════════════════╗
# ║              FAIL2BAN INTEGRATION                        ║
# ╚══════════════════════════════════════════════════════════╝

def fail2ban_block(ip: str) -> bool:
    """Ajoute une IP dans Fail2ban (jail soc-auto)."""
    if not Config.FAIL2BAN_ENABLE:
        return False
    try:
        result = subprocess.run(
            ["fail2ban-client", "set", Config.FAIL2BAN_JAIL, "banip", ip],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            log.info(f"Fail2ban: {ip} banni dans jail '{Config.FAIL2BAN_JAIL}'")
            return True
        log.warning(f"Fail2ban ban {ip}: {result.stderr.strip()}")
        return False
    except FileNotFoundError:
        log.debug("fail2ban-client non trouvé — skip")
        return False
    except Exception as e:
        log.error(f"Fail2ban erreur: {e}")
        return False


def fail2ban_unblock(ip: str) -> bool:
    """Retire une IP de Fail2ban."""
    if not Config.FAIL2BAN_ENABLE:
        return False
    try:
        result = subprocess.run(
            ["fail2ban-client", "set", Config.FAIL2BAN_JAIL, "unbanip", ip],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


# ╔══════════════════════════════════════════════════════════╗
# ║              GESTION DES BLOCAGES                        ║
# ╚══════════════════════════════════════════════════════════╝

def _schedule_unblock(ip: str, seconds: int):
    """Programme un déblocage automatique."""
    global _active_timers
    if ip in _active_timers:
        _active_timers[ip].cancel()
    timer = threading.Timer(seconds, _auto_unblock, args=[ip])
    timer.daemon = True
    timer.start()
    _active_timers[ip] = timer


def _auto_unblock(ip: str):
    """Callback de déblocage automatique."""
    global _active_timers
    _active_timers.pop(ip, None)
    unblock_ip(ip, source="auto-expiration")


def check_expired_blocks():
    """Vérifie et nettoie les blocages expirés."""
    state = load_state()
    expired = []
    
    for ip, info in state["blocked_ips"].items():
        blocked = BlockedIP(
            ip=ip,
            reason=info.get("raison", ""),
            blocked_at=info.get("bloque_le", ""),
            unblock_at=info.get("debloque_le"),
            permanent=info.get("permanent", False),
            source=info.get("source", "")
        )
        if blocked.is_expired:
            expired.append(ip)
    
    for ip in expired:
        firewall_unblock(ip)
        del state["blocked_ips"][ip]
        add_log("EXPIRATION", f"Blocage expiré pour {ip}", ip)
    
    if expired:
        save_state(state)
        log.info(f"{len(expired)} blocage(s) expiré(s) nettoyé(s)")


def record_native_block(ip: str, reason: str, category: str, agent: str, timeout_seconds: int = 7200):
    """
    Enregistre un blocage géré NATIVEMENT par Wazuh active-response
    (pas par notre script). Sert uniquement à l'affichage Telegram
    (/blocked, /check, /stats) — on ne peut PAS débloquer ces IPs
    depuis le bot, puisque c'est Wazuh (sur l'agent) qui gère ça, pas
    nous. Sans ce suivi, /blocked resterait vide pour ces catégories.
    """
    import time as _t
    state = load_state()
    if "native_blocked_ips" not in state:
        state["native_blocked_ips"] = {}
    now = _t.time()
    state["native_blocked_ips"][ip] = {
        "raison": reason,
        "categorie": category,
        "agent": agent,
        "blocked_at": now,
        "estimated_expiry": now + timeout_seconds
    }
    # Purge les entrées expirées depuis longtemps (> 24h après expiration estimée)
    state["native_blocked_ips"] = {
        k: v for k, v in state["native_blocked_ips"].items()
        if v.get("estimated_expiry", 0) > now - 86400
    }
    save_state(state)


def get_native_blocks() -> dict:
    """Retourne les blocages natifs Wazuh actuellement estimés actifs."""
    import time as _t
    state = load_state()
    now = _t.time()
    return {
        ip: info for ip, info in state.get("native_blocked_ips", {}).items()
        if info.get("estimated_expiry", 0) > now
    }


def block_ip(ip: str, reason: str, duration: int = None,
             permanent: bool = False, source: str = "auto",
             category: str = "") -> bool:
    """
    Bloque une IP via le firewall.
    
    Args:
        ip: L'adresse IP à bloquer
        reason: Raison du blocage
        duration: Durée en secondes (défaut: BLOCK_DURATION)
        permanent: Si True, pas de déblocage automatique
        source: Source du blocage (auto, admin, wazuh, etc.)
        category: Catégorie de l'alerte
    
    Returns:
        True si le blocage a réussi
    """
    if not is_valid_ip(ip):
        log.error(f"IP invalide: {ip}")
        return False
    
    if is_whitelisted(ip):
        log.info(f"{ip} en whitelist — blocage ignoré")
        return False
    
    if duration is None:
        duration = Config.BLOCK_DURATION

    state = load_state()
    if ip in state["blocked_ips"]:
        return False

    if not firewall_block(ip):
        return False

    # Fail2ban en parallèle (non bloquant si absent)
    fail2ban_block(ip)

    now = datetime.now()
    unblock_at = None if permanent else (now + timedelta(seconds=duration)).isoformat()
    today = now.strftime("%Y-%m-%d")

    # Reset stats journalier
    if state["stats"]["last_reset"] != today:
        state["stats"]["total_today"] = 0
        state["stats"]["last_reset"] = today

    state["blocked_ips"][ip] = {
        "raison": reason[:100],
        "bloque_le": now.isoformat(),
        "debloque_le": unblock_at,
        "permanent": permanent,
        "source": source,
        "category": category
    }
    
    # Mise à jour des stats
    state["stats"]["total_today"] += 1
    state["stats"]["total_week"] += 1
    if is_private_ip(ip):
        state["stats"]["total_blocked_private"] += 1
    
    save_state(state)
    
    duration_txt = "🔒 Permanent" if permanent else f"{duration//3600}h{(duration%3600)//60:02d}min"
    add_log("BLOCAGE", f"{ip} — {reason} ({duration_txt})", ip, category)

    if not permanent:
        _schedule_unblock(ip, duration)

    return True


def unblock_ip(ip: str, source: str = "auto", notify: bool = True) -> bool:
    """Débloque une IP."""
    state = load_state()
    if ip not in state["blocked_ips"]:
        return False
    
    firewall_unblock(ip)
    fail2ban_unblock(ip)
    del state["blocked_ips"][ip]
    save_state(state)
    add_log("DEBLOCAGE", f"{ip} débloquée ({source})", ip)

    if notify:
        telegram_send(
            f"✅ <b>IP DÉBLOQUÉE</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🌐 IP     : <code>{ip}</code>\n"
            f"📋 Source : {source}\n"
            f"🕐 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            force=True
        )
    return True


def prolong_block(ip: str, added_seconds: int = None) -> bool:
    """Prolonge le blocage d'une IP."""
    if added_seconds is None:
        added_seconds = Config.BLOCK_DURATION
    
    state = load_state()
    info = state["blocked_ips"].get(ip)
    if not info or info.get("permanent"):
        return False
    
    try:
        if info.get("debloque_le"):
            current_end = datetime.fromisoformat(info["debloque_le"])
            base = max(current_end, datetime.now())
        else:
            base = datetime.now()
        new_end = base + timedelta(seconds=added_seconds)
        info["debloque_le"] = new_end.isoformat()
        save_state(state)
        
        remaining = int((new_end - datetime.now()).total_seconds())
        _schedule_unblock(ip, remaining)
        add_log("PROLONGATION", f"{ip} prolongé de {added_seconds//3600}h", ip)
        return True
    except (ValueError, TypeError) as e:
        log.error(f"Erreur prolongation {ip}: {e}")
        return False


def ban_permanent(ip: str, reason: str = "Banni par admin") -> bool:
    """Bannissement définitif d'une IP."""
    global _active_timers
    
    if ip in _active_timers:
        _active_timers[ip].cancel()
        _active_timers.pop(ip, None)
    
    state = load_state()
    if ip in state["blocked_ips"]:
        state["blocked_ips"][ip]["permanent"] = True
        state["blocked_ips"][ip]["debloque_le"] = None
        save_state(state)
    else:
        if not firewall_block(ip):
            return False
        state = load_state()
        state["blocked_ips"][ip] = {
            "raison": reason,
            "bloque_le": datetime.now().isoformat(),
            "debloque_le": None,
            "permanent": True,
            "source": "admin",
            "category": "ban"
        }
        save_state(state)
    
    add_log("BAN_PERMANENT", f"{ip} bannie — {reason}", ip)
    return True


def add_to_whitelist(ip: str):
    """Ajoute une IP à la whitelist."""
    if not is_valid_ip(ip):
        return
    state = load_state()
    if ip not in state["whitelist"]:
        state["whitelist"].append(ip)
        save_state(state)
    unblock_ip(ip, source="whitelist", notify=False)
    add_log("WHITELIST", f"{ip} ajoutée à la whitelist", ip)


def get_remaining_time(ip: str) -> str:
    """Temps restant avant déblocage."""
    state = load_state()
    info = state["blocked_ips"].get(ip)
    if not info:
        return "N/A"
    blocked = BlockedIP(
        ip=ip, reason="", blocked_at="",
        unblock_at=info.get("debloque_le"),
        permanent=info.get("permanent", False), source=""
    )
    return blocked.remaining_time


# ╔══════════════════════════════════════════════════════════╗
# ║                      TELEGRAM                            ║
# ╚══════════════════════════════════════════════════════════╝

def telegram_send(msg: str, reply_markup: dict = None,
                  check_silence: bool = True, force: bool = False,
                  buttons: dict = None):
    """Envoie un message Telegram."""
    # Accepter 'buttons' comme alias de 'reply_markup'
    if buttons is not None and reply_markup is None:
        reply_markup = buttons

    if not Config.TELEGRAM_TOKEN or not Config.TELEGRAM_CHAT:
        return

    if check_silence and not force:
        state = load_state()
        silence = state.get("silence_until")
        if silence:
            try:
                if datetime.fromisoformat(silence) > datetime.now():
                    return
            except ValueError:
                pass

    try:
        url = f"https://api.telegram.org/bot{Config.TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": Config.TELEGRAM_CHAT,
            "text": msg[:4096],
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        if reply_markup:
            payload["reply_markup"] = json.dumps(reply_markup)
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        log.error(f"Telegram erreur: {e}")


def inline_keyboard(buttons: list) -> dict:
    """Construit un clavier inline Telegram (boutons attachés à un message)."""
    return {
        "inline_keyboard": [
            [{"text": text, "callback_data": data} for text, data in row]
            for row in buttons
        ]
    }


def reply_keyboard(rows: list, resize: bool = True, persistent: bool = True) -> dict:
    """
    Construit un clavier PERMANENT en bas de l'écran Telegram
    (visible tout le temps, pas attaché à un message précis).
    rows: liste de lignes, chaque ligne = liste de labels texte.
    Exemple: [["/status", "/logs"], ["/blocked", "/stats"]]
    """
    return {
        "keyboard": [[{"text": label} for label in row] for row in rows],
        "resize_keyboard": resize,
        "is_persistent": persistent,
        "one_time_keyboard": False
    }


# ╔══════════════════════════════════════════════════════════╗
# ║              INITIALISATION AU DÉMARRAGE                  ║
# ╚══════════════════════════════════════════════════════════╝

def init_soc():
    """Initialisation complète au démarrage."""
    log.info("═════════════════════════════════════════════")
    log.info("  SOC AUTOMATION — INITIALISATION")
    log.info("═════════════════════════════════════════════")
    
    # Validation configuration
    errors = Config.validate()
    if errors:
        log.warning(f"Configuration incomplète: {', '.join(errors)}")
    
    log.info(f"Config: {Config.summary()}")
    
    # Setup firewall
    firewall_setup()
    
    # Nettoyer les blocages expirés
    check_expired_blocks()
    
    # Reprogrammer les timers
    state = load_state()
    now = datetime.now()
    for ip, info in state["blocked_ips"].items():
        if info.get("permanent") or not info.get("debloque_le"):
            continue
        try:
            end = datetime.fromisoformat(info["debloque_le"])
            remaining = int((end - now).total_seconds())
            if remaining > 0:
                _schedule_unblock(ip, remaining)
                log.debug(f"Timer reprogrammé: {ip} ({remaining}s)")
        except ValueError:
            pass
    
    log.info("Initialisation terminée ✓")