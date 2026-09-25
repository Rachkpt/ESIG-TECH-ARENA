#!/usr/bin/env python3
"""
telegram_bot.py — Console Admin SOC via Telegram
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Commandes complètes pour piloter le SOC depuis mobile.
"""

import sys
import time
import hashlib
import logging
import requests
from datetime import datetime, timedelta

from soc_config import Config, Severity
from soc_utils import (
    is_valid_ip, is_whitelisted, is_private_ip,
    load_state, save_state, add_log, get_last_logs,
    block_ip, unblock_ip, prolong_block, ban_permanent,
    add_to_whitelist, get_remaining_time,
    telegram_send, inline_keyboard, reply_keyboard, check_expired_blocks,
    firewall_list_blocked, get_native_blocks,
    get_pending_decisions, get_pending_decision, resolve_pending_decision,
    bump_sector_stat, get_sector_stats, reset_offense, telegram_send_document
)
from soc_clients import wazuh, thehive, cortex
from soc_assets import sector_emoji, sector_label, all_assets, Criticality

log = logging.getLogger("telegram_bot")
API = f"https://api.telegram.org/bot{Config.TELEGRAM_TOKEN}"


# ╔══════════════════════════════════════════════════════════╗
# ║                     SÉCURITÉ                             ║
# ╚══════════════════════════════════════════════════════════╝

def is_admin(chat_id) -> bool:
    if str(chat_id) != str(Config.TELEGRAM_CHAT):
        add_log("ACCES_REFUSE", f"chat_id={chat_id}")
        return False
    return True


def answer_callback(cb_id: str, text: str = "✅"):
    try:
        requests.post(f"{API}/answerCallbackQuery",
                      json={"callback_query_id": cb_id, "text": text}, timeout=5)
    except Exception:
        pass


# ╔══════════════════════════════════════════════════════════╗
# ║                       MENUS                              ║
# ╚══════════════════════════════════════════════════════════╝

def persistent_keyboard():
    """
    Clavier PERMANENT complet — regroupe toutes les commandes en bas
    de l'écran Telegram, toujours visible. Libellés descriptifs alignés
    sur le texte exact du menu /menu (SOC ADMIN CONSOLE).
    """
    # Les 4 boutons "10 Dernières Alertes", "IPs Ping & NMAP",
    # "IPs Malveillantes / Logs" et "IPs Bloquées" ont été RETIRÉS du
    # clavier du bas (demande 12ak_H4ck). Leurs fonctions restent 100%
    # accessibles via le menu inline /menu et les commandes slash
    # /alerts /scan /malicious /blocked.
    return reply_keyboard([
        ["🔓 Débloquer une IP", "🔄 Actualiser"],
        ["📋 État du système", "📜 Dernières actions"],
        ["📊 Statistiques", "📁 Cases TheHive"],
        ["🧠 Rapport IA", "✅ Vérifier expirations"],
        ["🖥️ Agents", "🔍 Lancer Cortex"],
        ["🗂️ Case manuel", "⛔ Bloquer IP"],
        ["🚫 Bannir permanent", "✅ Whitelister"],
        ["🔇 Couper notifs"]
    ])


def main_menu():
    kb = inline_keyboard([
        [("⚠️ 10 Alertes", "cmd_alerts"),
         ("🔍 Ping & NMAP", "cmd_scan_attempts")],
        [("🛑 IPs Malveillantes", "cmd_malicious_ips"),
         ("🚫 IPs Bloquées", "cmd_blocked")],
        [("📋 Statut Système", "cmd_status"),
         ("📜 Derniers Logs", "cmd_logs")],
        [("📊 Statistiques", "cmd_stats"),
         ("🐝 Cases TheHive", "cmd_cases")],
        [("🧠 Rapport IA", "cmd_report"),
         ("🖥️ Agents", "cmd_agents")],
        [("⏳ Décisions en attente", "cmd_pending"),
         ("🏢 Secteurs", "cmd_sectors")],
        [("📄 Rapport PDF", "cmd_pdf")],
        [("🔍 Analyser IP", "cmd_analyze_prompt"),
         ("📁 Créer Case", "cmd_case_prompt")],
        [("🔇 Silence 30min", "cmd_silence30")]
    ])
    telegram_send(
        "🛡️ <b>SOC ADMIN CONSOLE</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "<code>/status</code> — État du système\n"
        "<code>/logs</code> — Dernières actions\n"
        "<code>/blocked</code> — IPs bloquées\n"
        "<code>/block IP MIN</code> — Bloquer IP\n"
        "<code>/unblock IP</code> — Débloquer\n"
        "<code>/ban IP</code> — Bannir permanent\n"
        "<code>/whitelist IP</code> — Whitelister\n"
        "<code>/cases</code> — Cases TheHive\n"
        "<code>/analyze IP</code> — Lancer Cortex (IP)\n"
        "<code>/url URL</code> — Scanner une URL\n"
        "<code>/domain DOMAINE</code> — Scanner un domaine\n"
        "<code>/hash HASH</code> — Scanner un hash\n"
        "📎 <i>Envoie un fichier au bot pour le tester (virus ?)</i>\n"
        "<code>/createcase IP</code> — Case manuel\n"
        "<code>/stats</code> — Statistiques\n"
        "<code>/report</code> — Rapport IA\n"
        "<code>/alerts</code> — 10 dernières alertes\n"
        "<code>/scan</code> — IPs ping/nmap\n"
        "<code>/malicious</code> — IPs malveillantes\n"
        "<code>/attente</code> — Décisions à valider (critique)\n"
        "<code>/secteurs</code> — SOC par secteur\n"
        "<code>/pdf</code> — Rapport d'activité PDF\n"
        "<code>/silence MIN</code> — Couper notifs\n"
        "<code>/check</code> — Vérifier expirations\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "🔰 By <b>12ak_H4ck</b>",
        buttons=kb
    )
    # Active le clavier permanent en bas de l'écran
    telegram_send("⌨️ Clavier rapide activé en bas de l'écran.", buttons=persistent_keyboard())


# ╔══════════════════════════════════════════════════════════╗
# ║                    COMMANDES                             ║
# ╚══════════════════════════════════════════════════════════╝

def cmd_status():
    services = {
        "Wazuh": Config.WAZUH_URL,
        "TheHive": Config.THEHIVE_URL,
        "Cortex": Config.CORTEX_URL
    }
    lines = []
    for name, url in services.items():
        client = {"Wazuh": wazuh, "TheHive": thehive, "Cortex": cortex}[name]
        ok = "✅" if client.check_connectivity() else "❌"
        lines.append(f"{ok} {name}")

    state = load_state()
    pending = sum(1 for c in state.get("cases", []) if not c.get("analyzed"))
    native_count = len(get_native_blocks())

    telegram_send(
        f"📋 <b>STATUT SYSTÈME</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        + "\n".join(lines) +
        f"\n\n🔒 IPs bloquées (script) : {len(state['blocked_ips'])}\n"
        f"🛡️ IPs bloquées (Wazuh natif) : {native_count}\n"
        f"📁 Cases en attente : {pending}\n"
        f"🔥 Firewall : {Config.FIREWALL_BACKEND}\n"
        f"🧠 IA : {Config.GROQ_MODEL}\n"
        f"🕐 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
    )


def cmd_agents():
    """Affiche le statut (up/down) de tous les agents Wazuh."""
    agents = wazuh.get_agents()
    if not agents:
        telegram_send(
            "⚠️ Impossible de récupérer les agents.\n"
            "📋 Voir <code>journalctl -u soc-script1</code> ou "
            "<code>journalctl -u soc-telegram</code> pour le détail exact de l'erreur API."
        )
        return

    up = [a for a in agents if a.get("status") == "active"]
    down = [a for a in agents if a.get("status") == "disconnected"]
    never = [a for a in agents if a.get("status") == "never_connected"]

    lines = [f"🖥️ <b>AGENTS WAZUH ({len(agents)})</b>", "━━━━━━━━━━━━━━━━━━━━━━━━"]

    if up:
        lines.append(f"\n✅ <b>En ligne ({len(up)})</b>")
        for a in up[:15]:
            lines.append(f"  🟢 {a.get('name','?')} — <code>{a.get('ip','?')}</code>")

    if down:
        lines.append(f"\n❌ <b>Hors ligne ({len(down)})</b>")
        for a in down[:15]:
            lines.append(f"  🔴 {a.get('name','?')} — <code>{a.get('ip','?')}</code>")

    if never:
        lines.append(f"\n⚪ <b>Jamais connectés ({len(never)})</b>")
        for a in never[:10]:
            lines.append(f"  ⚪ {a.get('name','?')}")

    telegram_send("\n".join(lines))


def cmd_logs():
    logs = get_last_logs(20)
    if not logs:
        telegram_send("📜 Aucune action enregistrée.")
        return
    lines = [f"🕐 {l['ts']}\n   [{l['action']}] {l['detail'][:55]}" for l in logs]
    telegram_send("📜 <b>20 DERNIÈRES ACTIONS</b>\n━━━━━━━━━━━━━━━━━━━━━━━━\n" + "\n\n".join(lines))


def cmd_blocked():
    state = load_state()
    blocked = state["blocked_ips"]
    native = get_native_blocks()

    if not blocked and not native:
        telegram_send("🔓 Aucune IP bloquée.")
        return

    lines = []
    if blocked:
        lines.append(f"<b>🔒 Bloquées par le script ({len(blocked)})</b> — débloquables ci-dessous")
        for ip, info in list(blocked.items())[:15]:
            lines.append(f"🌐 <code>{ip}</code> — {get_remaining_time(ip)}\n   {info['raison'][:45]}")

    if native:
        lines.append(f"\n<b>🛡️ Bloquées nativement par Wazuh ({len(native)})</b> — sur l'agent ciblé, pas débloquable ici")
        for ip, info in list(native.items())[:15]:
            remaining_min = max(0, int((info["estimated_expiry"] - __import__('time').time()) / 60))
            lines.append(
                f"🌐 <code>{ip}</code> — ~{remaining_min}min restantes\n"
                f"   {info['raison'][:45]}\n"
                f"   🎯 Agent : {info['agent']}"
            )

    # Seules les IPs bloquées par LE SCRIPT peuvent être débloquées via ce bot
    kb_rows = [[(f"🔓 {ip}", f"unblock_{ip}")] for ip in list(blocked.keys())[:6]]
    if blocked:
        kb_rows.append([("🚫 Tout débloquer (script)", "unblock_all")])
    kb = inline_keyboard(kb_rows) if kb_rows else None

    telegram_send(
        f"🔒 <b>IPs BLOQUÉES ({len(blocked) + len(native)})</b>\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
        + "\n\n".join(lines),
        buttons=kb
    )


def cmd_stats():
    state = load_state()
    stats = state["stats"]
    
    # Top IPs
    ip_counts = {}
    for l in state["logs"]:
        if l.get("ip"):
            ip_counts[l["ip"]] = ip_counts.get(l["ip"], 0) + 1
    top = sorted(ip_counts.items(), key=lambda x: -x[1])[:5]
    top_txt = "\n".join([f"  • <code>{ip}</code> — {n} événements" for ip, n in top]) or "  Aucune donnée"

    telegram_send(
        f"📊 <b>STATISTIQUES SOC</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔒 Bloquées aujourd'hui : {stats.get('total_today', 0)}\n"
        f"📅 Bloquées cette semaine : {stats.get('total_week', 0)}\n"
        f"🖥️ IPs privées bloquées : {stats.get('total_blocked_private', 0)}\n"
        f"🌍 Cases IP publiques : {stats.get('total_cases_public', 0)}\n"
        f"🦠 Malwares détectés : {stats.get('total_malware', 0)}\n"
        f"🔐 Brute forces : {stats.get('total_bruteforce', 0)}\n"
        f"🌐 Actuellement bloquées : {len(state['blocked_ips'])}\n\n"
        f"🏆 <b>Top IPs :</b>\n{top_txt}"
    )


def cmd_cases():
    cases = thehive.get_cases(8)
    if not cases:
        telegram_send("🐝 Aucun Case récent.")
        return
    lines = []
    for c in cases:
        sev = {1: "🟡", 2: "🟠", 3: "🔴", 4: "🔥"}.get(c.get("severity", 0), "⚪")
        lines.append(f"{sev} <b>#{c.get('number', '?')}</b> — {c.get('title', '')[:40]}\n   {c.get('status', '?')}")
    telegram_send("🐝 <b>CASES THEHIVE RÉCENTS</b>\n━━━━━━━━━━━━━━━━━━━━━━━━\n" + "\n\n".join(lines))


def cmd_report():
    state = load_state()
    state["report_requested"] = True
    save_state(state)
    telegram_send("🧠 Rapport IA en cours de génération...")


def cmd_check():
    check_expired_blocks()
    telegram_send("✅ Vérification des expirations terminée.")


def cmd_block(ip: str, minutes: int):
    if not is_valid_ip(ip):
        telegram_send(f"❌ IP invalide: <code>{ip}</code>")
        return
    if is_whitelisted(ip):
        telegram_send(f"❌ IP en whitelist: <code>{ip}</code>")
        return
    if minutes < 1 or minutes > 10080:
        telegram_send("❌ Durée: 1-10080 minutes")
        return
    ok = block_ip(ip, "Blocage manuel admin", duration=minutes*60, source="admin")
    if not ok:
        telegram_send(f"⚠️ Déjà bloquée")
        return

    msg = f"🔒 <code>{ip}</code> bloquée {minutes}min (local: iptables + fail2ban)"
    if Config.WAZUH_AR_ON_MANUAL_BLOCK:
        if wazuh.run_active_response(ip):
            msg += "\n🛡️ + firewall-drop Wazuh déclenché sur les agents actifs"
        else:
            msg += "\n⚠️ firewall-drop Wazuh non déclenché (voir logs — vérifier WAZUH_AR_COMMAND)"
    telegram_send(msg)


def cmd_unblock(ip: str):
    if not is_valid_ip(ip):
        telegram_send(f"❌ IP invalide: <code>{ip}</code>")
        return
    ok = unblock_ip(ip, source="admin")
    reset_offense(ip)  # repartir de zéro : l'IP n'est plus une récidiviste
    if not ok:
        telegram_send("⚠️ Non trouvée")
        return
    msg = f"✅ <code>{ip}</code> débloquée (local)"
    # Déblocage natif Wazuh sur les agents
    if Config.WAZUH_AR_UNBLOCK_COMMAND:
        if wazuh.run_active_response(ip, action="delete"):
            msg += "\n🛡️ + déblocage firewall-drop Wazuh déclenché sur les agents"
        else:
            msg += "\n⚠️ Déblocage Wazuh non déclenché (voir logs)"
    elif Config.WAZUH_AR_ON_MANUAL_BLOCK:
        msg += ("\nℹ️ Blocage natif Wazuh : expire seul via son timeout "
                "(configure WAZUH_AR_UNBLOCK_COMMAND pour un déblocage immédiat).")
    telegram_send(msg)


def cmd_ban(ip: str):
    if not is_valid_ip(ip):
        telegram_send(f"❌ IP invalide: <code>{ip}</code>")
        return
    ok = ban_permanent(ip)
    if not ok:
        telegram_send("⚠️ Erreur")
        return

    msg = f"🚫 <code>{ip}</code> bannie (permanent, local)"
    if Config.WAZUH_AR_ON_MANUAL_BLOCK:
        if wazuh.run_active_response(ip):
            msg += "\n🛡️ + firewall-drop Wazuh déclenché sur les agents actifs"
        else:
            msg += "\n⚠️ firewall-drop Wazuh non déclenché (voir logs)"
    telegram_send(msg)


def cmd_whitelist(ip: str):
    if not is_valid_ip(ip):
        telegram_send(f"❌ IP invalide: <code>{ip}</code>")
        return
    add_to_whitelist(ip)
    telegram_send(f"✅ <code>{ip}</code> en whitelist")


def cmd_analyze(ip: str):
    if not is_valid_ip(ip):
        telegram_send(f"❌ IP invalide: <code>{ip}</code>")
        return
    telegram_send(f"🔍 Analyse Cortex lancée pour <code>{ip}</code>...")

    # Crée un VRAI Case TheHive (pas un faux ID) pour que Script 2
    # puisse commenter le résultat correctement une fois l'analyse faite.
    case = thehive.create_ip_case(
        ip, "Analyse manuelle", "Analyse demandée via Telegram",
        Severity.MEDIUM, "Telegram"
    )
    if not case:
        telegram_send(f"⚠️ Échec création du Case TheHive pour <code>{ip}</code> — analyse annulée.")
        return

    assignee = case.get("assignee", "")
    state = load_state()
    state["cases"].append({
        "case_id": case.get("_id", ""),
        "number": case.get("number", "?"),
        "ip": ip,
        "title": f"Analyse manuelle — {ip}",
        "description": "Analyse demandée via Telegram",
        "severity": 2,
        "data_type": "ip",
        "assignee": assignee,
        "extra_data": {"category": "manual"},
        "created_at": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "analyzed": False
    })
    save_state(state)
    if assignee:
        telegram_send(f"👤 Case #{case.get('number','?')} assigné à <b>{assignee}</b>")
    add_log("ANALYSE_MANUELLE", f"Analyse demandée pour {ip} — Case #{case.get('number','?')}", ip)


def _submit_observable(value: str, data_type: str, label: str):
    """
    Soumet un observable (url/domain/hash/ip) à l'analyse Cortex via un
    Case TheHive. Script 2 lance les analyzers du bon type, synthétise
    avec l'IA et renvoie TOUT sur Telegram.
    """
    value = value.strip()
    if not value:
        telegram_send(f"❌ Valeur vide. Usage : /{data_type} <{data_type}>")
        return
    telegram_send(f"🔍 Analyse Cortex ({label}) lancée pour <code>{value[:80]}</code>...")

    case = thehive.create_observable_case(
        value, data_type, f"Analyse manuelle {label}",
        f"Analyse {label} demandée via Telegram", Severity.MEDIUM, "Telegram"
    )
    if not case:
        telegram_send(f"⚠️ Échec création du Case TheHive pour <code>{value[:80]}</code>.")
        return

    assignee = case.get("assignee", "")
    state = load_state()
    state["cases"].append({
        "case_id": case.get("_id", ""),
        "number": case.get("number", "?"),
        "ip": value,                 # le Script 2 lit ce champ comme observable
        "title": f"Analyse {label} — {value[:40]}",
        "description": f"Analyse {label} demandée via Telegram",
        "severity": 2,
        "data_type": data_type,      # ← type explicite : url / domain / hash / ip
        "assignee": assignee,
        "extra_data": {"category": "manual"},
        "created_at": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "analyzed": False
    })
    save_state(state)
    if assignee:
        telegram_send(f"👤 Case #{case.get('number','?')} assigné à <b>{assignee}</b>")
    add_log("ANALYSE_MANUELLE", f"Analyse {label} demandée pour {value[:60]} — Case #{case.get('number','?')}", "")


def cmd_url(url: str):
    if not (url.startswith("http://") or url.startswith("https://")):
        telegram_send("❌ URL invalide (doit commencer par http:// ou https://).\nEx : /url https://exemple.com/page")
        return
    _submit_observable(url, "url", "URL")


def cmd_domain(domain: str):
    if "." not in domain or " " in domain:
        telegram_send("❌ Domaine invalide.\nEx : /domain mauvais-site.com")
        return
    _submit_observable(domain, "domain", "Domaine")


def cmd_hash(h: str):
    if len(h) not in (32, 40, 64) or not all(c in "0123456789abcdefABCDEF" for c in h):
        telegram_send("❌ Hash invalide (MD5/SHA1/SHA256 attendu).\nEx : /hash 131f95c5...")
        return
    _submit_observable(h, "hash", "Hash")


def handle_document(message: dict):
    """
    L'admin envoie un FICHIER au bot → on calcule son SHA256 et on lance
    l'analyse Cortex (analyzers hash : VirusTotal, Virusshare…) + IA, le
    tout renvoyé sur Telegram. Simple : juste glisser un fichier, aucune
    commande ni bouton à connaître.
    """
    chat_id = message["chat"]["id"]
    if not is_admin(chat_id):
        return

    doc = message.get("document") or {}
    file_id = doc.get("file_id")
    file_name = doc.get("file_name", "fichier")
    file_size = doc.get("file_size", 0)

    if not file_id:
        return
    # Telegram Bot API : téléchargement limité à ~20 Mo
    if file_size and file_size > 20 * 1024 * 1024:
        telegram_send(f"❌ Fichier trop volumineux ({file_size//(1024*1024)} Mo). Limite : 20 Mo.")
        return

    telegram_send(f"📎 Fichier reçu : <b>{file_name}</b>\n⏳ Calcul de l'empreinte SHA256...")

    try:
        # 1. Obtenir le chemin du fichier côté Telegram
        r = requests.get(f"{API}/getFile", params={"file_id": file_id}, timeout=15)
        file_path = r.json().get("result", {}).get("file_path")
        if not file_path:
            telegram_send("⚠️ Impossible de récupérer le fichier depuis Telegram.")
            return

        # 2. Télécharger le contenu et calculer le SHA256
        dl = requests.get(
            f"https://api.telegram.org/file/bot{Config.TELEGRAM_TOKEN}/{file_path}",
            timeout=60
        )
        sha256 = hashlib.sha256(dl.content).hexdigest()
    except Exception as e:
        log.error(f"handle_document: {e}")
        telegram_send("⚠️ Erreur lors du téléchargement / hachage du fichier.")
        return

    telegram_send(
        f"🔑 <b>SHA256</b> : <code>{sha256}</code>\n"
        f"📎 {file_name} ({file_size} octets)\n"
        f"🔬 Lancement de l'analyse antivirus (Cortex)..."
    )

    # 3. Réutilise tout le pipeline hash existant (Cortex + IA + Telegram)
    _submit_observable(sha256, "hash", f"Fichier {file_name}")


def cmd_createcase(ip: str):
    if not is_valid_ip(ip):
        telegram_send(f"❌ IP invalide: <code>{ip}</code>")
        return
    case = thehive.create_ip_case(ip, "Investigation manuelle", "Case créé via Telegram", 
                                   Severity.MEDIUM, "Telegram")
    if case:
        num = case.get("number", "?")
        telegram_send(f"✅ Case <b>#{num}</b> créé pour <code>{ip}</code>")
        add_log("CASE_MANUEL", f"Case #{num} pour {ip}", ip)
    else:
        telegram_send("❌ Erreur création Case")


def cmd_silence(minutes: int):
    if minutes < 1 or minutes > 1440:
        telegram_send("❌ Durée: 1-1440 minutes")
        return
    state = load_state()
    state["silence_until"] = (datetime.now() + timedelta(minutes=minutes)).isoformat()
    save_state(state)
    telegram_send(f"🔇 Notifications coupées {minutes}min", force=True)


def cmd_alerts():
    """10 dernières alertes Wazuh (toutes catégories confondues)."""
    alerts = wazuh.get_alerts(limit=10)
    if not alerts:
        telegram_send("ℹ️ Aucune alerte récente.")
        return
    lines = []
    for a in alerts[:10]:
        rule = a.get("rule", {})
        data = a.get("data", {}) or {}
        src = data.get("srcip", "?")
        lvl = rule.get("level", 0)
        desc = rule.get("description", "?")[:50]
        sev = "🟡" if lvl < 7 else ("🟠" if lvl < 10 else "🔴")
        lines.append(f"{sev} L{lvl} <code>{src}</code>\n   {desc}")
    telegram_send("⚠️ <b>10 DERNIÈRES ALERTES</b>\n━━━━━━━━━━━━━━━━━━━━━━━━\n" + "\n\n".join(lines))


def cmd_scan_attempts():
    """IPs ayant tenté un ping/nmap/scan réseau (détection passive)."""
    state = load_state()
    logs = state.get("logs", [])
    scan_logs = [
        l for l in logs
        if l.get("category") == "network_scan"
    ][:15]

    if not scan_logs:
        telegram_send("ℹ️ Aucune tentative de ping/nmap détectée récemment.")
        return

    # Regrouper par IP pour éviter les doublons (une IP peut scanner plusieurs fois)
    seen_ips = {}
    for l in scan_logs:
        ip = l.get("ip", "?")
        if ip not in seen_ips:
            seen_ips[ip] = l

    lines = []
    for ip, l in list(seen_ips.items())[:10]:
        lines.append(f"🔍 <code>{ip}</code>\n   {l.get('detail','')[:60]}\n   🕐 {l.get('ts','')}")

    kb_rows = [[(f"🚫 Bloquer {ip}", f"block_{ip}_120")] for ip in list(seen_ips.keys())[:5]]
    kb = inline_keyboard(kb_rows) if kb_rows else None

    telegram_send(
        f"🔍 <b>IPS AYANT TENTÉ PING/NMAP ({len(seen_ips)})</b>\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
        + "\n\n".join(lines),
        buttons=kb
    )


def cmd_malicious_ips():
    """IPs malveillantes connues — cases TheHive + IPs bloquées, vue consolidée."""
    state = load_state()
    cases = state.get("cases", [])
    blocked = state.get("blocked_ips", {})
    native = get_native_blocks()

    lines = []
    if cases:
        lines.append("<b>📁 Cases TheHive ouverts:</b>")
        for c in cases[-8:]:
            ip = c.get("ip", "")
            label = ip if ip else c.get("extra_data", {}).get("file", "?")
            lines.append(f"  🔴 <code>{label}</code> — #{c.get('number','?')} — {c.get('title','')[:40]}")

    if blocked:
        lines.append("\n<b>🚫 IPs bloquées par le script:</b>")
        for ip, info in list(blocked.items())[:8]:
            lines.append(f"  🌐 <code>{ip}</code> — {info.get('raison','')[:40]}")

    if native:
        lines.append("\n<b>🛡️ IPs bloquées nativement par Wazuh:</b>")
        for ip, info in list(native.items())[:8]:
            lines.append(f"  🌐 <code>{ip}</code> — {info.get('raison','')[:40]} (agent {info.get('agent','?')})")

    if not lines:
        telegram_send("ℹ️ Aucune IP malveillante enregistrée actuellement.")
        return

    telegram_send("🦠 <b>IPS MALVEILLANTES / LOGS</b>\n━━━━━━━━━━━━━━━━━━━━━━━━\n" + "\n".join(lines))


# ╔══════════════════════════════════════════════════════════╗
# ║      INFRASTRUCTURES CRITIQUES : ATTENTE & SECTEURS     ║
# ╚══════════════════════════════════════════════════════════╝

def cmd_pending():
    """Liste les décisions en attente de validation humaine."""
    pend = get_pending_decisions()
    if not pend:
        telegram_send("✅ Aucune décision en attente de validation.")
        return
    for d in pend[-10:]:
        emoji = sector_emoji(d.get("secteur", "inconnu"))
        buttons = inline_keyboard([
            [("✅ Bloquer l'attaquant", f"approve_{d['id']}"),
             ("❌ Ignorer", f"reject_{d['id']}")],
        ])
        telegram_send(
            f"⏳ <b>DÉCISION EN ATTENTE</b> {emoji} {sector_label(d.get('secteur',''))}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 Équipement : <b>{d.get('asset_nom') or d.get('agent') or d.get('dst_ip') or 'N/A'}</b> "
            f"({d.get('criticite','?').upper()})\n"
            f"🌐 Source : <code>{d.get('ip','N/A')}</code>\n"
            f"📌 {d.get('reason','')[:150]}\n"
            f"🕐 {d.get('created_at','')[:19].replace('T',' ')}",
            buttons=buttons
        )


def cmd_pdf():
    """Génère le rapport d'activité SOC en PDF et l'envoie sur Telegram."""
    telegram_send("📄 Génération du rapport PDF en cours...")
    try:
        from soc_report import generate_report_pdf
        path = generate_report_pdf()
    except Exception as e:
        log.error(f"cmd_pdf: {e}")
        telegram_send(f"⚠️ Échec de génération du rapport PDF : {str(e)[:200]}")
        return
    ok = telegram_send_document(
        path,
        caption="🛡️ <b>Rapport d'activité SOC</b>\nIP bloquées, secteurs, menaces et événements récents."
    )
    if not ok:
        telegram_send("⚠️ Rapport généré mais échec de l'envoi (voir logs).")


def cmd_sectors():
    """Tableau de bord par secteur d'infrastructure critique."""
    stats = get_sector_stats()
    pend = get_pending_decisions()
    pend_by_sector = {}
    for d in pend:
        pend_by_sector[d.get("secteur", "inconnu")] = pend_by_sector.get(d.get("secteur", "inconnu"), 0) + 1

    # Secteurs connus depuis l'inventaire + ceux vus dans les stats
    secteurs = sorted(set(list(stats.keys()) + [a.secteur for a in all_assets()]))
    if not secteurs:
        telegram_send("ℹ️ Aucun secteur configuré (voir assets.yml).")
        return

    lines = ["🏢 <b>SOC MULTI-SECTEURS</b>", "━━━━━━━━━━━━━━━━━━━━━━━━"]
    for s in secteurs:
        st = stats.get(s, {})
        lines.append(
            f"{sector_emoji(s)} <b>{sector_label(s)}</b>\n"
            f"   🔔 Alertes : {st.get('alerts',0)} | "
            f"⛔ Bloqués : {st.get('blocked',0)}\n"
            f"   ⏳ En attente : {pend_by_sector.get(s,0)} | "
            f"✅ Validations : {st.get('validations',0)}"
        )
    # Inventaire résumé
    assets_list = all_assets()
    if assets_list:
        crit = sum(1 for a in assets_list if a.criticite is Criticality.CRITIQUE)
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"📋 Parc : {len(assets_list)} équipements ({crit} critiques)")
    telegram_send("\n".join(lines))


def _apply_decision(dec_id: str, approve: bool):
    """Traite la validation humaine d'une décision en attente."""
    d = get_pending_decision(dec_id)
    if not d:
        telegram_send("⚠️ Décision introuvable (expirée ?).")
        return
    if d.get("status") != "pending":
        telegram_send(f"ℹ️ Décision déjà traitée ({d.get('status')}).")
        return

    ip = d.get("ip", "")
    secteur = d.get("secteur", "inconnu")
    cible = d.get("asset_nom") or d.get("agent") or d.get("dst_ip") or "N/A"

    if not approve:
        resolve_pending_decision(dec_id, "rejected", by="admin")
        add_log("FAUX_POSITIF", f"{d.get('category','')} sur {cible} ignoré par admin", ip, d.get("category",""))
        telegram_send(
            f"❌ <b>IGNORÉ (faux positif)</b>\n"
            f"🎯 {cible} | 🌐 <code>{ip}</code>\n"
            f"📝 Aucune action — journalisé."
        )
        return

    # Validation → on bloque l'attaquant (local + Wazuh AR sur les agents)
    if not is_valid_ip(ip):
        resolve_pending_decision(dec_id, "approved", by="admin")
        telegram_send(f"⚠️ IP source invalide (<code>{ip}</code>) — décision close sans blocage.")
        return

    ok = block_ip(ip, f"Validé par admin — {d.get('reason','')}", source="admin-validation",
                  category=d.get("category", ""))
    resolve_pending_decision(dec_id, "approved", by="admin")
    bump_sector_stat(secteur, "validations")
    if ok:
        bump_sector_stat(secteur, "blocked")

    msg = (
        f"✅ <b>BLOCAGE VALIDÉ</b> {sector_emoji(secteur)} {sector_label(secteur)}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 Équipement : <b>{cible}</b>\n"
        f"🌐 Attaquant : <code>{ip}</code>\n"
    )
    msg += f"   ✔ Blocage local ({Config.FIREWALL_BACKEND} + fail2ban)\n" if ok \
           else "   ⚠️ Déjà bloquée ou échec local (voir logs)\n"
    if Config.WAZUH_AR_ON_MANUAL_BLOCK:
        if wazuh.run_active_response(ip):
            msg += "   ✔ firewall-drop Wazuh déclenché sur les agents actifs\n"
        else:
            msg += "   ⚠️ firewall-drop Wazuh non déclenché (voir logs)\n"
    add_log("VALIDATION_APPROUVEE", f"{d.get('category','')} sur {cible} — blocage validé", ip, d.get("category",""))
    telegram_send(msg)


# ╔══════════════════════════════════════════════════════════╗
# ║                     DISPATCH                             ║
# ╚══════════════════════════════════════════════════════════╝

def handle_command(text: str, chat_id):
    if not is_admin(chat_id):
        return
    
    text = text.strip()
    parts = text.split()
    cmd = parts[0].lower() if parts else ""

    simple = {
        "/start": main_menu,
        "/menu": main_menu,
        "/status": cmd_status,
        "/logs": cmd_logs,
        "/blocked": cmd_blocked,
        "/stats": cmd_stats,
        "/cases": cmd_cases,
        "/report": cmd_report,
        "/check": cmd_check,
        "/alerts": cmd_alerts,
        "/scan": cmd_scan_attempts,
        "/malicious": cmd_malicious_ips,
        "/agents": cmd_agents,
        "/attente": cmd_pending,
        "/secteurs": cmd_sectors,
        "/pdf": cmd_pdf,
        "⏳ Décisions en attente": cmd_pending,
        "🏢 Secteurs": cmd_sectors,
        "📄 Rapport PDF": cmd_pdf,
        # Labels du clavier permanent (texte exact envoyé par Telegram au clic)
        "⚠️ 10 Dernières Alertes": cmd_alerts,
        "🔍 IPs Ping & NMAP": cmd_scan_attempts,
        "🛑 IPs Malveillantes / Logs": cmd_malicious_ips,
        "🚫 IPs Bloquées": cmd_blocked,
        "🔓 Débloquer une IP": cmd_blocked,  # affiche la liste avec boutons de déblocage
        "🔄 Actualiser": cmd_status,
        "📋 État du système": cmd_status,
        "📜 Dernières actions": cmd_logs,
        "📊 Statistiques": cmd_stats,
        "📁 Cases TheHive": cmd_cases,
        "🧠 Rapport IA": cmd_report,
        "✅ Vérifier expirations": cmd_check,
        "🖥️ Agents": cmd_agents,
        "🔍 Lancer Cortex": lambda: telegram_send("🔍 Envoyez: /analyze IP"),
        "🗂️ Case manuel": lambda: telegram_send("📁 Envoyez: /createcase IP"),
        "⛔ Bloquer IP": lambda: telegram_send("⛔ Envoyez: /block IP MINUTES"),
        "🚫 Bannir permanent": lambda: telegram_send("🚫 Envoyez: /ban IP"),
        "✅ Whitelister": lambda: telegram_send("✅ Envoyez: /whitelist IP"),
        "🔇 Couper notifs": lambda: telegram_send("🔇 Envoyez: /silence MINUTES"),
    }

    if text in simple:
        simple[text]()
        return

    if cmd in simple:
        simple[cmd]()
    elif cmd == "/block" and len(parts) >= 3:
        try: cmd_block(parts[1], int(parts[2]))
        except ValueError: telegram_send("❌ Usage: /block IP MINUTES")
    elif cmd == "/unblock" and len(parts) >= 2:
        cmd_unblock(parts[1])
    elif cmd == "/ban" and len(parts) >= 2:
        cmd_ban(parts[1])
    elif cmd == "/whitelist" and len(parts) >= 2:
        cmd_whitelist(parts[1])
    elif cmd == "/analyze" and len(parts) >= 2:
        cmd_analyze(parts[1])
    elif cmd == "/url" and len(parts) >= 2:
        cmd_url(parts[1])
    elif cmd == "/domain" and len(parts) >= 2:
        cmd_domain(parts[1])
    elif cmd == "/hash" and len(parts) >= 2:
        cmd_hash(parts[1])
    elif cmd == "/createcase" and len(parts) >= 2:
        cmd_createcase(parts[1])
    elif cmd == "/silence" and len(parts) >= 2:
        try: cmd_silence(int(parts[1]))
        except ValueError: telegram_send("❌ Usage: /silence MINUTES")
    else:
        telegram_send("❓ Commande inconnue. /start pour le menu.")


def handle_callback(data: str, chat_id, cb_id):
    if not is_admin(chat_id):
        answer_callback(cb_id, "⛔ Non autorisé")
        return
    answer_callback(cb_id)

    actions = {
        "cmd_status": cmd_status,
        "cmd_logs": cmd_logs,
        "cmd_blocked": cmd_blocked,
        "cmd_stats": cmd_stats,
        "cmd_cases": cmd_cases,
        "cmd_report": cmd_report,
        "cmd_check": cmd_check,
        "cmd_alerts": cmd_alerts,
        "cmd_scan_attempts": cmd_scan_attempts,
        "cmd_malicious_ips": cmd_malicious_ips,
        "cmd_agents": cmd_agents,
        "cmd_pending": cmd_pending,
        "cmd_sectors": cmd_sectors,
        "cmd_pdf": cmd_pdf,
        "cmd_silence30": lambda: cmd_silence(30),
        "cmd_analyze_prompt": lambda: telegram_send("🔍 Envoyez: /analyze IP"),
        "cmd_case_prompt": lambda: telegram_send("📁 Envoyez: /createcase IP"),
    }

    if data in actions:
        actions[data]()
    elif data.startswith("approve_"):
        _apply_decision(data[8:], approve=True)
    elif data.startswith("reject_"):
        _apply_decision(data[7:], approve=False)
    elif data == "unblock_all":
        state = load_state()
        for ip in list(state["blocked_ips"].keys()):
            unblock_ip(ip, source="admin", notify=False)
        telegram_send("✅ Toutes les IPs débloquées")
    elif data.startswith("unblock_"):
        cmd_unblock(data[8:])
    elif data.startswith("prolong_"):
        ip = data[8:]
        if prolong_block(ip):
            telegram_send(f"⏱️ <code>{ip}</code> prolongé")
        else:
            telegram_send(f"⚠️ Impossible de prolonger <code>{ip}</code>")
    elif data.startswith("ban_"):
        cmd_ban(data[4:])
    elif data.startswith("block_"):
        # Format: block_<ip>_<minutes> (bouton "🚫 Bloquer {ip}" du menu ping/nmap)
        payload = data[6:]
        try:
            ip_part, min_part = payload.rsplit("_", 1)
            cmd_block(ip_part, int(min_part))
        except (ValueError, IndexError):
            telegram_send(f"⚠️ Blocage impossible: <code>{payload}</code>")


# ╔══════════════════════════════════════════════════════════╗
# ║                  BOUCLE PRINCIPALE                       ║
# ╚══════════════════════════════════════════════════════════╝

def main():
    if not Config.TELEGRAM_TOKEN or not Config.TELEGRAM_CHAT:
        print("❌ TELEGRAM_TOKEN ou TELEGRAM_CHAT manquant")
        sys.exit(1)

    log.info("═════════════════════════════════════════════")
    log.info("  telegram_bot.py — DÉMARRÉ — By 12ak_H4ck")
    log.info("═════════════════════════════════════════════")

    # Purge le backlog getUpdates : on repart du DERNIER update en file
    # pour ne PAS rejouer d'anciennes commandes après un restart.
    last_id = 0
    try:
        r = requests.get(f"{API}/getUpdates", params={"offset": -1, "timeout": 0}, timeout=10)
        results = r.json().get("result", [])
        if results:
            last_id = results[-1]["update_id"]
            log.info(f"Backlog purgé — reprise après update_id={last_id}")
    except Exception as e:
        log.warning(f"Purge backlog impossible (démarrage normal): {e}")

    main_menu()

    while True:
        try:
            r = requests.get(
                f"{API}/getUpdates",
                params={"offset": last_id + 1, "timeout": 25},
                timeout=30
            )
            if r.status_code != 200:
                time.sleep(5)
                continue

            for update in r.json().get("result", []):
                last_id = update["update_id"]
                
                if "message" in update and "text" in update["message"]:
                    handle_command(update["message"]["text"], update["message"]["chat"]["id"])
                elif "message" in update and "document" in update["message"]:
                    handle_document(update["message"])
                elif "callback_query" in update:
                    cq = update["callback_query"]
                    handle_callback(cq["data"], cq["message"]["chat"]["id"], cq["id"])

        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            log.error("Telegram connexion perdue")
            time.sleep(10)
        except Exception as e:
            log.error(f"Bot erreur: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()