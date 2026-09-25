#!/usr/bin/env python3
"""
surveillance_soc.py — Script 1 : Surveillance SOC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Surveille Wazuh en temps réel :
  - IP privée  → blocage firewall + Fail2ban + Telegram + Mail
  - IP publique → Case TheHive + file pour Script 2
  - Malware    → Case TheHive + hash → Cortex
  - FIM        → Notification Telegram (création / suppression / modification)
  - SSH        → Notification Telegram
  - Suricata EVE JSON → parsing direct (nmap, DDoS, scan, malware...)
"""

import os
import sys
import time
import json
import logging
from datetime import datetime

from soc_config import (
    Config, WazuhAlert, AlertCategory, Severity,
    classify_alert, get_severity_for_category, DETECTION_RULES,
    ACTIONABLE_CATEGORIES, NATIVE_AR_CATEGORIES
)
from soc_utils import (
    init_soc, is_valid_ip, is_private_ip, is_whitelisted,
    is_alert_processed, mark_alert_processed, get_processed_set, commit_processed_ids,
    block_ip, add_log, telegram_send, inline_keyboard,
    get_remaining_time, fail2ban_block, load_state, save_state,
    should_alert, clear_throttle, record_native_block, check_expired_blocks,
    add_pending_decision, bump_sector_stat, record_offense, reset_offense,
    get_pending_decisions, resolve_pending_decision
)
from soc_clients import wazuh, thehive, mail
import soc_assets as assets
from soc_assets import Criticality, sector_emoji, sector_label

log = logging.getLogger("script1")

# Position de lecture du fichier EVE JSON (tail -f style)
_eve_position: int = 0


# ╔══════════════════════════════════════════════════════════╗
# ║              SURICATA EVE JSON READER                    ║
# ╚══════════════════════════════════════════════════════════╝

def read_suricata_eve() -> list:
    """
    Lit les nouvelles alertes Suricata depuis eve.json.
    Utilise un offset pour ne lire que les nouvelles lignes (tail -f style).
    Retourne une liste de dicts Suricata de type 'alert'.
    """
    global _eve_position
    eve_path = Config.SURICATA_EVE

    if not Config.SURICATA_ENABLE or not os.path.exists(eve_path):
        return []

    alerts = []
    try:
        with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(_eve_position)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerts.append(event)
                except json.JSONDecodeError:
                    pass
            _eve_position = f.tell()
    except Exception as e:
        log.error(f"Suricata EVE read: {e}")

    return alerts


def process_suricata_alert(event: dict):
    """
    Traite une alerte Suricata brute (EVE JSON).
    Convertit en WazuhAlert-like puis route comme les alertes Wazuh.
    """
    alert_info = event.get("alert", {})
    src_ip     = event.get("src_ip", "")
    dst_ip     = event.get("dest_ip", "")
    signature  = alert_info.get("signature", "Suricata alert")
    category   = alert_info.get("category", "")
    severity   = alert_info.get("severity", 3)
    proto      = event.get("proto", "")
    ts         = event.get("timestamp", datetime.now().isoformat())

    # Convertir sévérité Suricata (1=high, 3=low) en niveau Wazuh (5-15)
    wazuh_level_map = {1: 13, 2: 9, 3: 6}
    rule_level = wazuh_level_map.get(severity, 6)

    if not is_valid_ip(src_ip):
        return

    # Construire un WazuhAlert synthétique
    alert = WazuhAlert(
        id=f"suricata_{event.get('flow_id', ts)}",
        timestamp=ts,
        rule_id=alert_info.get("gid", 0),
        rule_description=signature,
        rule_level=rule_level,
        rule_groups=["suricata", "ids"],
        src_ip=src_ip,
        dst_ip=dst_ip,
        agent_name="Suricata",
        agent_id="suricata",
        data={
            "srcip": src_ip,
            "dstip": dst_ip,
            "proto": proto,
            "alert": alert_info
        }
    )

    # Dédoublonnage
    if is_alert_processed(alert.id):
        return
    mark_alert_processed(alert.id)

    log.info(f"Suricata alert: {signature} | src={src_ip} | cat={category}")
    process_network_alert(alert)


# ╔══════════════════════════════════════════════════════════╗
# ║              TRAITEMENT DES ALERTES                      ║
# ╚══════════════════════════════════════════════════════════╝

SOC_SERVICE_NAMES = ["soc-script1", "soc-script2", "soc-telegram"]


def process_self_monitoring(alert: WazuhAlert) -> bool:
    """
    Détecte si l'alerte concerne un crash de l'un des propres services
    du SOC (rule.id 40704 = "Systemd: Service exited due to a failure").
    Alerte TOUJOURS, indépendamment du filtre ACTIONABLE_CATEGORIES —
    si le SOC lui-même tombe en panne, c'est le silence radio total
    sinon (comme lors de la panne Filebeat/Indexer non détectée).
    Retourne True si géré (l'appelant doit s'arrêter là).
    """
    full_log = alert.data.get("_full_log", "") or ""
    text = f"{alert.rule_description} {full_log}".lower()

    is_systemd_failure = (
        alert.rule_id == 40704 or "systemd" in [g.lower() for g in alert.rule_groups]
    )
    if not is_systemd_failure:
        return False

    matched_service = next((s for s in SOC_SERVICE_NAMES if s in text), None)
    if not matched_service:
        return False

    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    telegram_send(
        f"🆘 <b>[CRITIQUE] LE SOC S'EST ARRÊTÉ</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚙️ Service : <code>{matched_service}</code>\n"
        f"💻 Machine : {alert.agent_name}\n"
        f"📌 {alert.rule_description}\n"
        f"🕐 {ts}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚠️ La surveillance peut être interrompue.\n"
        f"👉 Vérifier : <code>systemctl status {matched_service}</code>",
        force=True
    )
    add_log("SELF_MONITORING", f"{matched_service} a planté sur {alert.agent_name}", "", "self")
    return True


def process_network_alert(alert: WazuhAlert):
    """Traite une alerte réseau (scan, brute force, DDoS, etc.)."""
    # ── AUTO-SURVEILLANCE : si c'est le SOC lui-même qui plante,
    # on doit TOUJOURS être notifié, peu importe la catégorie/filtre.
    if process_self_monitoring(alert):
        return

    # Classer l'alerte d'abord (ne dépend pas de l'IP)
    alert.category = classify_alert(alert)
    alert.severity = get_severity_for_category(alert.category, alert.rule_level)

    # ── SUPPRESSION ACTIVE DE MENACE (pas d'IP nécessaire) ─
    if alert.category == AlertCategory.THREAT_REMOVED:
        process_threat_removed(alert)
        return

    # ── MALWARE (pas d'IP nécessaire — événement fichier local) ─
    hash_value = alert.data.get("sha256", alert.data.get("hash", ""))
    if alert.category == AlertCategory.MALWARE:
        process_malware(alert, hash_value)
        return

    if not alert.has_valid_source_ip:
        return
    if is_whitelisted(alert.src_ip):
        return

    # ── FILTRE : on n'agit QUE sur les catégories pertinentes ──
    # (évite le bruit générique : PAM login/sudo, événements OTHER, etc.)
    if alert.category not in ACTIONABLE_CATEGORIES:
        return

    # ══════════════════════════════════════════════════════════
    #  RÉPONSE GRADUÉE SELON LA CRITICITÉ (infrastructures critiques)
    #  On identifie l'équipement concerné (source OU cible) et sa
    #  criticité. Sur un équipement CRITIQUE, on NE bloque JAMAIS
    #  automatiquement (couper un service vital pourrait être pire que
    #  l'attaque) : on demande une validation humaine sur Telegram.
    # ══════════════════════════════════════════════════════════
    target_asset, secteur, crit = _assess_targets(alert)
    alert.sector = secteur
    bump_sector_stat(secteur, "alerts")

    # Équipement critique (ou attaque industrielle ICS) → l'humain décide
    if crit is Criticality.CRITIQUE or alert.category == AlertCategory.ICS_ATTACK:
        request_human_validation(alert, target_asset, secteur, crit)
        return

    # Équipement sensible → blocage automatique mais de COURTE durée
    # (isolable temporairement sans couper durablement le service).
    if crit is Criticality.SENSIBLE:
        alert.block_duration = min(Config.BLOCK_DURATION, 900)  # 15 min max

    # ── IP PRIVÉE → BLOCAGE IMMÉDIAT ──────────────────────
    if alert.is_private_source:
        process_private_ip(alert)
        return

    # ── IP PUBLIQUE → CASE THEHIVE ────────────────────────
    process_public_ip(alert)


def _assess_targets(alert: WazuhAlert):
    """
    Détermine l'équipement concerné par l'alerte et le niveau de
    criticité à appliquer. On regarde à la fois la CIBLE (dst_ip /
    agent) et la SOURCE (src_ip) : si l'une des deux est un équipement
    critique connu, c'est ce niveau qui prime — bloquer l'IP d'un
    équipement critique (faux positif) pourrait couper un service vital.

    Retourne (asset_à_afficher, secteur, criticité_max).
    """
    dst_asset = assets.lookup(dst_ip=alert.dst_ip, agent_name=alert.agent_name)
    src_asset = assets.lookup(dst_ip=alert.src_ip)

    # Secteur d'affichage : on privilégie un secteur connu (cible puis source)
    if dst_asset.secteur != "inconnu":
        display_asset, secteur = dst_asset, dst_asset.secteur
    elif src_asset.secteur != "inconnu":
        display_asset, secteur = src_asset, src_asset.secteur
    else:
        display_asset, secteur = dst_asset, "inconnu"

    order = {Criticality.STANDARD: 1, Criticality.SENSIBLE: 2, Criticality.CRITIQUE: 3}
    crit = max(dst_asset.criticite, src_asset.criticite, key=lambda c: order[c])
    return display_asset, secteur, crit


def request_human_validation(alert: WazuhAlert, asset, secteur: str, crit: Criticality):
    """
    Équipement critique : on NE bloque pas automatiquement, on demande une
    validation humaine — MAIS sans saturer Telegram :

      • 1ère attaque de l'IP  → 1 message avec boutons ✅/❌ (« tentative n°1 »)
      • attaques suivantes     → silencieuses (le compteur monte en fond)
      • seuil de récidive atteint (REPEAT_THRESHOLD) → blocage AUTOMATIQUE
        + 1 message final, SAUF si la source est elle-même un équipement
        critique/sensible connu (là on ne bloque jamais tout seul).
    """
    ip = alert.src_ip
    category_name = DETECTION_RULES.get(alert.category, {}).get("description", alert.category.value)

    # Compteur de récidive (fenêtre glissante REPEAT_WINDOW)
    count = record_offense(ip, Config.REPEAT_WINDOW)

    # Garde-fou : la SOURCE est-elle un équipement protégé (faux positif
    # possible = service vital) ? Si oui, jamais de blocage automatique.
    src_asset = assets.lookup(dst_ip=ip)
    src_protected = src_asset.criticite in (Criticality.CRITIQUE, Criticality.SENSIBLE)

    # ── RÉCIDIVE : seuil atteint → blocage automatique ────────
    if count >= Config.REPEAT_THRESHOLD and not src_protected:
        _auto_block_recidive(alert, asset, secteur, crit, count, category_name)
        return

    # ── 1ère attaque → on demande la validation (une seule fois) ──
    if count == 1:
        _send_validation_request(alert, asset, secteur, crit, count, category_name)
        return

    # ── Attaques intermédiaires → SILENCE (compteur en arrière-plan) ──
    # (source protégée : on relance quand même une fois au seuil, pour
    #  rappeler qu'une décision humaine reste nécessaire)
    if src_protected and count == Config.REPEAT_THRESHOLD:
        _send_validation_request(alert, asset, secteur, crit, count, category_name,
                                 escalation=True)
        return

    add_log("RECIDIVE_SILENCE",
            f"{category_name} depuis {ip} — tentative n°{count} (silencieux)",
            ip, alert.category.value)


def _send_validation_request(alert, asset, secteur, crit, count, category_name,
                             escalation: bool = False):
    """Crée la décision en attente et envoie LE message Telegram avec boutons."""
    ip = alert.src_ip
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    emoji = sector_emoji(secteur)
    slabel = sector_label(secteur)
    cible = asset.nom or alert.agent_name or alert.dst_ip or "N/A"

    dec_id = add_pending_decision({
        "ip": ip, "dst_ip": alert.dst_ip, "agent": alert.agent_name,
        "asset_nom": asset.nom, "secteur": secteur, "criticite": crit.value,
        "category": alert.category.value,
        "reason": f"{category_name} — {alert.rule_description}",
        "rule_level": alert.rule_level,
    })
    bump_sector_stat(secteur, "pending")

    buttons = inline_keyboard([
        [("✅ Bloquer l'attaquant", f"approve_{dec_id}"),
         ("❌ Ignorer (faux positif)", f"reject_{dec_id}")],
    ])

    is_ics = alert.category == AlertCategory.ICS_ATTACK
    if escalation:
        entete = f"🔁 <b>[RÉCIDIVE — {crit.label()}]</b>"
        note = (f"⚠️ <b>{count}e tentative</b> — source protégée, blocage auto impossible.\n"
                f"   Décision humaine <b>toujours</b> requise :")
    else:
        entete = "🏭 <b>[ALERTE ICS/SCADA]</b>" if is_ics else f"🚨 <b>[{crit.label()}]</b>"
        note = (f"⛔ <b>Blocage automatique DÉSACTIVÉ</b> sur cet équipement critique\n"
                f"   (préserver la continuité du service vital).\n"
                f"👉 <b>Décision requise</b> (tentative n°{count}) :")

    telegram_send(
        f"{entete} {emoji} {slabel}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 Équipement : <b>{cible}</b> ({crit.emoji()} {crit.label()})\n"
        f"🌐 Source : <code>{ip or 'N/A'}</code>\n"
        f"🖥️ Cible : <code>{alert.dst_ip or alert.agent_name or 'N/A'}</code>\n"
        f"📌 {category_name}\n"
        f"📝 Règle : {alert.rule_description}\n"
        f"⚠️ Niveau : {alert.rule_level}/15\n"
        f"🕐 {ts}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{note}",
        buttons=buttons,
        force=True
    )
    add_log("VALIDATION_REQUISE",
            f"{category_name} sur {cible} — attente décision admin (#{dec_id})",
            ip, alert.category.value)


def _auto_block_recidive(alert, asset, secteur, crit, count, category_name):
    """Récidive au-delà du seuil : blocage automatique + 1 notification."""
    ip = alert.src_ip
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    cible = asset.nom or alert.agent_name or alert.dst_ip or "N/A"

    # Résoudre la décision en attente éventuelle (auto-approuvée par récidive)
    for d in get_pending_decisions():
        if d.get("ip") == ip and d.get("category") == alert.category.value:
            resolve_pending_decision(d["id"], "approved", by="auto-récidive")
            break

    blocked = block_ip(ip, f"Récidive x{count} — {category_name}",
                       source="auto-recidive", category=alert.category.value)
    if blocked:
        bump_sector_stat(secteur, "blocked")
    reset_offense(ip)  # le compteur repart à zéro une fois bloqué

    msg = (
        f"⛔ <b>BLOCAGE AUTOMATIQUE (RÉCIDIVE)</b> {sector_emoji(secteur)} {sector_label(secteur)}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 Équipement : <b>{cible}</b> ({crit.emoji()} {crit.label()})\n"
        f"🌐 Attaquant : <code>{ip}</code>\n"
        f"📌 {category_name}\n"
        f"🔁 <b>{count} tentatives</b> — seuil de récidive atteint\n"
        f"🕐 {ts}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
    )
    msg += "   ✔ Blocage local effectué\n" if blocked else "   ⚠️ Déjà bloquée / échec local\n"
    if Config.WAZUH_AR_ON_MANUAL_BLOCK and wazuh.run_active_response(ip):
        msg += "   ✔ firewall-drop Wazuh déclenché sur les agents actifs\n"

    buttons = inline_keyboard([[("🔓 Débloquer", f"unblock_{ip}"),
                                ("🚫 Bannir", f"ban_{ip}")]])
    telegram_send(msg, buttons=buttons, force=True)
    add_log("BLOCAGE_RECIDIVE",
            f"{ip} bloqué après {count} tentatives — {category_name}",
            ip, alert.category.value)


def process_private_ip(alert: WazuhAlert):
    """Traite une alerte avec IP source privée → blocage."""
    ip = alert.src_ip
    category_name = DETECTION_RULES.get(alert.category, {}).get("description", alert.category.value)
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Ces catégories sont maintenant bloquées NATIVEMENT par Wazuh
    # active-response, directement sur la machine réellement attaquée
    # (voir NATIVE_AR_CATEGORIES). Le blocage local ici serait
    # redondant et trompeur (il protégerait la machine du SCRIPT,
    # pas la machine visée par l'attaque) — on notifie seulement,
    # sans dupliquer l'action.
    if alert.category in NATIVE_AR_CATEGORIES:
        throttle_key = f"{alert.category.value}:{ip}"
        if not should_alert(throttle_key, window_seconds=3600):
            return
        add_log(
            "DETECTE_NATIF",
            f"{category_name} — géré par Wazuh active-response sur {alert.agent_name}",
            ip, alert.category.value
        )
        record_native_block(
            ip=ip, reason=f"{category_name} — {alert.rule_description}",
            category=alert.category.value, agent=alert.agent_name,
            timeout_seconds=Config.BLOCK_DURATION
        )
        telegram_send(
            f"🔴 <b>[{alert.severity.name}] {category_name}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🌐 Source : <code>{ip}</code>\n"
            f"🎯 Cible : {alert.agent_name}\n"
            f"📌 Règle : {alert.rule_description}\n"
            f"⚠️ Niveau : {alert.rule_level}/15\n"
            f"🕐 {ts}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"✅ <b>Décision :</b>\n"
            f"  ✔ Blocage géré nativement par Wazuh (agent {alert.agent_name})\n"
            f"  ℹ️ Notification uniquement — pas de blocage local redondant"
        )
        return

    # Blocage (durée réduite pour un équipement "sensible", cf. réponse graduée)
    blocked = block_ip(
        ip=ip,
        reason=f"{category_name} — {alert.rule_description}",
        duration=alert.block_duration,
        source="wazuh-script1",
        category=alert.category.value
    )

    if not blocked:
        return

    bump_sector_stat(alert.sector, "blocked")
    add_log(
        "BLOQUE_PRIVE",
        f"{category_name} — {alert.rule_description}",
        ip,
        alert.category.value
    )

    # Anti-spam : ne renvoie pas la même notif (catégorie+IP) avant 1h.
    # Le blocage et le log restent effectués à chaque fois, seule la
    # notification Telegram/Email est limitée pour ne pas saturer.
    throttle_key = f"{alert.category.value}:{ip}"
    if not should_alert(throttle_key, window_seconds=3600):
        return

    # Boutons Telegram
    buttons = inline_keyboard([
        [("🔓 Débloquer", f"unblock_{ip}"),
         ("⏱️ +2h", f"prolong_{ip}")],
        [("🚫 Bannir permanent", f"ban_{ip}")]
    ])

    # Message Telegram
    telegram_send(
        f"{alert.severity.emoji()} <b>[{alert.severity.label()}] {category_name}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 Source : <code>{ip}</code>\n"
        f"🎯 Destination : <code>{alert.dst_ip or 'N/A'}</code>\n"
        f"💻 Agent : {alert.agent_name}\n"
        f"📌 Règle : {alert.rule_description}\n"
        f"⚠️ Niveau : {alert.rule_level}/15\n"
        f"⏱️ Durée : {get_remaining_time(ip)}\n"
        f"🕐 Heure : {ts}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ <b>Décision :</b>\n"
        f"  ✔ IP privée détectée\n"
        f"  ✔ Blocage effectué ({Config.FIREWALL_BACKEND})\n"
        f"  ✔ Notification Telegram\n"
        f"  ✔ Journal mis à jour\n",
        buttons=buttons,
        force=True
    )

    # Email
    mail.send_block_alert(
        ip=ip,
        reason=alert.rule_description,
        category=category_name,
        duration=get_remaining_time(ip),
        agent=alert.agent_name
    )

    # Stats
    state = __import__('soc_utils', fromlist=['load_state', 'save_state']).load_state()
    if alert.category == AlertCategory.BRUTE_FORCE:
        state["stats"]["total_bruteforce"] = state["stats"].get("total_bruteforce", 0) + 1
    __import__('soc_utils', fromlist=['save_state']).save_state(state)


def process_public_ip(alert: WazuhAlert):
    """Traite une alerte avec IP publique → Case TheHive."""
    ip = alert.src_ip
    category_name = DETECTION_RULES.get(alert.category, {}).get("description", alert.category.value)
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Anti-spam : pas de nouveau Case pour la même (catégorie, IP) avant 1h
    throttle_key = f"{alert.category.value}:{ip}"
    if not should_alert(throttle_key, window_seconds=3600):
        add_log("SCAN_IGNORE", f"{category_name} répété (throttle 1h)", ip, alert.category.value)
        return

    # Créer le Case TheHive
    case = thehive.create_ip_case(
        ip=ip,
        title=f"{category_name} détecté",
        description=f"**Règle:** {alert.rule_description}\n**Niveau:** {alert.rule_level}/15\n**Agent:** {alert.agent_name}",
        severity=alert.severity,
        source="Wazuh"
    )

    if not case:
        clear_throttle(throttle_key)  # échec -> on annule le throttle pour réessayer au prochain cycle
        telegram_send(
            f"⚠️ <b>ÉCHEC CRÉATION CASE</b>\n"
            f"🌐 IP: <code>{ip}</code>\n"
            f"📌 {category_name}\n"
            f"📋 Voir <code>journalctl -u soc-script1</code> pour le détail de l'erreur TheHive",
            force=True
        )
        return

    case_id = case.get("_id", "")
    case_num = case.get("number", "?")

    # Déterminer le vrai data_type (IP valide ou FQDN)
    case_data_type = "ip" if is_valid_ip(ip) else "fqdn"

    # Ajouter à la file pour Script 2
    su = __import__('soc_utils', fromlist=['load_state', 'save_state'])
    state = su.load_state()
    state["cases"].append({
        "case_id": case_id,
        "number": case_num,
        "ip": ip,
        "title": f"{category_name} détecté",
        "description": alert.rule_description,
        "severity": alert.severity.value,
        "data_type": case_data_type,
        "extra_data": {
            "agent": alert.agent_name,
            "rule_level": alert.rule_level,
            "category": alert.category.value
        },
        "created_at": ts,
        "analyzed": False
    })
    state["cases"] = state["cases"][-100:]
    state["stats"]["total_cases_public"] = state["stats"].get("total_cases_public", 0) + 1
    su.save_state(state)

    # Notification Telegram
    telegram_send(
        f"📊 <b>[{alert.severity.label()}] {category_name}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 IP : <code>{ip}</code>\n"
        f"📁 Case : <b>#{case_num}</b>\n"
        f"💻 Agent : {alert.agent_name}\n"
        f"🕐 {ts}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ <b>Décision :</b>\n"
        f"  ✔ Case créé dans TheHive\n"
        f"  ✔ Observable ajouté\n"
        f"  ⏳ Analyse Cortex en attente (Script 2)\n",
        force=True
    )

    add_log("CASE_CREE", f"Case #{case_num} pour {ip} — {category_name}", ip, alert.category.value)


def process_malware(alert: WazuhAlert, hash_value: str):
    """Traite une alerte malware → Case TheHive + hash dans la file (si disponible)."""
    file_path = alert.data.get("file", alert.data.get("path", ""))
    # Fallback : le chemin n'est pas toujours dans un champ structuré
    # (ex: "VirusTotal: Alert - /root/eicar_test.txt - 60 engines detected this file")
    if not file_path:
        import re
        m = re.search(r"Alert\s*-\s*(\S+)\s*-\s*\d+\s*engines", alert.rule_description, re.IGNORECASE)
        if not m:
            m = re.search(r"(/[^\s]+)", alert.rule_description)
        file_path = m.group(1) if m else "Inconnu"

    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Anti-spam : évite le flood si VirusTotal/Wazuh re-scanne le même
    # fichier en boucle (ex: alerte identique toutes les 30s).
    throttle_key = f"malware:{hash_value or file_path}"
    if not should_alert(throttle_key, window_seconds=3600):
        return

    # Infos VirusTotal additionnelles si présentes (ex: "62 engines detected this file")
    vt = alert.data.get("_virustotal", {})
    vt_positives = vt.get("positives", "")
    vt_line = f"🦠 Détections VT : {vt_positives} moteurs\n" if vt_positives else ""

    has_hash = bool(hash_value)

    case = None
    case_num = "?"
    if has_hash:
        case = thehive.create_malware_case(
            file_path=file_path,
            hash_value=hash_value,
            agent=alert.agent_name,
            description=f"**Règle:** {alert.rule_description}\n**Niveau:** {alert.rule_level}/15"
        )
        if case:
            case_id = case.get("_id", "")
            case_num = case.get("number", "?")

            su = __import__('soc_utils', fromlist=['load_state', 'save_state'])
            state = su.load_state()
            state["cases"].append({
                "case_id": case_id,
                "number": case_num,
                "ip": "",
                "title": f"Malware: {file_path}",
                "description": alert.rule_description,
                "severity": Severity.CRITICAL.value,
                "data_type": "hash",
                "extra_data": {
                    "hash": hash_value,
                    "file": file_path,
                    "agent": alert.agent_name,
                    "category": "malware"
                },
                "created_at": ts,
                "analyzed": False
            })
            state["cases"] = state["cases"][-100:]
            state["stats"]["total_malware"] = state["stats"].get("total_malware", 0) + 1
            su.save_state(state)

    # Notification — toujours envoyée, même sans hash exploitable
    hash_line = f"🔑 SHA256 : <code>{hash_value[:32]}...</code>\n" if has_hash else ""
    case_line = f"📁 Case : <b>#{case_num}</b>\n" if case else (
        "⚠️ <i>Pas de hash exploitable — Case non créé automatiquement</i>\n" if not has_hash
        else "⚠️ <i>Échec création Case TheHive</i>\n"
    )
    decision_lines = (
        "  ✔ Case créé\n  ✔ Hash envoyé à Cortex (Script 2)\n" if case else
        "  ⚠️ Vérifier manuellement (hash manquant ou case en échec)\n"
    )

    telegram_send(
        f"🦠 <b>[CRITICAL] MALWARE DÉTECTÉ</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📄 Fichier : <code>{file_path}</code>\n"
        f"💻 Machine : {alert.agent_name}\n"
        f"{vt_line}"
        f"{hash_line}"
        f"{case_line}"
        f"📌 Règle : {alert.rule_description}\n"
        f"🕐 {ts}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ <b>Décision :</b>\n"
        f"{decision_lines}"
        f"  ⚠️ <i>Envisager l'isolation de la machine</i>",
        force=True
    )

    add_log("MALWARE", f"Case #{case_num} — {file_path} — {hash_value[:16] if has_hash else 'pas de hash'}", "", "malware")


def process_threat_removed(alert: WazuhAlert):
    """
    Traite une alerte de suppression active (VirusTotal/Wazuh active-response).
    Lie cette suppression au Case malware déjà créé (par hash ou chemin)
    et envoie une notification COMBINÉE : détection + suppression.
    """
    file_path = alert.data.get("file", alert.data.get("path", ""))
    # Fallback : le chemin n'est souvent PAS dans un champ structuré pour
    # les alertes active-response, mais dans le texte du message lui-même
    # (ex: "...removed threat located at /home/eicar.com").
    if not file_path:
        import re
        m = re.search(r"located at\s+(\S+)", alert.rule_description, re.IGNORECASE)
        if not m:
            m = re.search(r"file[:\s]+(\S+)", alert.rule_description, re.IGNORECASE)
        file_path = m.group(1).rstrip(".,;") if m else "Inconnu"

    hash_value = alert.data.get("sha256", alert.data.get("hash", ""))
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Anti-spam : throttle 1h par (agent + fichier) — sans ça, un cycle
    # de recréation/suppression rapide du même fichier sature Telegram.
    throttle_key = f"threat_removed:{alert.agent_name}:{file_path}"
    if not should_alert(throttle_key, window_seconds=3600):
        add_log("THREAT_REMOVED_IGNORE", f"{file_path} sur {alert.agent_name} — throttle 1h", "", "malware")
        return

    su = __import__('soc_utils', fromlist=['load_state', 'save_state'])
    state = su.load_state()

    # Chercher le case malware correspondant (par hash, sinon par chemin)
    matched_case = None
    for c in reversed(state.get("cases", [])):
        if c.get("data_type") != "hash":
            continue
        extra = c.get("extra_data", {})
        if hash_value and extra.get("hash") == hash_value:
            matched_case = c
            break
        if not hash_value and extra.get("file") == file_path:
            matched_case = c
            break

    case_num = matched_case.get("number", "?") if matched_case else "?"
    case_id = matched_case.get("case_id", "") if matched_case else ""

    # Marquer le case comme "menace neutralisée" pour ne pas le re-traiter inutilement
    if matched_case:
        matched_case["threat_removed"] = True
        matched_case["removed_at"] = ts
        su.save_state(state)

        # Commenter le Case TheHive existant (alerte + suppression liées)
        if case_id:
            thehive.add_comment(
                case_id,
                f"**Menace neutralisée automatiquement — {ts}**\n\n"
                f"Le fichier `{file_path}` a été supprimé par active-response "
                f"(VirusTotal/Wazuh) suite à la détection initiale du Case #{case_num}."
            )

    # ── Notification combinée : DÉTECTION + SUPPRESSION ────
    telegram_send(
        f"🦠🗑️ <b>[CRITICAL] MENACE DÉTECTÉE ET SUPPRIMÉE</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📄 Fichier : <code>{file_path}</code>\n"
        f"💻 Machine : {alert.agent_name}\n"
        + (f"🔑 SHA256 : <code>{hash_value[:32]}...</code>\n" if hash_value else "") +
        (f"📁 Case lié : <b>#{case_num}</b>\n" if matched_case else "⚠️ Aucun case malware existant trouvé (alerte isolée)\n") +
        f"🕐 {ts}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ <b>Statut :</b>\n"
        f"  ✔ Virus détecté\n"
        f"  ✔ Fichier supprimé automatiquement (active-response)\n"
        f"  ✔ Aucune action manuelle requise",
        force=True
    )

    add_log(
        "THREAT_REMOVED",
        f"Menace supprimée: {file_path} ({hash_value[:16] if hash_value else 'N/A'}) "
        f"— Case lié: #{case_num}",
        "", "malware"
    )


def process_ssh_alert(alert: WazuhAlert):
    """Traite une alerte SSH — ne notifie QUE les échecs/tentatives, pas les connexions normales."""
    src_ip = alert.src_ip or "Inconnue"
    user = alert.data.get("dstuser", alert.data.get("user", "Inconnu"))
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    is_success = any(k in alert.rule_description.lower() for k in [
        "accepted", "publickey", "session opened", "login session opened"
    ])

    # Ne pas notifier les connexions SSH réussies normales (bruit) —
    # seulement les tentatives échouées / suspectes.
    if is_success:
        add_log("SSH", f"Connexion SSH réussie {src_ip} → {alert.agent_name}", src_ip)
        return

    # Anti-spam : une seule notif par IP toutes les heures pour éviter
    # le flood en cas de brute force SSH actif (des dizaines de tentatives/min).
    if not should_alert(f"ssh_fail:{src_ip}", window_seconds=3600):
        add_log("SSH", f"Tentative SSH {src_ip} → {alert.agent_name} (throttle)", src_ip)
        return

    telegram_send(
        f"🔐 <b>TENTATIVE SSH ÉCHOUÉE</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 IP source : <code>{src_ip}</code>\n"
        f"👤 User : {user}\n"
        f"💻 Serveur : {alert.agent_name}\n"
        f"⚠️ Niveau : {alert.rule_level}/15\n"
        f"🕐 {ts}"
    )

    add_log("SSH", f"Tentative SSH {src_ip} → {alert.agent_name}", src_ip)


def process_fim_event(event: dict):
    """
    Traite un événement FIM (création, suppression, modification).
    Pour les fichiers créés/modifiés avec un hash exploitable :
    - Notifie Telegram immédiatement (comme avant)
    - Crée AUTOMATIQUEMENT un Case TheHive avec l'observable hash
    - Met en file pour Script 2 qui lance Cortex automatiquement
      (VirusTotal, etc.) et renvoie le résultat par Telegram/Email
    """
    file_path = event.get("file", event.get("path", ""))
    if not file_path:
        return
    
    action = str(event.get("type", event.get("event", ""))).lower()
    agent_raw = event.get("agent", {})
    agent = agent_raw.get("name", "Inconnu") if isinstance(agent_raw, dict) else "Inconnu"
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    
    basename = os.path.basename(file_path)
    dirname = os.path.dirname(file_path)

    # Anti-spam : la NOTIFICATION elle-même (pas juste la création de case)
    # est throttlée 1h par (agent + fichier + action). Sans ça, un fichier
    # qui change en boucle (ex: cycle FIM/active-response) sature Telegram.
    notif_throttle_key = f"fim_notif:{agent}:{file_path}:{action}"
    if not should_alert(notif_throttle_key, window_seconds=3600):
        add_log("FIM_NOTIF_IGNORE", f"{file_path} sur {agent} ({action}) — throttle 1h", "", "fim")
        return

    # Extraire les infos de changement (hash, taille, permissions)
    sha256_before = event.get("sha256_before", "")
    sha256_after  = event.get("sha256_after", event.get("sha256", ""))
    size_after    = event.get("size_after", event.get("size", ""))
    perms         = event.get("perm_after", event.get("perm", ""))

    if any(k in action for k in ["added", "created"]):
        telegram_send(
            f"📥 <b>FICHIER CRÉÉ — FIM</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📄 Fichier : <code>{basename}</code>\n"
            f"📂 Dossier : <code>{dirname}</code>\n"
            f"💻 Agent : {agent}\n"
            f"🔑 SHA256 : <code>{sha256_after[:32] if sha256_after else 'N/A'}...</code>\n"
            f"📏 Taille : {size_after or 'N/A'}\n"
            f"🕐 {ts}"
        )
        add_log("FIM_AJOUT", f"Fichier créé: {file_path} sur {agent}")
        _fim_auto_analyze(file_path, sha256_after, agent, "créé", ts)

    elif any(k in action for k in ["deleted", "removed"]):
        telegram_send(
            f"🗑️ <b>FICHIER SUPPRIMÉ — FIM</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📄 Fichier : <code>{basename}</code>\n"
            f"📂 Dossier : <code>{dirname}</code>\n"
            f"💻 Agent : {agent}\n"
            f"🕐 {ts}"
        )
        add_log("FIM_SUPPR", f"Fichier supprimé: {file_path} sur {agent}")
        # Pas d'analyse possible (fichier supprimé) — pas de queue Cortex

    elif any(k in action for k in ["modified", "changed"]):
        hash_line = ""
        if sha256_before and sha256_after and sha256_before != sha256_after:
            hash_line = (
                f"🔑 Hash avant : <code>{sha256_before[:20]}...</code>\n"
                f"🔑 Hash après : <code>{sha256_after[:20]}...</code>\n"
            )
        telegram_send(
            f"✏️ <b>FICHIER MODIFIÉ — FIM</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📄 Fichier : <code>{basename}</code>\n"
            f"📂 Dossier : <code>{dirname}</code>\n"
            f"💻 Agent : {agent}\n"
            f"{hash_line}"
            f"🔐 Perms : {perms or 'N/A'}\n"
            f"🕐 {ts}"
        )
        add_log("FIM_MODIF", f"Fichier modifié: {file_path} sur {agent}")
        _fim_auto_analyze(file_path, sha256_after, agent, "modifié", ts)


def _fim_auto_analyze(file_path: str, hash_value: str, agent: str, action: str, ts: str):
    """
    Crée automatiquement un Case TheHive + met en file pour Script 2
    (qui lance Cortex + Groq automatiquement) pour un fichier FIM créé/modifié.
    Throttle 1h par (agent + fichier) pour éviter de spammer TheHive si
    un fichier change en boucle (ex: log applicatif réécrit sans arrêt).
    """
    if not hash_value:
        return  # rien à analyser sans hash

    throttle_key = f"fim_analyze:{agent}:{file_path}"
    if not should_alert(throttle_key, window_seconds=3600):
        add_log("FIM_ANALYSE_IGNORE", f"{file_path} sur {agent} (throttle 1h)", "", "fim")
        return

    case = thehive.create_fim_case(file_path, hash_value, agent, action)
    if not case:
        clear_throttle(throttle_key)  # échec -> on annule le throttle pour réessayer au prochain cycle
        log.warning(f"Échec création Case FIM pour {file_path}")
        return

    case_id = case.get("_id", "")
    case_num = case.get("number", "?")

    state = load_state()
    state["cases"].append({
        "case_id": case_id,
        "number": case_num,
        "ip": "",
        "title": f"FIM {action}: {file_path}",
        "description": f"Fichier {action} détecté par FIM sur {agent}",
        "severity": Severity.MEDIUM.value,
        "data_type": "hash",
        "extra_data": {
            "hash": hash_value,
            "file": file_path,
            "agent": agent,
            "category": "fim"
        },
        "created_at": ts,
        "analyzed": False
    })
    state["cases"] = state["cases"][-100:]
    save_state(state)

    telegram_send(
        f"🔬 <b>Analyse automatique lancée</b>\n"
        f"📄 <code>{file_path}</code>\n"
        f"📁 Case TheHive : <b>#{case_num}</b>\n"
        f"⏳ Cortex va analyser le hash — résultat à venir sur ce chat"
    )
    add_log("FIM_CASE", f"Case #{case_num} créé pour {file_path} ({action})", "", "fim")


# ╔══════════════════════════════════════════════════════════╗
# ║                  BOUCLE PRINCIPALE                       ║
# ╚══════════════════════════════════════════════════════════╝

def main():
    if os.geteuid() != 0:
        print("❌ Lance en root: sudo python3 surveillance_soc.py")
        sys.exit(1)

    # Initialisation
    init_soc()

    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    telegram_send(
        f"🛡️ <b>SOC SCRIPT 1 — DÉMARRÉ</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ Wazuh : {Config.WAZUH_URL}\n"
        f"✅ TheHive : {Config.THEHIVE_URL}\n"
        f"✅ Firewall : {Config.FIREWALL_BACKEND}\n"
        f"✅ Intervalle : {Config.WAZUH_POLL_INTERVAL}s\n"
        f"✅ Niveau min : {Config.WAZUH_MIN_LEVEL}/15\n"
        f"🕐 {ts}\n"
        f"🔰 By <b>12ak_H4ck</b>",
        force=True
    )

    if Config.MAIL_ON_START and mail.is_configured():
        mail.send(
            "🛡️ SOC Script 1 — Démarré",
            f"Script 1 démarré à {ts}\nConfig: {Config.summary()}",
            html=False
        )

    log.info("═════════════════════════════════════════════")
    log.info("  SCRIPT 1 — surveillance_soc.py")
    log.info(f"  {Config.summary()}")
    log.info("═════════════════════════════════════════════")

    # ── CURSEUR ANTI-FLOOD ──────────────────────────────────
    # Au démarrage, on ne remonte JAMAIS l'historique — seules les
    # alertes APRÈS ce timestamp seront traitées. Évite le flood
    # Telegram avec des centaines d'alertes déjà anciennes.
    cursor = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ssh_cursor = cursor
    scan_cursor = cursor
    log.info(f"Curseur de démarrage : alertes après {cursor} uniquement")

    errors = 0
    cycle = 0
    while True:
        try:
            # Filet de sécurité : nettoie les blocages expirés dont le
            # timer aurait sauté (restart). Toutes les ~5 min pour limiter l'I/O.
            cycle += 1
            if cycle % 10 == 1:
                check_expired_blocks()

            # ── Alertes Wazuh (uniquement depuis le curseur) ─
            alerts_raw = wazuh.get_alerts(since_ts=cursor)
            # SSH/PAM : requête dédiée à seuil bas (capture aussi les
            # connexions réussies niveau 3, filtrées par le seuil global)
            ssh_raw = wazuh.get_ssh_alerts(since_ts=ssh_cursor)
            # Scans réseau (Suricata-via-Wazuh, niveau 3 générique)
            scan_raw = wazuh.get_scan_alerts(since_ts=scan_cursor)
            # FIM : toujours limité aux 5 dernières minutes
            fim_events = wazuh.get_fim_events(minutes=5)

            # Avancer le curseur au timestamp le plus récent vu ce cycle
            if alerts_raw:
                latest_ts = max((a.get("timestamp", cursor) for a in alerts_raw), default=cursor)
                if latest_ts > cursor:
                    cursor = latest_ts
            if ssh_raw:
                latest_ssh_ts = max((a.get("timestamp", ssh_cursor) for a in ssh_raw), default=ssh_cursor)
                if latest_ssh_ts > ssh_cursor:
                    ssh_cursor = latest_ssh_ts
            if scan_raw:
                latest_scan_ts = max((a.get("timestamp", scan_cursor) for a in scan_raw), default=scan_cursor)
                if latest_scan_ts > scan_cursor:
                    scan_cursor = latest_scan_ts

            # Dédoublonnage optimisé : un seul load_state() pour tout le
            # cycle au lieu d'un aller-retour disque par alerte individuelle.
            processed_set = get_processed_set()
            newly_processed = set()

            for raw in ssh_raw:
                alert = wazuh.parse_alert(raw)
                if not alert:
                    continue
                if alert.id in processed_set or alert.id in newly_processed:
                    continue
                newly_processed.add(alert.id)
                alert.category = AlertCategory.SSH
                alert.severity = get_severity_for_category(alert.category, alert.rule_level)
                process_ssh_alert(alert)

            for raw in scan_raw:
                alert = wazuh.parse_alert(raw)
                if not alert:
                    continue
                if alert.id in processed_set or alert.id in newly_processed:
                    continue
                newly_processed.add(alert.id)
                # Laisser classify_alert() déterminer la vraie catégorie
                # (généralement NETWORK_SCAN, mais peut varier selon le texte)
                process_network_alert(alert)

            for raw in alerts_raw:
                alert = wazuh.parse_alert(raw)
                if not alert:
                    continue
                if alert.id in processed_set or alert.id in newly_processed:
                    continue
                newly_processed.add(alert.id)

                # Classer AVANT de router — sinon la comparaison
                # ci-dessous compare toujours la valeur par défaut (OTHER)
                alert.category = classify_alert(alert)
                alert.severity = get_severity_for_category(alert.category, alert.rule_level)

                if alert.category == AlertCategory.SSH:
                    process_ssh_alert(alert)
                else:
                    process_network_alert(alert)

            # Une seule écriture disque pour tout le cycle, au lieu d'une
            # par alerte traitée (gros gain d'I/O quand le volume monte).
            commit_processed_ids(newly_processed)

            for event in fim_events:
                process_fim_event(event)

            # ── Alertes Suricata EVE JSON ───────────────────
            suricata_alerts = read_suricata_eve()
            for event in suricata_alerts:
                process_suricata_alert(event)

            if suricata_alerts:
                log.info(f"Suricata: {len(suricata_alerts)} alerte(s) traitée(s)")

            log.info(
                f"Cycle OK — Wazuh: {len(alerts_raw)} alertes | SSH: {len(ssh_raw)} | "
                f"Scan: {len(scan_raw)} | FIM: {len(fim_events)} | Suricata: {len(suricata_alerts)}"
            )
            errors = 0

        except Exception as e:
            errors += 1
            log.error(f"Erreur boucle: {e}", exc_info=True)
            if errors >= 5:
                telegram_send(f"⚠️ <b>Script 1: {errors} erreurs consécutives</b>\n{str(e)[:200]}", force=True)
                errors = 0

        time.sleep(Config.WAZUH_POLL_INTERVAL)


if __name__ == "__main__":
    main()