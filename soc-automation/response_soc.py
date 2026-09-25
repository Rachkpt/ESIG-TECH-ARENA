#!/usr/bin/env python3
"""
response_soc.py — Script 2 : Analyse & Réponse Automatique
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Traite les Cases en attente :
  1. Lance les analyzers Cortex adaptés (IP, hash, etc.)
  2. Collecte les résultats
  3. Analyse IA avec Groq
  4. Envoie rapport Telegram + Email
  5. Met à jour le Case TheHive
"""

import time
import logging
from datetime import datetime

from soc_config import Config, Severity, DataType
from soc_utils import (
    load_state, save_state, add_log, telegram_send,
    get_last_logs, firewall_setup, check_expired_blocks
)
from soc_clients import (
    cortex, groq, thehive, mail,
    extract_telegram_version
)

log = logging.getLogger("script2")


# ╔══════════════════════════════════════════════════════════╗
# ║               TRAITEMENT D'UN CASE                       ║
# ╚══════════════════════════════════════════════════════════╝

def process_case(case: dict):
    """Pipeline complet pour un Case en attente."""
    case_id = case["case_id"]
    case_num = case["number"]
    ip = case.get("ip", "")

    # data_type : utiliser celui stocké, sinon détecter automatiquement
    data_type = case.get("data_type")
    if not data_type:
        from soc_utils import is_valid_ip
        data_type = "ip" if is_valid_ip(ip) else "fqdn" if ip else "hash"

    extra = case.get("extra_data", {})
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Déterminer la donnée à analyser
    if data_type == "hash":
        observable_data = extra.get("hash", "")
        observable_label = f"Hash {observable_data[:16]}..."
        file_path = extra.get("file", "Inconnu")
        agent = extra.get("agent", "Inconnu")
    else:
        observable_data = ip
        observable_label = ip
        file_path = ""
        agent = extra.get("agent", "")

    if not observable_data:
        log.error(f"Case {case_num}: pas de donnée à analyser")
        return

    log.info(f"Traitement Case #{case_num} — {observable_label}")

    # Notification de démarrage
    telegram_send(
        f"🔬 <b>ANALYSE EN COURS</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{'🌐 IP' if data_type == 'ip' else '🔑 Hash'} : <code>{observable_label}</code>\n"
        f"📁 Case : <b>#{case_num}</b>\n"
        f"🕐 Début : {ts}\n"
        f"⏳ <i>Lancement des analyzers Cortex...</i>"
    )

    # ── 1. Lancer les analyzers Cortex ─────────────────────
    results = cortex.analyze_observable(observable_data, data_type)
    success_count = sum(1 for r in results if r.status == "Success")
    malicious_count = sum(1 for r in results if r.is_malicious)

    log.info(f"Case #{case_num}: {success_count}/{len(results)} analyzers réussis")

    # Résumé des résultats pour Telegram
    results_summary = []
    for r in results:
        status_emoji = "✅" if r.status == "Success" else ("❌" if r.status == "Failure" else "⏰")
        mal_emoji = "🚨" if r.is_malicious else "✓"
        results_summary.append(f"{status_emoji} {mal_emoji} <b>{r.analyzer_name}</b>: {r.score}/100")

    telegram_send(
        f"⚙️ <b>{len(results)} ANALYZER(S) TERMINÉS</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{'🌐 IP' if data_type == 'ip' else '🔑 Hash'} : <code>{observable_label}</code>\n"
        f"📊 Résultats : {success_count}/{len(results)} réussis\n"
        f"🚨 Malveillants : {malicious_count}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n" +
        "\n".join(results_summary[:10])
    )

    # ── 2. Analyse IA avec Groq ────────────────────────────
    if data_type == "hash":
        ia_analysis = groq.analyze_malware(file_path, observable_data, agent, results)
    else:
        ia_analysis = groq.analyze_ip(observable_data, results, case.get("description", ""))

    # ── 3. Extraire version Telegram ───────────────────────
    tg_version = extract_telegram_version(ia_analysis)

    # ── 4. Notification finale Telegram ────────────────────
    telegram_send(
        f"🧠 <b>ANALYSE IA TERMINÉE</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{'🌐 IP' if data_type == 'ip' else '🔑 Hash'} : <code>{observable_label}</code>\n"
        f"📁 Case : <b>#{case_num}</b>\n"
        f"📊 Analyzers : {success_count}/{len(results)}\n"
        f"🚨 Malveillants : {malicious_count}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{tg_version}",
        force=True
    )

    # ── 5. Rapport Email ───────────────────────────────────
    if data_type == "hash":
        mail.send_malware_alert(file_path, observable_data, agent, ia_analysis)
    else:
        mail.send_case_alert(observable_data, str(case_num), case.get("title", ""), results, ia_analysis)

    # ── 6. Auto-blocage IP publique si malveillante ────────
    if data_type == "ip" and ip and malicious_count > 0:
        from soc_utils import block_ip as _block, is_whitelisted as _wl
        if not _wl(ip):
            blocked = _block(
                ip=ip,
                reason=f"Cortex: {malicious_count}/{len(results)} analyzer(s) malveillant(s)",
                source="response-cortex",
                category=extra.get("category", "public_ip")
            )
            if blocked:
                log.info(f"IP publique {ip} bloquée automatiquement après analyse Cortex")
                telegram_send(
                    f"🚫 <b>IP PUBLIQUE BLOQUÉE POST-ANALYSE</b>\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"🌐 IP : <code>{ip}</code>\n"
                    f"📁 Case : <b>#{case_num}</b>\n"
                    f"🚨 Analyzers malveillants : {malicious_count}/{len(results)}\n"
                    f"⏱️ Durée : {Config.BLOCK_DURATION//3600}h\n"
                    f"🕐 {ts}",
                    force=True
                )

    # ── 7. Mettre à jour TheHive ───────────────────────────
    # Préparer le commentaire
    analyzers_txt = "\n".join([
        f"- **{r.analyzer_name}**: {r.status} (Score: {r.score}/100)"
        for r in results
    ])
    
    comment = (
        f"**Analyse automatique SOC — {ts}**\n\n"
        f"**Analyzers Cortex ({success_count}/{len(results)} réussis):**\n{analyzers_txt}\n\n"
        f"**Analyse IA (Groq):**\n\n{ia_analysis}"
    )
    thehive.add_comment(case_id, comment)

    # ── 8. Logger ──────────────────────────────────────────
    add_log(
        "ANALYSE_COMPLETE",
        f"Case #{case_num} — {observable_label} — {success_count} analyzers — {malicious_count} malveillants",
        observable_label,
        extra.get("category", data_type)
    )


# ╔══════════════════════════════════════════════════════════╗
# ║               RAPPORT D'ACTIVITÉ                        ║
# ╚══════════════════════════════════════════════════════════╝

def generate_activity_report():
    """Génère un rapport d'activité à la demande."""
    state = load_state()
    logs = get_last_logs(25)
    stats = state["stats"]

    rapport = groq.generate_report(logs, stats)

    telegram_send(
        f"📊 <b>RAPPORT D'ACTIVITÉ SOC</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{rapport}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        force=True
    )


# ╔══════════════════════════════════════════════════════════╗
# ║                  BOUCLE PRINCIPALE                       ║
# ╚══════════════════════════════════════════════════════════╝

def main():
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Script 2 peut bloquer une IP publique après analyse Cortex : il DOIT
    # donc s'assurer que la chaîne firewall existe, sans dépendre de
    # l'ordre de démarrage de script1.
    try:
        firewall_setup()
    except Exception as e:
        log.warning(f"firewall_setup au démarrage: {e}")

    # Vérifications
    warnings = []
    if not Config.CORTEX_API: warnings.append("❌ CORTEX_API")
    if not Config.THEHIVE_API: warnings.append("❌ THEHIVE_API")
    if not Config.GROQ_API_KEY: warnings.append("❌ GROQ_API_KEY")
    if not mail.is_configured(): warnings.append("⚠️ Mail non configuré")

    warning_block = ""
    if warnings:
        warning_text = chr(10).join(warnings)
        warning_block = f"⚠️ <b>Config manquante:</b>{chr(10)}{warning_text}{chr(10)}"

    telegram_send(
        f"🔬 <b>SOC SCRIPT 2 — DÉMARRÉ</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ Cortex : {Config.CORTEX_URL}\n"
        f"✅ Groq : {Config.GROQ_MODEL}\n"
        f"✅ Mail : {'✅' if mail.is_configured() else '❌'}\n"
        f"{warning_block}\n"
        f"🕐 {ts}\n"
        f"🔰 By <b>12ak_H4ck</b>",
        force=True
    )

    log.info("═════════════════════════════════════════════")
    log.info("  SCRIPT 2 — response_soc.py")
    log.info(f"  Cortex: {Config.CORTEX_URL}")
    log.info(f"  Groq: {Config.GROQ_MODEL}")
    log.info("═════════════════════════════════════════════")

    errors = 0
    while True:
        try:
            # Filet de sécurité : si un timer d'unblock a sauté (restart),
            # on nettoie quand même les blocages expirés à chaque cycle.
            check_expired_blocks()

            state = load_state()

            # Vérifier si un rapport est demandé
            if state.get("report_requested"):
                generate_activity_report()
                state = load_state()
                state["report_requested"] = False
                save_state(state)

            # Traiter les cases en attente
            cases = state.get("cases", [])
            pending = [c for c in cases if not c.get("analyzed", False)]

            for case in pending:
                process_case(case)
                
                # Marquer comme analysé
                state = load_state()
                for c in state["cases"]:
                    if c["case_id"] == case["case_id"]:
                        c["analyzed"] = True
                save_state(state)

            if pending:
                log.info(f"{len(pending)} case(s) traité(s)")
            
            errors = 0

        except Exception as e:
            errors += 1
            log.error(f"Erreur boucle: {e}", exc_info=True)
            if errors >= 5:
                telegram_send(f"⚠️ <b>Script 2: {errors} erreurs</b>\n{str(e)[:200]}", force=True)
                errors = 0

        time.sleep(Config.WAZUH_POLL_INTERVAL)


if __name__ == "__main__":
    main()