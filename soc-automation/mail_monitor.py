#!/usr/bin/env python3
"""
mail_monitor.py — Script 4 : surveillance de la boîte mail (anti-phishing)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Se connecte en IMAP au serveur mail (iRedMail / Dovecot), lit les
nouveaux messages, en extrait les LIENS (URLs) et les soumet au pipeline
d'analyse existant (Cortex → IA → Telegram). Objectif : détecter
automatiquement les emails de phishing dès leur réception.

Dépendances : uniquement la bibliothèque standard (imaplib, email).

Config (.env) :
  MAIL_MONITOR_ENABLE=true
  IMAP_HOST=mail.tondomaine.tg   IMAP_PORT=993
  IMAP_USER=soc@tondomaine.tg    IMAP_PASS=...
  IMAP_FOLDER=INBOX              MAIL_POLL_INTERVAL=60
"""

import re
import sys
import time
import email
import imaplib
import logging
from email.header import decode_header
from datetime import datetime

from soc_config import Config, Severity
from soc_utils import (
    load_state, save_state, add_log, telegram_send, should_alert
)
from soc_clients import thehive

log = logging.getLogger("mail_monitor")

# Regex d'extraction d'URL (http/https), on nettoie la ponctuation finale
_URL_RE = re.compile(r'https?://[^\s"\'<>()\]}]+', re.IGNORECASE)
_TRAILING = '.,;:!?)]}>"\''


def _decode(value: str) -> str:
    """Décode un en-tête MIME (sujet/expéditeur éventuellement encodé)."""
    if not value:
        return ""
    parts = []
    for txt, enc in decode_header(value):
        if isinstance(txt, bytes):
            try:
                parts.append(txt.decode(enc or "utf-8", "replace"))
            except (LookupError, TypeError):
                parts.append(txt.decode("utf-8", "replace"))
        else:
            parts.append(txt)
    return "".join(parts)


def _extract_bodies(msg) -> str:
    """Concatène les parties texte + html du message."""
    chunks = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        chunks.append(payload.decode(charset, "replace"))
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                chunks.append(payload.decode(msg.get_content_charset() or "utf-8", "replace"))
        except Exception:
            pass
    return "\n".join(chunks)


def extract_urls(text: str) -> list:
    """Extrait les URLs uniques d'un texte (nettoie la ponctuation finale)."""
    urls = []
    seen = set()
    for m in _URL_RE.findall(text or ""):
        u = m.rstrip(_TRAILING)
        # ignore les images/ressources statiques courantes (bruit)
        if re.search(r'\.(png|jpg|jpeg|gif|svg|css|ico|woff2?)($|\?)', u, re.I):
            continue
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def _enqueue_url(url: str, sender: str, subject: str):
    """Crée un case TheHive (type url) et le met en file pour le Script 2."""
    case = thehive.create_observable_case(
        url, "url", "Lien recu par email",
        f"Lien detecte dans un email\nExpediteur : {sender}\nSujet : {subject}",
        Severity.MEDIUM, "Email")
    if not case:
        telegram_send(f"⚠️ Échec création case pour le lien : <code>{url[:80]}</code>")
        return None
    state = load_state()
    state["cases"].append({
        "case_id": case.get("_id", ""),
        "number": case.get("number", "?"),
        "ip": url,
        "title": f"Lien email — {url[:40]}",
        "description": f"Email de {sender} — {subject}",
        "severity": 2,
        "data_type": "url",
        "assignee": case.get("assignee", ""),
        "extra_data": {"category": "email_phishing", "sender": sender, "subject": subject},
        "created_at": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "analyzed": False,
    })
    save_state(state)
    return case.get("number", "?")


def process_message(msg, mailbox: str = ""):
    """Traite un message : extrait les liens et lance l'analyse."""
    sender = _decode(msg.get("From", ""))
    subject = _decode(msg.get("Subject", "(sans objet)"))
    body = _extract_bodies(msg)
    urls = extract_urls(body)

    if not urls:
        log.info(f"[{mailbox}] Email de {sender} — aucun lien")
        return

    urls = urls[:Config.MAIL_MAX_URLS]
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    telegram_send(
        f"📧 <b>EMAIL REÇU — analyse des liens</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📥 Boîte : <code>{mailbox}</code>\n"
        f"✉️ De : <code>{sender[:60]}</code>\n"
        f"📝 Sujet : {subject[:80]}\n"
        f"🔗 Liens détectés : <b>{len(urls)}</b>\n"
        f"🕐 {ts}\n"
        f"⏳ Analyse Cortex en cours (résultats à suivre)...",
        force=True
    )

    for url in urls:
        # Anti-spam : un même lien n'est pas ré-analysé avant 6h
        if not should_alert(f"mailurl:{url}", window_seconds=21600):
            continue
        num = _enqueue_url(url, sender, subject)
        if num:
            add_log("EMAIL_LIEN", f"Lien de {sender} mis en analyse (case #{num})", "", "email_phishing")


def load_accounts() -> list:
    """
    Retourne la liste des boîtes à surveiller : [(user, password), ...].
    Priorité au fichier MAIL_ACCOUNTS_FILE (une ligne 'email:motdepasse',
    lignes vides et # ignorées) ; sinon repli sur IMAP_USER/IMAP_PASS.
    Tous les comptes partagent IMAP_HOST/IMAP_PORT (même serveur iRedMail).
    """
    import os
    accounts = []
    path = Config.MAIL_ACCOUNTS_FILE
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # split sur le PREMIER ':' (les emails n'en contiennent pas)
                if ":" in line:
                    user, pwd = line.split(":", 1)
                    user, pwd = user.strip(), pwd.strip()
                    if user and pwd:
                        accounts.append((user, pwd))
    if not accounts and Config.IMAP_USER and Config.IMAP_PASS:
        accounts.append((Config.IMAP_USER, Config.IMAP_PASS))
    return accounts


def _connect(user: str, passwd: str) -> imaplib.IMAP4_SSL:
    import ssl
    ctx = ssl.create_default_context()
    if not Config.IMAP_VERIFY_SSL:
        # iRedMail utilise souvent un certificat auto-signé en lab
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    conn = imaplib.IMAP4_SSL(Config.IMAP_HOST, Config.IMAP_PORT, ssl_context=ctx)
    conn.login(user, passwd)
    conn.select(Config.IMAP_FOLDER)
    return conn


def main():
    if not Config.MAIL_MONITOR_ENABLE:
        print("MAIL_MONITOR_ENABLE=false — surveillance mail désactivée.")
        sys.exit(0)
    if not Config.IMAP_HOST:
        print("❌ IMAP_HOST manquant dans .env")
        sys.exit(1)

    accounts = load_accounts()
    if not accounts:
        print("❌ Aucun compte à surveiller (mail_accounts.txt vide et IMAP_USER/PASS absents)")
        sys.exit(1)

    log.info("═════════════════════════════════════════════")
    log.info("  SCRIPT 4 — mail_monitor.py (anti-phishing email)")
    log.info(f"  Serveur : {Config.IMAP_HOST}:{Config.IMAP_PORT} | {len(accounts)} boîte(s)")
    log.info("═════════════════════════════════════════════")
    telegram_send(
        f"📬 <b>Surveillance mail activée</b>\n"
        f"Serveur : <code>{Config.IMAP_HOST}</code>\n"
        f"Boîtes surveillées : <b>{len(accounts)}</b>\n"
        f"Les liens des nouveaux emails seront analysés automatiquement.",
        force=True
    )

    errors = 0
    backoff = 0   # secondes d'attente supplémentaire après erreurs réseau
    while True:
        for user, passwd in accounts:
            try:
                conn = _connect(user, passwd)
                typ, data = conn.search(None, "UNSEEN")   # nouveaux messages
                ids = data[0].split() if data and data[0] else []
                for mid in ids:
                    typ, msg_data = conn.fetch(mid, "(RFC822)")
                    if typ != "OK" or not msg_data or not msg_data[0]:
                        continue
                    msg = email.message_from_bytes(msg_data[0][1])
                    try:
                        process_message(msg, mailbox=user)
                    except Exception as e:
                        log.error(f"[{user}] Traitement message {mid}: {e}")
                    conn.store(mid, "+FLAGS", "\\Seen")   # marque lu
                conn.logout()
                if ids:
                    log.info(f"[{user}] {len(ids)} nouvel(aux) email(s) traité(s)")
                errors = 0
                backoff = 0
            except Exception as e:
                errors += 1
                log.error(f"[{user}] Boucle mail: {e}")
                # Recul progressif : évite de marteler le serveur (et de se
                # faire bannir par fail2ban) quand la connexion échoue.
                backoff = min(600, (backoff or 30) * 2)
                if errors >= 5:
                    telegram_send(f"⚠️ <b>Surveillance mail : {errors} erreurs</b>\n"
                                  f"Boîte <code>{user}</code> : {str(e)[:150]}", force=True)
                    errors = 0
            # Petite pause ENTRE chaque boîte (connexions moins rapprochées)
            time.sleep(3)
        # Recul supplémentaire si des erreurs réseau se produisent
        time.sleep(Config.MAIL_POLL_INTERVAL + backoff)


if __name__ == "__main__":
    main()
