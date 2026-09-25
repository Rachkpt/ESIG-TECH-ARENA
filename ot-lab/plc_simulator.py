#!/usr/bin/env python3
"""
plc_simulator.py — Automate industriel (PLC) Modbus/TCP simulé — CEET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Simule un automate programmable d'un poste électrique de la CEET, qui
parle le protocole industriel Modbus/TCP (port 502). Sert de CIBLE pour
la démonstration de détection d'attaque ICS/SCADA du SOC.

Aucune dépendance externe : serveur Modbus/TCP minimal en socket pur
(fonctionne sur n'importe quelle VM Python 3, sans pip install).

Cartographie (registres du poste Lomé-Nord) :
  • Coils (bobines, lecture/écriture bit) :
      0 = Disjoncteur ligne 1   (1 = fermé/sous tension, 0 = ouvert)
      1 = Disjoncteur ligne 2
      2 = Sectionneur transfo
  • Registres de maintien (mesures, 16 bits) :
      0 = Tension ligne 1 (V, ex. 15000 = 15 kV)
      1 = Tension ligne 2
      2 = Charge (%)

⚠️ Le protocole Modbus n'a AUCUNE authentification : n'importe qui sur
   le réseau peut écrire une bobine (ouvrir un disjoncteur). C'est
   précisément ce que le SOC doit détecter et soumettre à validation
   humaine — jamais bloquer aveuglément (couper le courant ≠ sécurité).

Usage :
    sudo python3 plc_simulator.py            # écoute 0.0.0.0:502
    python3 plc_simulator.py --host 0.0.0.0 --port 1502   # sans root
"""

import argparse
import socket
import struct
import threading
import time
from datetime import datetime

# ── État de l'automate ────────────────────────────────────────────
COILS = {0: True, 1: True, 2: True}                    # disjoncteurs fermés
REGISTERS = {0: 15000, 1: 15000, 2: 62}                # tensions + charge
COIL_NAMES = {0: "Disjoncteur ligne 1", 1: "Disjoncteur ligne 2",
              2: "Sectionneur transfo"}
_lock = threading.Lock()


def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {level:5} │ {msg}", flush=True)


def _read_bits(store, start, qty):
    """Encode qty bits (coils) à partir de `start` en octets Modbus."""
    nbytes = (qty + 7) // 8
    data = bytearray(nbytes)
    for i in range(qty):
        if store.get(start + i, False):
            data[i // 8] |= (1 << (i % 8))
    return bytes([nbytes]) + bytes(data)


def _read_regs(store, start, qty):
    """Encode qty registres 16 bits à partir de `start`."""
    data = bytearray([qty * 2])
    for i in range(qty):
        data += struct.pack(">H", store.get(start + i, 0) & 0xFFFF)
    return bytes(data)


def handle_pdu(pdu: bytes, peer: str) -> bytes:
    """Traite une PDU Modbus et retourne la PDU de réponse."""
    if not pdu:
        return b""
    func = pdu[0]

    try:
        # ── 0x01 Read Coils / 0x02 Read Discrete Inputs ──
        if func in (0x01, 0x02):
            start, qty = struct.unpack(">HH", pdu[1:5])
            with _lock:
                return bytes([func]) + _read_bits(COILS, start, qty)

        # ── 0x03 Read Holding / 0x04 Read Input Registers ──
        if func in (0x03, 0x04):
            start, qty = struct.unpack(">HH", pdu[1:5])
            with _lock:
                return bytes([func]) + _read_regs(REGISTERS, start, qty)

        # ── 0x05 Write Single Coil ── (COMMANDE SENSIBLE) ─
        if func == 0x05:
            addr, value = struct.unpack(">HH", pdu[1:5])
            new_state = (value == 0xFF00)
            with _lock:
                COILS[addr] = new_state
            name = COIL_NAMES.get(addr, f"coil {addr}")
            etat = "FERMÉ ⚡" if new_state else "OUVERT ⛔ (COUPURE)"
            log(f"ÉCRITURE COIL depuis {peer} → {name} = {etat}", "WRITE")
            if not new_state:
                log(f"🚨 {name} OUVERT par {peer} — perte d'alimentation simulée !", "ALERT")
            return pdu[:5]  # écho de la requête = réponse standard

        # ── 0x06 Write Single Register ── (COMMANDE SENSIBLE) ─
        if func == 0x06:
            addr, value = struct.unpack(">HH", pdu[1:5])
            with _lock:
                REGISTERS[addr] = value
            log(f"ÉCRITURE REGISTRE depuis {peer} → reg {addr} = {value}", "WRITE")
            return pdu[:5]

        # ── Fonction non supportée → exception Modbus 0x01 ─
        log(f"Fonction Modbus 0x{func:02x} non supportée (depuis {peer})", "WARN")
        return bytes([func | 0x80, 0x01])
    except struct.error:
        return bytes([func | 0x80, 0x03])  # illegal data value


def handle_client(conn: socket.socket, addr):
    peer = addr[0]
    log(f"Connexion Modbus de {peer}:{addr[1]}", "CONN")
    try:
        conn.settimeout(60)
        while True:
            header = _recv_exact(conn, 7)
            if not header:
                break
            tid, pid, length, unit = struct.unpack(">HHHB", header)
            pdu = _recv_exact(conn, length - 1)
            if pdu is None:
                break
            resp_pdu = handle_pdu(pdu, peer)
            if not resp_pdu:
                continue
            mbap = struct.pack(">HHHB", tid, 0, len(resp_pdu) + 1, unit)
            conn.sendall(mbap + resp_pdu)
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        conn.close()
        log(f"Déconnexion {peer}", "CONN")


def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None if not buf else buf
        buf += chunk
    return buf


def _status_printer():
    """Affiche périodiquement l'état du poste."""
    while True:
        time.sleep(15)
        with _lock:
            etats = " | ".join(
                f"{COIL_NAMES[c]}: {'ON' if COILS.get(c) else 'OFF'}"
                for c in sorted(COIL_NAMES)
            )
        log(f"État poste → {etats}", "STATE")


def main():
    ap = argparse.ArgumentParser(description="Automate Modbus/TCP simulé (CEET)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=502,
                    help="502 = port Modbus standard (root requis) ; 1502 sinon")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.host, args.port))
    except PermissionError:
        log(f"Port {args.port} interdit (root requis pour <1024). "
            f"Relance avec --port 1502.", "ERROR")
        return
    srv.listen(5)

    log("═════════════════════════════════════════════")
    log(f"  AUTOMATE CEET (Modbus/TCP) — {args.host}:{args.port}")
    log("  Poste électrique Lomé-Nord — 3 disjoncteurs")
    log("═════════════════════════════════════════════")
    threading.Thread(target=_status_printer, daemon=True).start()

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        log("Arrêt de l'automate.", "INFO")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
