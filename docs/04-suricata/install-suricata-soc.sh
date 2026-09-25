#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SOC Automation Pipeline — Installation du capteur Suricata
#
#  Installe Suricata en mode IDS, déploie toutes les règles custom
#  présentes dans rules/ (n'importe quel *.rules ajouté là est repris
#  automatiquement) + le jeu ET Open, et écrit dans
#  /var/log/suricata/eve.json — le fichier ingéré par Wazuh/surveillance_soc.py.
#
#  À LANCER SUR LA MACHINE CAPTEUR (celle qui voit le trafic à
#  surveiller). Sur un bridge Proxmox sans port-mirroring, c'est la
#  machine CIBLE de l'attaque.
#
#  Usage :
#      sudo bash install-suricata-soc.sh
#      sudo IFACE=eth1 HOMENET='[10.0.0.0/8]' bash install-suricata-soc.sh
#
#  Pour ajouter d'autres règles custom : dépose n'importe quel fichier
#  *.rules dans rules/ (à côté de ce script) et relance le script.
#
#  Testé : Ubuntu 20.04/22.04/24.04 (PPA OISF), Debian 11/12.
# ══════════════════════════════════════════════════════════════════
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "À lancer en root (sudo)."; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="$SCRIPT_DIR/rules"

# ── 1. Paramètres (auto-détection, surchargeables par variables d'env) ──
IFACE="${IFACE:-$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')}"
[ -n "${IFACE:-}" ] || { echo "Interface introuvable — relance avec IFACE=<iface>"; exit 1; }
HOMENET="${HOMENET:-[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]}"
echo ">> Interface capteur : $IFACE"
echo ">> HOME_NET          : $HOMENET"

# ── 2. Installation du paquet ──
. /etc/os-release
export DEBIAN_FRONTEND=noninteractive
if [ "${ID:-}" = "ubuntu" ]; then
  apt-get update -y
  apt-get install -y software-properties-common jq
  add-apt-repository -y ppa:oisf/suricata-stable
  apt-get update -y
fi
apt-get install -y suricata jq
systemctl stop suricata 2>/dev/null || true

# ── 3. Règles custom SOC — tous les *.rules trouvés dans rules/ ──
mkdir -p /etc/suricata/rules "$RULES_DIR"
shopt -s nullglob
CUSTOM_RULES=("$RULES_DIR"/*.rules)
shopt -u nullglob

if [ "${#CUSTOM_RULES[@]}" -eq 0 ]; then
  echo ">> Aucune règle dans $RULES_DIR — écriture d'un jeu minimal par défaut"
  cat > "$RULES_DIR/soc-custom.rules" <<'RULES'
alert tcp any any -> any any (msg:"POSSBL PORT SCAN (NMAP -sS)"; flow:to_server,stateless; flags:S; threshold:type both, track by_src, count 20, seconds 60; classtype:attempted-recon; sid:3400001; priority:2; rev:1;)
alert tcp any any -> any 22 (msg:"POSSBL SSH BRUTE FORCE"; flow:to_server,stateless; flags:S; threshold:type both, track by_src, count 10, seconds 20; classtype:attempted-recon; sid:3400030; priority:2; rev:1;)
alert tcp any any -> any 4444 (msg:"POSSBL SCAN SHELL M-SPLOIT TCP"; flow:to_server; classtype:trojan-activity; sid:3400020; priority:1; rev:1;)
RULES
  CUSTOM_RULES=("$RULES_DIR/soc-custom.rules")
fi

for f in "${CUSTOM_RULES[@]}"; do
  name="$(basename "$f")"
  install -m 0644 "$f" "/etc/suricata/rules/$name"
  echo ">> Règle custom installée : $name"
done

# ── 4. Configuration de suricata.yaml ──
Y=/etc/suricata/suricata.yaml
[ -f "$Y.orig" ] || cp "$Y" "$Y.orig"
sed -i "s|^\([[:space:]]*\)HOME_NET:.*|\1HOME_NET: \"$HOMENET\"|" "$Y"
sed -i "0,/^\([[:space:]]*\)- interface:.*/s//\1- interface: $IFACE/" "$Y"
sed -i 's|^\([[:space:]]*\)#\?[[:space:]]*community-id:.*|\1community-id: true|' "$Y"

# charge chaque règle custom en plus de suricata.rules (idempotent au ré-lancement)
for f in "${CUSTOM_RULES[@]}"; do
  name="$(basename "$f")"
  grep -q "$name" "$Y" || \
    sed -i "/^[[:space:]]*-[[:space:]]*suricata\.rules[[:space:]]*\$/a\\  - /etc/suricata/rules/$name" "$Y"
done

# coupe le bruit "decoder / stream / app-layer events" (trames L2 du bridge Proxmox)
sed -i -E 's|^([[:space:]]*-[[:space:]]*[a-z0-9-]*events\.rules[[:space:]]*)$|#\1|' "$Y"

if [ -f /etc/default/suricata ]; then
  sed -i "s|^IFACE=.*|IFACE=\"$IFACE\"|"          /etc/default/suricata || true
  sed -i 's|^LISTENMODE=.*|LISTENMODE=af-packet|' /etc/default/suricata || true
fi

# ── 5. Suppression du bruit décodeur résiduel ──
if ! grep -q 'sig_id 2200121' /etc/suricata/threshold.config 2>/dev/null; then
  cat >> /etc/suricata/threshold.config <<'EOF'

# Bruit L2 du bridge Proxmox (SURICATA Ethertype unknown, etc.)
suppress gen_id 1, sig_id 2200121
suppress gen_id 1, sig_id 2200122
EOF
fi

# ── 6. Règles Emerging Threats Open ──
if command -v suricata-update >/dev/null 2>&1; then
  suricata-update update-sources || true
  suricata-update enable-source et/open || true
  suricata-update || true
fi

# ── 7. Validation + démarrage ──
echo ">> Test de configuration..."
suricata -T -c "$Y" -v
systemctl enable suricata
systemctl restart suricata
sleep 3
systemctl --no-pager --full status suricata | grep -E 'Active:|Loaded:' || true

cat <<EOF

══════════════════════════════════════════════════════════════════
 Suricata installé.
   Interface   : $IFACE
   Règles SOC  : $(printf '%s, ' "${CUSTOM_RULES[@]##*/}" | sed 's/, $//')
   Journal     : /var/log/suricata/eve.json   (JSON — ingéré par Wazuh)
   Alertes     : tail -f /var/log/suricata/fast.log

 Test :  depuis une AUTRE machine   nmap -sS -p1-1000 <ip-de-ce-capteur>
         puis  grep 'POSSBL' /var/log/suricata/fast.log
══════════════════════════════════════════════════════════════════
EOF
