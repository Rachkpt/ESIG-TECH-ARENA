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
# Poste de supervision SCADA autorisé (SEUL hôte censé écrire sur les
# automates Modbus). Utilisé par rules/soc-ics.rules. Par défaut un
# placeholder improbable → TOUTE écriture Modbus déclenche (idéal démo).
# En prod : SCADA_HMI='[192.168.10.10]' bash install-suricata-soc.sh
SCADA_HMI="${SCADA_HMI:-[192.0.2.123]}"
echo ">> Interface capteur : $IFACE"
echo ">> HOME_NET          : $HOMENET"
echo ">> SCADA_HMI (autorisé écriture Modbus) : $SCADA_HMI"

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

# Variable SCADA_HMI (poste de supervision autorisé) pour soc-ics.rules :
# ajoutée sous address-groups si absente, sinon mise à jour (idempotent).
if grep -qE '^\s*SCADA_HMI:' "$Y"; then
  sed -i "s|^\([[:space:]]*\)SCADA_HMI:.*|\1SCADA_HMI: \"$SCADA_HMI\"|" "$Y"
else
  sed -i "/^\([[:space:]]*\)HOME_NET:.*/a\\    SCADA_HMI: \"$SCADA_HMI\"" "$Y"
fi

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

# ── 7. Intégration Wazuh : l'agent lit eve.json et remonte les alertes ──
#  Ajoute un bloc <localfile> (format json) dans ossec.conf pour que
#  l'agent Wazuh ingère /var/log/suricata/eve.json. Idempotent : ne
#  duplique rien si le bloc existe déjà. Désactivable : WAZUH_INTEGRATION=false
WAZUH_INTEGRATION="${WAZUH_INTEGRATION:-true}"
EVE_JSON="/var/log/suricata/eve.json"
OSSEC_CONF="${OSSEC_CONF:-/var/ossec/etc/ossec.conf}"

if [ "$WAZUH_INTEGRATION" = "true" ]; then
  if [ -f "$OSSEC_CONF" ]; then
    if grep -q "$EVE_JSON" "$OSSEC_CONF"; then
      echo ">> Wazuh : eve.json déjà déclaré dans $OSSEC_CONF (rien à faire)"
    else
      echo ">> Wazuh : ajout de eve.json dans $OSSEC_CONF"
      cp "$OSSEC_CONF" "$OSSEC_CONF.bak.$(date +%s)"
      LF_BLOCK="  <localfile>\n    <log_format>json</log_format>\n    <location>$EVE_JSON</location>\n  </localfile>"
      if grep -q '</ossec_config>' "$OSSEC_CONF"; then
        # Insère le bloc juste avant la DERNIÈRE balise </ossec_config>
        awk -v block="$LF_BLOCK" '
          { lines[NR] = $0; if ($0 ~ /<\/ossec_config>/) last = NR }
          END {
            for (i = 1; i <= NR; i++) {
              if (i == last) print block
              print lines[i]
            }
          }' "$OSSEC_CONF" > "$OSSEC_CONF.tmp" && mv "$OSSEC_CONF.tmp" "$OSSEC_CONF"
      else
        # Pas de balise fermante : on ajoute un bloc ossec_config complet
        printf '<ossec_config>\n%b\n</ossec_config>\n' "$LF_BLOCK" >> "$OSSEC_CONF"
      fi
    fi

    # Redémarrer l'agent Wazuh pour prendre en compte le localfile
    if systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-agent'; then
      echo ">> Redémarrage wazuh-agent..."
      systemctl restart wazuh-agent || echo "   ⚠️ échec restart wazuh-agent (vérifier manuellement)"
    elif systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-manager'; then
      echo ">> Redémarrage wazuh-manager..."
      systemctl restart wazuh-manager || echo "   ⚠️ échec restart wazuh-manager (vérifier manuellement)"
    else
      echo "   ⚠️ Ni wazuh-agent ni wazuh-manager détecté — relancer le service Wazuh à la main."
    fi
  else
    echo ">> ⚠️ $OSSEC_CONF introuvable : agent Wazuh non installé sur ce capteur ?"
    echo "   Installe l'agent Wazuh puis relance, ou passe OSSEC_CONF=<chemin>."
  fi
else
  echo ">> Intégration Wazuh désactivée (WAZUH_INTEGRATION=false)"
fi

# ── 8. Validation + démarrage ──
echo ">> Test de configuration..."
suricata -T -c "$Y" -v
systemctl enable suricata
systemctl restart suricata
sleep 3
systemctl --no-pager --full status suricata | grep -E 'Active:|Loaded:' || true

cat <<EOF

══════════════════════════════════════════════════════════════════
 Suricata installé + intégré à Wazuh.
   Interface   : $IFACE
   Règles SOC  : $(printf '%s, ' "${CUSTOM_RULES[@]##*/}" | sed 's/, $//')
   Journal     : /var/log/suricata/eve.json   (JSON — ingéré par Wazuh)
   Wazuh       : localfile ajouté dans $OSSEC_CONF (WAZUH_INTEGRATION=$WAZUH_INTEGRATION)
   Alertes     : tail -f /var/log/suricata/fast.log

 Test :  depuis une AUTRE machine   nmap -sS -p1-1000 <ip-de-ce-capteur>
         1) local  : grep 'POSSBL' /var/log/suricata/fast.log
         2) Wazuh  : chercher rule.groups "suricata" dans le dashboard /
                     l'Indexer (index wazuh-alerts-*)
══════════════════════════════════════════════════════════════════
EOF
