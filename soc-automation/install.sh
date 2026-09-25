#!/bin/bash
# ═══════════════════════════════════════════════════════════
# SOC AUTOMATION PRO — Script d'installation
# ═══════════════════════════════════════════════════════════

set -e

INSTALL_DIR="/opt/soc-automation"
SERVICE_USER="root"

echo "🛡️  SOC Automation Pro — Installation"
echo "═════════════════════════════════════"

# Vérifier root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Lance en root: sudo bash install.sh"
    exit 1
fi

# Créer le répertoire
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Copier les fichiers
echo "📁 Copie des fichiers..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR"/*.py "$INSTALL_DIR/" 2>/dev/null || true
if [ -f "$SCRIPT_DIR/.env.example" ] && [ ! -f "$INSTALL_DIR/.env" ]; then
    cp "$SCRIPT_DIR/.env.example" "$INSTALL_DIR/" 2>/dev/null || true
fi

# Installer les dépendances
echo "📦 Installation des dépendances Python..."
pip3 install requests python-dotenv --break-system-packages 2>/dev/null || \
pip3 install requests python-dotenv

# Créer le fichier .env s'il n'existe pas
if [ ! -f "$INSTALL_DIR/.env" ]; then
    if [ -f "$INSTALL_DIR/.env.example" ]; then
        cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
        echo "⚠️  Édite le fichier .env avec tes vraies valeurs :"
        echo "   nano $INSTALL_DIR/.env"
    else
        echo "⚠️  Aucun .env trouvé — crée-le manuellement avant de démarrer les services."
    fi
else
    echo "✅ .env déjà présent, conservé tel quel."
fi

# Créer la jail Fail2ban soc-auto
echo "🔒 Configuration Fail2ban..."
if command -v fail2ban-client &>/dev/null; then
    cat > /etc/fail2ban/jail.d/soc-auto.conf << 'EOFAIL'
[soc-auto]
enabled  = true
filter   = soc-auto
banaction = iptables-allports
bantime  = 7200
maxretry = 1
EOFAIL

    cat > /etc/fail2ban/filter.d/soc-auto.conf << 'EOFIL'
[Definition]
failregex =
ignoreregex =
EOFIL

    systemctl restart fail2ban 2>/dev/null || true
    echo "✅ Jail Fail2ban 'soc-auto' configurée"
else
    echo "⚠️  Fail2ban non installé (apt install fail2ban)"
fi

# Créer le répertoire de logs
mkdir -p /var/log
touch /var/log/soc_automation.log
chmod 644 /var/log/soc_automation.log

# Créer les services systemd
echo "⚙️  Configuration des services systemd..."

cat > /etc/systemd/system/soc-script1.service << 'EOF'
[Unit]
Description=SOC Script 1 — Surveillance Wazuh
After=network.target

StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
WorkingDirectory=/opt/soc-automation
ExecStart=/usr/bin/python3 /opt/soc-automation/surveillance_soc.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/soc-script2.service << 'EOF'
[Unit]
Description=SOC Script 2 — Analyse & Réponse
After=network.target

StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
WorkingDirectory=/opt/soc-automation
ExecStart=/usr/bin/python3 /opt/soc-automation/response_soc.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/soc-telegram.service << 'EOF'
[Unit]
Description=SOC Telegram Bot Admin
After=network.target

StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
WorkingDirectory=/opt/soc-automation
ExecStart=/usr/bin/python3 /opt/soc-automation/telegram_bot.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Recharger systemd
systemctl daemon-reload

# Activer les services
systemctl enable soc-script1 soc-script2 soc-telegram

echo ""
echo "═══════════════════════════════════════════════════════"
echo "✅  Installation terminée !"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Prochaines étapes :"
echo "  1. nano $INSTALL_DIR/.env"
echo "  2. systemctl start soc-script1 soc-script2 soc-telegram"
echo "  3. systemctl status soc-script1 soc-script2 soc-telegram"
echo "  4. tail -f /var/log/soc_automation.log"
echo ""
echo "Commandes utiles :"
echo "  systemctl restart soc-script1   # Redémarrer surveillance"
echo "  systemctl restart soc-script2   # Redémarrer analyse"
echo "  systemctl stop soc-telegram     # Arrêter le bot"
echo "  journalctl -u soc-script1 -f    # Logs script 1"
echo ""