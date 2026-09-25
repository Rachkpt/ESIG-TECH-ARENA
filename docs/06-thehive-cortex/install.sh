#!/bin/bash
# ═══════════════════════════════════════════════════════════
# TheHive 5 + Cortex — Installation automatisée
# Docker + stack complète, avec les correctifs découverts en
# déploiement réel (permissions logs, secret Play, URL analyzer).
# ═══════════════════════════════════════════════════════════

set -e

PROJECT_DIR="$HOME/soc-project"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$EUID" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo "🐝 TheHive 5 + Cortex — Installation automatisée"
echo "═════════════════════════════════════════════════"

# ─── 1. Docker ────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "📦 Installation de Docker..."
    $SUDO apt update
    $SUDO apt install -y ca-certificates curl gnupg
    $SUDO install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    $SUDO chmod a+r /etc/apt/keyrings/docker.gpg

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      $SUDO tee /etc/apt/sources.list.d/docker.list > /dev/null

    $SUDO apt update
    $SUDO apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    echo "✅ Docker installé : $(docker --version)"
else
    echo "✅ Docker déjà présent : $(docker --version)"
fi

# ─── 2. Code des analyzers Cortex ──────────────────────────────
if [ ! -d /opt/Cortex-Analyzers ]; then
    echo "📥 Récupération de Cortex-Analyzers..."
    CLONE_OK=false
    for i in 1 2 3; do
        if $SUDO git clone --depth 1 https://github.com/TheHive-Project/Cortex-Analyzers.git /opt/Cortex-Analyzers; then
            CLONE_OK=true
            break
        fi
        echo "⚠️  Échec du clone (souvent un DNS/réseau instable), nouvelle tentative dans 10s... ($i/3)"
        $SUDO rm -rf /opt/Cortex-Analyzers
        sleep 10
    done
    if [ "$CLONE_OK" != true ]; then
        echo "❌ Impossible de cloner Cortex-Analyzers après 3 tentatives. Relance ce script plus tard, ou clone manuellement :"
        echo "   sudo git clone https://github.com/TheHive-Project/Cortex-Analyzers.git /opt/Cortex-Analyzers"
        exit 1
    fi
else
    echo "✅ /opt/Cortex-Analyzers déjà présent, conservé tel quel."
fi

# ─── 3. Répertoire projet ───────────────────────────────────────
echo "📁 Préparation de $PROJECT_DIR..."
mkdir -p "$PROJECT_DIR/cortex/logs"
cp "$SCRIPT_DIR/docker-compose.yml" "$PROJECT_DIR/docker-compose.yml"

# Le conteneur Cortex écrit ses logs avec l'UID 1001 (image thehiveproject/cortex).
# Un dossier créé en root fait planter Cortex au démarrage (Permission denied).
$SUDO chown -R 1001:1001 "$PROJECT_DIR/cortex/logs"

# ─── 4. Secrets + .env ──────────────────────────────────────────
if [ -f "$PROJECT_DIR/.env" ]; then
    echo "✅ .env déjà présent, secrets conservés."
    set -a
    source "$PROJECT_DIR/.env"
    set +a
else
    echo "🔑 Génération des secrets..."
    CORTEX_SECRET_KEY=$(openssl rand -hex 32)
    THEHIVE_SECRET_KEY=$(openssl rand -hex 32)
    MINIO_ROOT_USER="soc-admin"
    MINIO_ROOT_PASSWORD=$(openssl rand -hex 24)

    cat > "$PROJECT_DIR/.env" << EOF
THEHIVE_SECRET_KEY=${THEHIVE_SECRET_KEY}
CORTEX_SECRET_KEY=${CORTEX_SECRET_KEY}
MINIO_ROOT_USER=${MINIO_ROOT_USER}
MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}
EOF
    chmod 600 "$PROJECT_DIR/.env"
    echo "✅ .env généré dans $PROJECT_DIR/.env (secrets non affichés ici)"
fi

# ─── 5. application.conf Cortex ────────────────────────────────
# Heredoc NON quoté (<< EOF, pas << 'EOF') : bash substitue vraiment
# ${CORTEX_SECRET_KEY} par sa valeur. Un secret trop court (ex. la
# chaîne littérale non substituée) fait planter Cortex :
# "application secret is too short... 256 bits requis".
# analyzer.urls doit être une URL avec schéma (file://), pas un
# chemin brut, sinon MalformedURLException au démarrage.
cat > "$PROJECT_DIR/cortex/application.conf" << EOF
play.http.secret.key = "${CORTEX_SECRET_KEY}"

search {
  index = cortex
  uri = "http://elasticsearch:9200"
}

cache.job = 10 minutes

job {
  timeout = 30 minutes
  directory = /tmp/cortex-jobs
}

analyzer {
  urls = [
    "file:///opt/Cortex-Analyzers/analyzers"
  ]
}
EOF

# ─── 6. Lancer la stack ─────────────────────────────────────────
echo "🚀 Lancement des conteneurs (peut prendre plusieurs minutes, gros téléchargements)..."
cd "$PROJECT_DIR"

UP_OK=false
for i in 1 2 3; do
    if $SUDO docker compose up -d; then
        UP_OK=true
        break
    fi
    echo "⚠️  docker compose up a échoué (souvent un timeout DNS pendant le pull), nouvelle tentative dans 15s... ($i/3)"
    sleep 15
done
if [ "$UP_OK" != true ]; then
    echo "❌ Échec après 3 tentatives. Relance manuellement : cd $PROJECT_DIR && docker compose up -d"
    exit 1
fi

# ─── 7. Dépendances Python des analyzers ───────────────────────
echo "⏳ Attente que le conteneur Cortex soit joignable..."
CORTEX_READY=false
for i in $(seq 1 12); do
    if $SUDO docker compose exec -T cortex.local true 2>/dev/null; then
        CORTEX_READY=true
        break
    fi
    sleep 5
done

if [ "$CORTEX_READY" = true ]; then
    echo "📦 Installation des dépendances Python des analyzers (VirusTotal, AbuseIPDB)..."
    $SUDO docker compose exec -T cortex.local bash -c '
        apt-get update -qq && apt-get install -y -qq python3 python3-pip >/dev/null 2>&1
        pip3 install -q -r /opt/Cortex-Analyzers/analyzers/VirusTotal/requirements.txt 2>/dev/null
        pip3 install -q -r /opt/Cortex-Analyzers/analyzers/AbuseIPDB/requirements.txt 2>/dev/null
    ' || echo "⚠️  Installation des dépendances analyzers échouée, à refaire manuellement (voir cortex-analyzers.md)"
else
    echo "⚠️  Cortex pas encore joignable, dépendances analyzers à installer plus tard (voir cortex-analyzers.md)"
fi

# ─── 8. Résumé ──────────────────────────────────────────────────
IP=$(hostname -I | awk '{print $1}')
echo ""
echo "═══════════════════════════════════════════════════════"
echo "✅  Installation terminée !"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Laisse 3-5 min à Cassandra/Elasticsearch pour finir de démarrer, puis :"
echo "  TheHive  → http://$IP:9000   (admin@thehive.local / secret — à changer immédiatement)"
echo "  Cortex   → http://$IP:9001   (créer un compte admin au premier accès)"
echo "  MinIO    → http://$IP:9002   (identifiants dans $PROJECT_DIR/.env)"
echo ""
echo "⚠️  Rappel : si le conteneur cortex.local est recréé (down/up, pull, --force-recreate),"
echo "   les dépendances pip des analyzers sont perdues — relance ce script, ou refais"
echo "   l'Étape 2 de cortex-analyzers.md."
echo ""
echo "Étapes manuelles restantes (pas automatisables, nécessitent l'interface web) :"
echo "  1. Créer le premier compte admin Cortex (http://$IP:9001)"
echo "  2. README.md Étape 5      → lier Cortex à TheHive (Administration → Cortex, clé API)"
echo "  3. organisation-setup.md → créer l'organisation dédiée à soc-automation"
echo ""
echo "Ensuite, pour activer VirusTotal + AbuseIPDB dans Cortex sans cliquer dans l'UI :"
echo "  bash $SCRIPT_DIR/activate-analyzers.sh"
echo "  (te demandera ta clé API Cortex + tes clés VirusTotal/AbuseIPDB — voir cortex-analyzers.md Étape 1)"
echo ""
