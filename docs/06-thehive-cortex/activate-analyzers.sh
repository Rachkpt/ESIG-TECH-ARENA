#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Active VirusTotal + AbuseIPDB dans Cortex via son API REST
#
# Prérequis, non automatisables (voir README.md / cortex-analyzers.md) :
#   1. Un compte Cortex org-admin déjà créé (premier accès web obligatoire)
#      + sa clé API (Cortex → mon compte → clé API)
#   2. De vraies clés VirusTotal / AbuseIPDB (comptes externes)
#
# Utilisable en mode interactif (il demande les valeurs manquantes)
# ou non-interactif (exporte CORTEX_API_KEY / VT_API_KEY / ABUSEIPDB_API_KEY
# avant de lancer le script).
# ═══════════════════════════════════════════════════════════

set -e

CORTEX_URL="${CORTEX_URL:-http://localhost:9001}"

# Identifiants d'analyzer tels que listés dans Cortex → Organization → Analyzers.
# Si une version plus récente est listée chez toi, remplace ici ou exporte
# VT_ANALYZER_ID / ABUSEIPDB_ANALYZER_ID avant de lancer le script.
VT_ANALYZER_ID="${VT_ANALYZER_ID:-VirusTotal_GetReport_3_1}"
ABUSEIPDB_ANALYZER_ID="${ABUSEIPDB_ANALYZER_ID:-AbuseIPDB_1_0}"

echo "🔑 Activation des analyzers Cortex (VirusTotal + AbuseIPDB)"
echo "════════════════════════════════════════════════════════"
echo "⚠️  Best-effort : l'API d'activation n'est pas couverte par un test"
echo "   automatisé ici. Si une requête échoue, le message d'erreur HTTP"
echo "   est affiché et l'activation manuelle reste possible (voir"
echo "   cortex-analyzers.md, Étape 3)."
echo ""

[ -z "$CORTEX_API_KEY" ] && read -rp "Clé API Cortex (org-admin) : " CORTEX_API_KEY
[ -z "$VT_API_KEY" ] && read -rp "Clé API VirusTotal : " VT_API_KEY
[ -z "$ABUSEIPDB_API_KEY" ] && read -rp "Clé API AbuseIPDB : " ABUSEIPDB_API_KEY

if [ -z "$CORTEX_API_KEY" ]; then
    echo "❌ Clé API Cortex manquante, impossible de continuer."
    exit 1
fi

RESP_FILE=$(mktemp)
trap 'rm -f "$RESP_FILE"' EXIT

activate() {
    local analyzer_id="$1"
    local api_key="$2"

    if [ -z "$api_key" ]; then
        echo "⏭️  $analyzer_id : pas de clé fournie, ignoré."
        return
    fi

    echo "→ Activation de $analyzer_id..."
    local http_code
    http_code=$(curl -s -o "$RESP_FILE" -w "%{http_code}" \
        -X POST "$CORTEX_URL/api/organization/analyzer/$analyzer_id" \
        -H "Authorization: Bearer $CORTEX_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$analyzer_id\", \"configuration\": {\"key\": \"$api_key\"}, \"jobCache\": 10, \"jobTimeout\": 30}")

    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        echo "  ✅ $analyzer_id activé."
    else
        echo "  ⚠️  Échec (HTTP $http_code). Réponse de Cortex :"
        cat "$RESP_FILE"
        echo ""
        echo "  → Active-le à la main : Cortex → Organization → Analyzers → cherche"
        echo "    '$analyzer_id' → + Create → colle la clé dans le champ 'key'."
    fi
}

activate "$VT_ANALYZER_ID" "$VT_API_KEY"
activate "$ABUSEIPDB_ANALYZER_ID" "$ABUSEIPDB_API_KEY"

echo ""
echo "Vérifie dans Cortex → Organization → Analyzers que les deux apparaissent."
echo "Puis teste-les vraiment (ne pas sauter cette étape) : voir cortex-analyzers.md, Étape 4."
