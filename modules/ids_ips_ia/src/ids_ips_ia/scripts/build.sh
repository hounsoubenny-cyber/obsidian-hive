#!/bin/bash
# =============================================================================
# SHIELD IA - BUILD COMPLET (PyArmor + Nuitka + UPX)
# Protection maximale du code source
# =============================================================================

set -e

# =============================================================================
# CONFIGURATION
# =============================================================================
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN="$(which python3.11)"
OUTPUT_NAME="shield_ai_ids_ips"
DIST_DIR="${PROJECT_ROOT}/dist_final"
TEMP_DIR="${PROJECT_ROOT}/build_temp"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $1"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

# =============================================================================
# VÉRIFICATIONS PRÉALABLES
# =============================================================================
check_dependencies() {
    print_step "Vérification des dépendances..."

    # Vérifier PyArmor
    if ! command -v pyarmor &> /dev/null; then
        print_error "PyArmor n'est pas installé"
        echo "  pip install pyarmor"
        exit 1
    fi

    # Vérifier Nuitka
    if ! python3.11 -m nuitka --version &> /dev/null; then
        print_error "Nuitka n'est pas installé"
        echo "  pip install nuitka"
        exit 1
    fi

    # Vérifier UPX (optionnel)
    if command -v upx &> /dev/null; then
        HAS_UPX=true
        print_success "UPX trouvé (compression activée)"
    else
        HAS_UPX=false
        print_warning "UPX non trouvé (pas de compression)"
        echo "  sudo dnf install upx  # Fedora"
        echo "  sudo apt install upx  # Debian/Ubuntu"
    fi

    print_success "Dépendances OK"
}

# =============================================================================
# NETTOYAGE
# =============================================================================
clean_build() {
    print_step "Nettoyage des builds précédents..."
    rm -rf "${TEMP_DIR}" 2>/dev/null || true
    rm -rf "${DIST_DIR}" 2>/dev/null || true
    mkdir -p "${TEMP_DIR}"
    mkdir -p "${DIST_DIR}"
    print_success "Nettoyage terminé"
}

# =============================================================================
# ÉTAPE 1 : PYARMOR (OBFUSCATION)
# =============================================================================
build_pyarmor() {
    print_step "🔒 [1/3] PyArmor - Obfuscation du code..."

    cd "${PROJECT_ROOT}"

    # Obfuscation ULTRA avancée
    pyarmor gen \
        --recursive \
        --advanced 5 \
        --obf-code 2 \
        --obf-string 2 \
        --obf-module 1 \
        --wrap-mode 1 \
        --mix-str \
        --private \
        --restrict \
        --output "${TEMP_DIR}/pyarmor" \
        ids_ips_ia/ 2>&1 | grep -v "^$" || true

    # Copier le point d'entrée
    cp main_ids_ips.py "${TEMP_DIR}/pyarmor/"

    # Copier les fichiers de données nécessaires
    echo "  Copie des fichiers de données..."
    mkdir -p "${TEMP_DIR}/pyarmor/ids_ips_ia/config"
    mkdir -p "${TEMP_DIR}/pyarmor/ids_ips_ia/data"
    mkdir -p "${TEMP_DIR}/pyarmor/ids_ips_ia/models/data"
    mkdir -p "${TEMP_DIR}/pyarmor/ids_ips_ia/reaction/data"
    mkdir -p "${TEMP_DIR}/pyarmor/ids_ips_ia/detection/data"

    cp -r ids_ips_ia/config/*.json "${TEMP_DIR}/pyarmor/ids_ips_ia/config/" 2>/dev/null || true
    cp -r ids_ips_ia/data/* "${TEMP_DIR}/pyarmor/ids_ips_ia/data/" 2>/dev/null || true
    cp ids_ips_ia/.env "${TEMP_DIR}/pyarmor/ids_ips_ia/" 2>/dev/null || true
    cp -r ids_ips_ia/reaction/data/locator/*.mmdb "${TEMP_DIR}/pyarmor/ids_ips_ia/reaction/data/locator/" 2>/dev/null || true

    print_success "PyArmor terminé"
}

# =============================================================================
# ÉTAPE 2 : NUITKA (COMPILATION STANDALONE)
# =============================================================================
build_nuitka() {
    print_step "🔧 [2/3] Nuitka - Compilation standalone..."

    cd "${TEMP_DIR}/pyarmor"

    # Liste des packages à inclure (détection automatique + manuelle)
    PACKAGES=(
        "ids_ips_ia"
        "ids_ips_ia.auth"
        "ids_ips_ia.config"
        "ids_ips_ia.core"
        "ids_ips_ia.detection"
        "ids_ips_ia.ids_ips_utils"
        "ids_ips_ia.memory_managers"
        "ids_ips_ia.models"
        "ids_ips_ia.reaction"
        "ids_ips_ia.refit_system"
        "dpkt"
        "pcap"
        "geoip2"
        "maxminddb"
        "loguru"
        "fastapi"
        "uvicorn"
        "slowapi"
        "starlette"
        "pydantic"
        "tensorflow"
        "keras"
        "sklearn"
        "numpy"
        "scipy"
        "pandas"
        "bokeh"
        "bcrypt"
        "jwt"
        "jose"
        "netifaces"
        "psutil"
        "yaml"
        "dill"
        "joblib"
        "nest_asyncio"
        "aiohttp"
        "aiosignal"
        "frozenlist"
        "multidict"
        "yarl"
        "websockets"
        "watchfiles"
        "python-dotenv"
        "passlib"
        "python-multipart"
        "email-validator"
    )

    # Construire les arguments --include-package
    INCLUDE_ARGS=""
    for pkg in "${PACKAGES[@]}"; do
        INCLUDE_ARGS="${INCLUDE_ARGS} --include-package=${pkg}"
    done

    # Dossiers de données à inclure
    DATA_DIRS=(
        "ids_ips_ia/config=ids_ips_ia/config"
        "ids_ips_ia/data=ids_ips_ia/data"
        "ids_ips_ia/models/data=ids_ips_ia/models/data"
        "ids_ips_ia/reaction/data=ids_ips_ia/reaction/data"
        "ids_ips_ia/detection/data=ids_ips_ia/detection/data"
    )

    DATA_ARGS=""
    for data_dir in "${DATA_DIRS[@]}"; do
        if [ -d "${data_dir%%=*}" ]; then
            DATA_ARGS="${DATA_ARGS} --include-data-dir=${data_dir}"
        fi
    done

    # Compilation Nuitka
    echo "  Compilation en cours (peut prendre 10-30 minutes)..."

    ${PYTHON_BIN} -m nuitka \
        --standalone \
        --onefile \
        --assume-yes-for-downloads \
        --enable-plugin=anti-bloat \
        --enable-plugin=pylint-warnings \
        ${HAS_UPX:+--enable-plugin=upx} \
        ${HAS_UPX:+--upx} \
        --lto=yes \
        --strip \
        --no-deployment \
        --output-dir="${TEMP_DIR}/nuitka" \
        --output-filename="${OUTPUT_NAME}" \
        ${INCLUDE_ARGS} \
        ${DATA_ARGS} \
        main_ids_ips.py 2>&1 | grep -E "(✅|❌|⚠️|Error|FATAL|完成)" || true

    # Copier l'exécutable final
    if [ -f "${TEMP_DIR}/nuitka/${OUTPUT_NAME}.bin" ]; then
        cp "${TEMP_DIR}/nuitka/${OUTPUT_NAME}.bin" "${DIST_DIR}/${OUTPUT_NAME}.bin"
    elif [ -f "${TEMP_DIR}/nuitka/${OUTPUT_NAME}" ]; then
        cp "${TEMP_DIR}/nuitka/${OUTPUT_NAME}" "${DIST_DIR}/${OUTPUT_NAME}.bin"
    fi

    print_success "Nuitka terminé"
}

# =============================================================================
# ÉTAPE 3 : UPX (COMPRESSION SUPPLÉMENTAIRE)
# =============================================================================
build_upx() {
    if [ "${HAS_UPX}" = true ] && [ -f "${DIST_DIR}/${OUTPUT_NAME}.bin" ]; then
        print_step "📦 [3/3] UPX - Compression maximale..."
        upx --best --lzma --ultra-brute "${DIST_DIR}/${OUTPUT_NAME}.bin" 2>&1 | tail -3
        print_success "UPX terminé"
    else
        print_step "📦 [3/3] UPX - Non disponible, skip"
    fi
}

# =============================================================================
# CRÉATION DU SCRIPT DE LANCEMENT
# =============================================================================
create_launcher() {
    print_step "Création du script de lancement..."

    cat > "${DIST_DIR}/run_${OUTPUT_NAME}.sh" << 'EOF'
#!/bin/bash
# Script de lancement pour SHIELD AI IDS/IPS

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Vérifier les capabilities
if ! getcap "${SCRIPT_DIR}/shield_ai_ids_ips.bin" 2>/dev/null | grep -q "cap_net_raw"; then
    echo "🔧 Configuration des capabilities réseau..."
    sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "${SCRIPT_DIR}/shield_ai_ids_ips.bin"
fi

# Lancer l'application
cd "${SCRIPT_DIR}"
./shield_ai_ids_ips.bin "$@"
EOF

    chmod +x "${DIST_DIR}/run_${OUTPUT_NAME}.sh"
    print_success "Script de lancement créé"
}

# =============================================================================
# RÉSUMÉ FINAL
# =============================================================================
show_summary() {
    echo ""
    echo "============================================================"
    echo -e "${GREEN}✅ BUILD TERMINÉ AVEC SUCCÈS !${NC}"
    echo "============================================================"
    echo ""
    echo "📦 Livrable généré :"
    echo "   ${DIST_DIR}/${OUTPUT_NAME}.bin"
    echo ""
    echo "🚀 Lancement :"
    echo "   cd ${DIST_DIR}"
    echo "   sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ${OUTPUT_NAME}.bin"
    echo "   ./${OUTPUT_NAME}.bin"
    echo ""
    echo "   Ou utilisez le script de lancement :"
    echo "   ./run_${OUTPUT_NAME}.sh"
    echo ""
    echo "📊 Taille du binaire :"
    ls -lh "${DIST_DIR}/${OUTPUT_NAME}.bin" 2>/dev/null | awk '{print "   " $5 " " $9}'
    echo ""
    echo "🔐 Protections appliquées :"
    echo "   ✅ PyArmor (obfuscation niveau 5)"
    echo "   ✅ Nuitka (compilation C standalone)"
    if [ "${HAS_UPX}" = true ]; then
        echo "   ✅ UPX (compression + brouillage)"
    fi
    echo ""
    echo "📁 Fichiers de données requis (à distribuer avec le binaire) :"
    echo "   - .env (configuration)"
    echo "   - config/*.json"
    echo "   - models/data/*.pkl (modèles pré-entraînés)"
    echo "   - reaction/data/locator/*.mmdb (géolocalisation)"
    echo ""
    echo "============================================================"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    echo "============================================================"
    echo -e "${BLUE}🛡️  SHIELD AI IDS/IPS - BUILD COMPLET${NC}"
    echo "============================================================"
    echo ""

    check_dependencies
    clean_build
    build_pyarmor
    build_nuitka
    build_upx
    create_launcher
    show_summary
}

# Lancer le build
main "$@"
