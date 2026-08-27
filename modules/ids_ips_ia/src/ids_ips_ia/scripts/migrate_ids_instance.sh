#!/usr/bin/env bash
set -euo pipefail

# ── À adapter si besoin ──────────────────────────────────────────────
ROOT="/home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/src/ids_ips_ia"
SUFFIX="5d8ceaf9ee"   # dernier -10 de sh_as-000423b8-6b77-45ee-871b-525d8ceaf9ee
DRY_RUN=false          # passe à false pour vraiment déplacer les fichiers
# ──────────────────────────────────────────────────────────────────────

move() {
    local src="$1"
    local dst="$2"
    if [ ! -e "$src" ]; then
        echo "  ⏭️  absent, skip : $src"
        return
    fi

    # Si src est un dossier et dst est un sous-dossier de src, on copie le contenu
    if [ -d "$src" ] && [[ "$dst" == "$src"/* ]]; then
        # Créer le dossier de destination
        mkdir -p "$dst"
        if [ "$DRY_RUN" = true ]; then
            echo "  [DRY RUN] cp -r '$src'/* -> '$dst/'"
        else
            # Copier le contenu, pas le dossier lui-même
            cp -r "$src"/* "$dst/" 2>/dev/null || true
            echo "  ✅ copier : $src/* -> $dst/"
        fi
        return
    fi

    mkdir -p "$(dirname "$dst")"
    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] cp -r '$src' -> '$dst'"
    else
        cp -r "$src" "$dst"
        echo "  ✅ copier : $src -> $dst"
    fi
}

echo "=== Migration vers instance $SUFFIX ==="
echo "(DRY_RUN=$DRY_RUN — repasse à false dans le script une fois vérifié)"
echo ""

echo "--- reaction (history / whitelist / nft) ---"
move "$ROOT/reaction/data/history"   "$ROOT/reaction/data/$SUFFIX/history"
move "$ROOT/reaction/data/whitelist" "$ROOT/reaction/data/$SUFFIX/whitelist"
move "$ROOT/reaction/data/nft"       "$ROOT/reaction/data/$SUFFIX/nft"
echo "  (locator/ NON déplacé — reste partagé, contient GeoLite2)"
echo ""

echo "--- detection (anomalies + scores IP) ---"
move "$ROOT/detection/data/anomalies"         "$ROOT/detection/data/$SUFFIX/anomalies"
move "$ROOT/detection/data/historique_score"  "$ROOT/detection/data/$SUFFIX/historique_score"
echo ""

echo "--- models (modèle entraîné) ---"
# ✅ CORRECTION : copier le CONTENU de models/, pas le dossier lui-même
move "$ROOT/models/data/models" "$ROOT/models/data/models/$SUFFIX"
echo ""

echo "--- refit_system (queue de ré-entraînement) ---"
move "$ROOT/refit_system/data/refit_data" "$ROOT/refit_system/data/$SUFFIX/refit_data"
echo ""

echo "--- core (dumps de capture) ---"
move "$ROOT/core/data" "$ROOT/core/data_bak_pre_instance_$SUFFIX"
echo "  (déplacé en backup — capture.py recréera un data/$SUFFIX/ propre au prochain run)"
echo ""

echo "=== Terminé ==="
