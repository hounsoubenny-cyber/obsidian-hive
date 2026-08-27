#!/usr/bin/env bash
# migrate_modules_to_packages.sh
#
# Transforme chaque module de ~/PROJET/obsidian_hive/modules/ en package
# installable indépendant :
#   modules/<nom>/  ->  modules/<nom>/pyproject.toml
#                       modules/<nom>/src/<nom>/  (tout le code actuel, déplacé ici)
#
# USAGE (à lancer DEPUIS ~/PROJET/obsidian_hive/modules) :
#   ./migrate_modules_to_packages.sh            # dry-run : affiche ce qui SERAIT fait
#   DRY_RUN=0 ./migrate_modules_to_packages.sh   # exécution réelle
#
# ⚠️ Avant de lancer en DRY_RUN=0 : assure-toi que ton git est propre
# (git status) pour pouvoir tout annuler avec `git checkout .` / `git reset`
# si jamais un truc te déplaît après coup.

set -euo pipefail

MODULES=(
    "modules_utils"
    "ids_ips_ia"
    "anti_phishing_ia"
    "contextguard"
    "deepfake_detector"
    "sandbox_ia"
    "scanner_ia"
    "simulateur_attaque_ia"
)
# Exclus volontairement : cyber_learn, MODEL_SHARED (pas concernés par cette migration)

BASE_DIR="$(pwd)"
DRY_RUN="${DRY_RUN:-1}"

log() { printf "[%s] %s\n" "$1" "$2"; }

pkg_name_hyphen() {
    # convention PyPI : tirets plutôt que underscores dans le nom du package
    echo "$1" | tr '_' '-'
}

is_git_repo() {
    git -C "$BASE_DIR" rev-parse --is-inside-work-tree > /dev/null 2>&1
}

move_item() {
    local src="$1" dst="$2"
    if [ "$DRY_RUN" = "1" ]; then
        log "DRY" "déplacer '$src' -> '$dst'"
        return
    fi
    if is_git_repo && git -C "$BASE_DIR" ls-files --error-unmatch "$src" > /dev/null 2>&1; then
        git mv "$src" "$dst"
    else
        mv "$src" "$dst"
    fi
}

log "INFO" "Racine : $BASE_DIR"
log "INFO" "Mode   : $([ "$DRY_RUN" = "1" ] && echo 'DRY-RUN (rien ne sera modifié)' || echo 'EXÉCUTION RÉELLE')"
echo

for module in "${MODULES[@]}"; do
    module_dir="${BASE_DIR}/${module}"

    if [ ! -d "$module_dir" ]; then
        log "SKIP" "$module : dossier introuvable ($module_dir)"
        continue
    fi

    if [ -f "${module_dir}/pyproject.toml" ]; then
        log "SKIP" "$module : pyproject.toml existe déjà (déjà migré ?)"
        continue
    fi

    if [ -d "${module_dir}/src" ]; then
        log "SKIP" "$module : src/ existe déjà (migration déjà en cours ?)"
        continue
    fi

    log "INFO" "=== $module ==="

    src_pkg_dir="${module_dir}/src/${module}"

    if [ "$DRY_RUN" = "1" ]; then
        log "DRY" "mkdir -p '$src_pkg_dir'"
    else
        mkdir -p "$src_pkg_dir"
    fi

    shopt -s dotglob nullglob
    for item in "$module_dir"/*; do
        base_item="$(basename "$item")"

        # Ne jamais se déplacer soi-même
        [ "$base_item" = "src" ] && continue
        [ "$base_item" = "pyproject.toml" ] && continue

        # __pycache__ : pas la peine de le déplacer, il se régénère
        if [ "$base_item" = "__pycache__" ]; then
            if [ "$DRY_RUN" = "1" ]; then
                log "DRY" "supprimer '$item' (cache, inutile à garder)"
            else
                rm -rf "$item"
            fi
            continue
        fi

        move_item "$item" "$src_pkg_dir/"
    done
    shopt -u dotglob nullglob

    init_file="${src_pkg_dir}/__init__.py"
    if [ "$DRY_RUN" = "1" ]; then
        log "DRY" "touch '$init_file' (si absent)"
    else
        [ -f "$init_file" ] || touch "$init_file"
    fi

    pkg_hyphen="$(pkg_name_hyphen "$module")"
    pyproject_content="[build-system]
requires = [\"setuptools>=68\"]
build-backend = \"setuptools.build_meta\"

[project]
name = \"${pkg_hyphen}\"
version = \"0.1.0\"
requires-python = \">=3.11\"
dependencies = [
    # ⚠️ À remplir : dépendances propres à ce module
]

[tool.setuptools.packages.find]
where = [\"src\"]
"

    if [ "$DRY_RUN" = "1" ]; then
        log "DRY" "écrire ${module_dir}/pyproject.toml (name=\"${pkg_hyphen}\")"
    else
        printf "%s" "$pyproject_content" > "${module_dir}/pyproject.toml"
    fi

    log "OK" "$module migré"
    echo
done

log "INFO" "Terminé."
if [ "$DRY_RUN" = "1" ]; then
    log "INFO" "C'était un dry-run. Relance avec : DRY_RUN=0 ./migrate_modules_to_packages.sh"
fi
