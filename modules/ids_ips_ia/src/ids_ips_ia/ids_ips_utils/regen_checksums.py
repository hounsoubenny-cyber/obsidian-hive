#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug 27 08:15:45 2026

@author: hounsousamuel
"""

"""
Nettoie les anciens fichiers checksum (.sha256, .sha256_<chemin complet>...)
et régénère un .sha_<nom_du_modele> propre pour chaque model_*.pkl présent.

Usage:
    python3 regen_checksums.py /chemin/vers/models/data/models
"""

import sys
import os
import glob
import hashlib

from ids_ips_ia.ids_ips_utils.loader import checksum_path_for  # réutilise la même logique que save()/load()


def regen_checksums(models_dir: str, dry_run: bool = True):
    models_dir = os.path.abspath(models_dir)
    model_files = sorted(glob.glob(os.path.join(models_dir, "*.pkl")))

    if not model_files:
        print(f"⚠️  Aucun .pkl trouvé dans {models_dir}")
        return

    # 1) Supprimer TOUS les anciens fichiers checksum, peu importe leur format
    old_checksums = [
        f for f in glob.glob(os.path.join(models_dir, ".sha*"))
    ]
    print(f"=== {len(old_checksums)} ancien(s) fichier(s) checksum trouvé(s) ===")
    for f in old_checksums:
        if dry_run:
            print(f"  [DRY RUN] rm {f}")
        else:
            os.remove(f)
            print(f"  🗑️  supprimé : {f}")

    # 2) Recalculer et écrire un checksum propre pour chaque modèle
    print(f"\n=== Régénération pour {len(model_files)} modèle(s) ===")
    for model_path in model_files:
        with open(model_path, "rb") as f:
            data = f.read()
        checksum = hashlib.sha256(data).hexdigest()
        checksum_path = checksum_path_for(model_path)

        if dry_run:
            print(f"  [DRY RUN] {os.path.basename(checksum_path)}  <-  {os.path.basename(model_path)}")
        else:
            with open(checksum_path, "w") as f:
                f.write(checksum)
            print(f"  ✅ {os.path.basename(checksum_path)}")

    print("\nTerminé." + ("  (dry_run=True, rien n'a été modifié)" if dry_run else ""))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 regen_checksums.py /chemin/vers/models/data/models [--apply]")
        sys.exit(1)

    target_dir = sys.argv[1]
    apply = "--apply" in sys.argv
    regen_checksums(target_dir, dry_run=not apply)