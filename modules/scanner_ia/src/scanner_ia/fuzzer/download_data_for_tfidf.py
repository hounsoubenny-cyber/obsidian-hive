#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 31 12:36:27 2026

@author: hounsousamuel
"""

import os
import json
import time
import zstandard as zstd
from datasets import load_dataset


def download_and_save_to_drive(output_dir: str):
    """Télécharge un échantillon HTML/PHP/CSS/MD/JS depuis
    ruediste/codeparrot-github-code-10G, filtré par langage, et sauvegarde
    IMMÉDIATEMENT après chaque langue (pas à la toute fin) pour ne rien
    perdre si Kaggle coupe la session en cours de route.
    """
    os.makedirs(output_dir, exist_ok=True)

    configs = [
        {"lang": "html", "max": 70_000, "name": "HTML"},
        {"lang": "php",  "max": 50_000, "name": "PHP"},
        {"lang": "css",  "max": 40_000, "name": "CSS"},
        {"lang": "md",   "max": 50_000, "name": "Markdown"},
        {"lang": "js",   "max": 50_000, "name": "JavaScript"},
    ]

    start_total = time.time()
    all_counts = {}

    for cfg in configs:
        lang_id = cfg["lang"]
        target_count = cfg["max"]
        label = cfg["name"]

        print(f"\n⏳ Récupération de {target_count} fichiers {label} (streaming direct)...")

        ds = load_dataset(
            "ruediste/codeparrot-github-code-10G",
            lang_id,
            split="train",
            streaming=True,
        )

        lang_data = []
        count = 0
        start_lang = time.time()

        for item in ds:
            code = item.get("code") or item.get("content") or ""

            if lang_id == "html":
                if "<html" in code.lower() and "<body" in code.lower():
                    lang_data.append(code)
                    count += 1
            elif lang_id in ["js", "php"]:
                if "{" in code and '"' in code and len(code) > 150:
                    lang_data.append(code)
                    count += 1
            elif lang_id == "css":
                if len(code) > 80 and "{" in code:
                    lang_data.append(code)
                    count += 1
            elif lang_id == "md":
                if len(code) > 80:
                    lang_data.append(code)
                    count += 1

            if count > 0 and count % 10000 == 0:
                print(f"  -> {count}/{target_count} {label} extraits ({time.time() - start_lang:.1f}s)")

            if count >= target_count:
                break

        elapsed_lang = time.time() - start_lang
        print(f"✅ {count} {label} récupérés avec succès en {elapsed_lang:.1f}s.")
        all_counts[label] = count

        out_path_lang = os.path.join(output_dir, f"corpus_{lang_id}.json.zst")
        json_bytes = json.dumps(lang_data).encode("utf-8")
        compressed = zstd.compress(json_bytes, level=9)

        with open(out_path_lang, "wb") as f:
            f.write(compressed)

        size_mb = len(compressed) / (1024 * 1024)
        print(f"📦 {label} sauvegardé : {out_path_lang} ({size_mb:.1f} Mo)")

    total_elapsed = time.time() - start_total
    total_docs = sum(all_counts.values())
    print(f"\n🎉 TOTAL : {total_docs} documents extraits en {total_elapsed:.1f}s !")
    print("📊 Détail par langue :")
    for label, count in all_counts.items():
        print(f"  • {label:<12} : {count}")

    return all_counts


def merge_corpus_files(output_dir: str, merged_path: str):
    """Recombine les corpus_<lang>.json.zst individuels en un seul fichier,
    une fois toutes les langues téléchargées avec succès.
    """
    all_data = []
    for fname in sorted(os.listdir(output_dir)):
        if fname.startswith("corpus_") and fname.endswith(".json.zst"):
            path = os.path.join(output_dir, fname)
            with open(path, "rb") as f:
                data = json.loads(zstd.decompress(f.read()).decode("utf-8"))
            all_data.extend(data)
            print(f"  • {fname} : +{len(data)} documents")

    json_bytes = json.dumps(all_data).encode("utf-8")
    compressed = zstd.compress(json_bytes, level=9)  
    with open(merged_path, "wb") as f:
        f.write(compressed)

    size_mb = len(compressed) / (1024 * 1024)
    print(f"\n✅ Fusionné : {len(all_data)} documents -> {merged_path} ({size_mb:.1f} Mo)")
    return all_data


if __name__ == "__main__":
    OUTPUT_DIR = "/kaggle/working/corpus_parts"
    MERGED_FILE = "/content/drive/MyDrive/corpus_tfidf_web.json.zst"  # adapte le chemin Drive

    counts = download_and_save_to_drive(OUTPUT_DIR)
    merge_corpus_files(OUTPUT_DIR, MERGED_FILE)