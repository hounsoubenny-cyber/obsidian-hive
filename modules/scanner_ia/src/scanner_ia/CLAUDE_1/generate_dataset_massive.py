#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   GÉNÉRATION DATASET MASSIF - ShieldAI V2                                   ║
║   Scanne 20 serveurs → Génère dataset ML avec features + labels              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   Input:  20 serveurs Flask (ports 5001-5020)                               ║
║   Output: dataset_X.csv (features) + dataset_y.csv (labels)                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   Usage: python generate_dataset.py                                         ║
║   Durée: ~2-3 heures pour scanner 300 URLs                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import asyncio
import pandas as pd
from datetime import datetime

# Ajuster path pour importer le scanner
SCANNER_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, SCANNER_PATH)

from main_scanner import Scanner
from ml_model.features_extractor import FeatureExtractor

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

GROUND_TRUTH_FILE = "./servers_generated/ground_truth.json"
SCANNER_CONFIG = "/home/hounsousamuel/PROJET/ShieldIA_v2/scanner_ia/shieldai_scanner.config.json5"

OUTPUT_DIR = "dataset_generated"
OUTPUT_X = os.path.join(OUTPUT_DIR, "dataset_X.csv")
OUTPUT_Y = os.path.join(OUTPUT_DIR, "dataset_y.csv")
OUTPUT_STATS = os.path.join(OUTPUT_DIR, "generation_stats.json")

# 19 types de vulnérabilités + SAFE
ALL_LABELS = [
    "BufOvr",
    "CMDi",
    "CRLF_Injection",
    "CredsExpose",
    "DirTrav",
    "GraphQLi",
    "InfoDisc",
    "InsecDeser",
    "InsecPerm",
    "JWT",
    "NoSQLi",
    "Prototype_Pollution",
    "RateLimit",
    "SQLi",
    "SSRF",
    "SSTI",
    "SessFix",
    "XSS",
    "XXE",
    "SAFE"
]

# ══════════════════════════════════════════════════════════════════════════════
# FONCTIONS DE GÉNÉRATION
# ══════════════════════════════════════════════════════════════════════════════

def load_ground_truth():
    """Charge le fichier ground_truth.json"""
    print(f"📂 Chargement ground truth: {GROUND_TRUTH_FILE}")
    
    if not os.path.exists(GROUND_TRUTH_FILE):
        raise FileNotFoundError(
            f"Ground truth file not found: {GROUND_TRUTH_FILE}\n"
            "Run generate_all_servers.py first!"
        )
    
    with open(GROUND_TRUTH_FILE, 'r') as f:
        ground_truth = json.load(f)
    
    print(f"  ✅ {len(ground_truth)} URLs chargées")
    return ground_truth

def get_base_urls_by_port():
    """Retourne liste des URLs de base par port"""
    base_urls = []
    for port in range(5001, 5021):  # 5001-5020
        base_urls.append(f"http://localhost:{port}")
    return base_urls

async def scan_server(base_url, scanner, ground_truth):
    """Scanne un serveur et retourne features + labels"""
    print(f"\n🔍 Scanning {base_url}...")
    
    try:
        # Scan complet du serveur
        result = await scanner.scan(
            url=base_url,
            allowed_domains=[base_url, "http://localhost"],
            use_cache=False,
            put_result_in_cache=False
        )
        
        # Extraire les features (Phase 5)
        features_data = result.phases_result.get("features_extraction", [])
        
        if not features_data:
            print(f"  ⚠️  Aucune feature extraite pour {base_url}")
            return None, None
        
        # Convertir en DataFrame
        if isinstance(features_data, list):
            df_features = pd.DataFrame(features_data)
        else:
            df_features = features_data  # Déjà un DataFrame
        
        # Créer les labels depuis ground_truth
        labels_list = []
        for _, row in df_features.iterrows():
            url = row.get('url', '')
            
            # Chercher dans ground_truth
            true_vulns = ground_truth.get(url, ["UNKNOWN"])
            
            # Créer vecteur de labels (one-hot encoding)
            label_vector = {vuln: (vuln in true_vulns) for vuln in ALL_LABELS}
            labels_list.append(label_vector)
        
        df_labels = pd.DataFrame(labels_list)
        
        print(f"  ✅ {len(df_features)} samples extraits")
        return df_features, df_labels
        
    except Exception as e:
        print(f"  ❌ Erreur lors du scan de {base_url}: {str(e)}")
        import traceback
        traceback.print_exc()
        return None, None

async def generate_dataset():
    """Génère le dataset complet"""
    
    print("="*80)
    print("🔥 GÉNÉRATION DATASET MASSIF - ShieldAI V2")
    print("="*80)
    
    # Créer dossier de sortie
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Charger ground truth
    ground_truth = load_ground_truth()
    
    # Initialiser le scanner
    print(f"\n🔧 Initialisation du scanner...")
    scanner = Scanner(
        config_path=SCANNER_CONFIG,
        active_scan=True,
        use_cache=False,
        debug=False,
        semaphore=50,
        use_semantic=True
    )
    print(f"  ✅ Scanner prêt")
    
    # Obtenir liste des serveurs
    base_urls = get_base_urls_by_port()
    print(f"\n📋 {len(base_urls)} serveurs à scanner (ports 5001-5020)")
    
    # Scanner tous les serveurs
    all_features = []
    all_labels = []
    
    start_time = datetime.now()
    
    for i, base_url in enumerate(base_urls, 1):
        print(f"\n{'='*80}")
        print(f"📊 Progression: {i}/{len(base_urls)} serveurs")
        print(f"{'='*80}")
        
        features, labels = await scan_server(base_url, scanner, ground_truth)
        
        if features is not None and labels is not None:
            all_features.append(features)
            all_labels.append(labels)
    
    # Combiner tous les DataFrames
    print("\n" + "="*80)
    print("🔄 Combinaison de tous les résultats...")
    print("="*80)
    
    if not all_features:
        print("❌ Aucune donnée générée !")
        return
    
    final_X = pd.concat(all_features, ignore_index=True)
    final_y = pd.concat(all_labels, ignore_index=True)
    
    # Sauvegarder
    print(f"\n💾 Sauvegarde des datasets...")
    final_X.to_csv(OUTPUT_X, index=False)
    final_y.to_csv(OUTPUT_Y, index=False)
    
    # Statistiques
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    stats = {
        "total_samples": len(final_X),
        "total_features": len(final_X.columns),
        "total_labels": len(final_y.columns),
        "servers_scanned": len(base_urls),
        "duration_seconds": duration,
        "duration_human": f"{duration//3600:.0f}h {(duration%3600)//60:.0f}m {duration%60:.0f}s",
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "label_distribution": final_y.sum().to_dict()
    }
    
    with open(OUTPUT_STATS, 'w') as f:
        json.dump(stats, f, indent=2)
    
    # Affichage final
    print("\n" + "="*80)
    print("✅ GÉNÉRATION DATASET TERMINÉE !")
    print("="*80)
    print(f"\n📊 Statistiques finales:")
    print(f"  • Total samples: {stats['total_samples']:,}")
    print(f"  • Total features: {stats['total_features']}")
    print(f"  • Total labels: {stats['total_labels']}")
    print(f"  • Serveurs scannés: {stats['servers_scanned']}")
    print(f"  • Durée totale: {stats['duration_human']}")
    
    print(f"\n📁 Fichiers générés:")
    print(f"  • Features: {OUTPUT_X}")
    print(f"  • Labels: {OUTPUT_Y}")
    print(f"  • Stats: {OUTPUT_STATS}")
    
    print(f"\n📈 Distribution des labels:")
    for label, count in sorted(stats['label_distribution'].items(), key=lambda x: -x[1])[:10]:
        print(f"  • {label:20s}: {count:>6,} samples")
    
    print("\n" + "="*80)
    print("🚀 Dataset prêt pour entraînement ML !")
    print("="*80)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("\n🔥 ShieldAI V2 - Dataset Generation")
    print("⚠️  Assurez-vous que tous les serveurs sont lancés (./start_all.sh)")
    print("\nAppuyez sur ENTRÉE pour continuer ou CTRL+C pour annuler...")
    try:
        input()
    except KeyboardInterrupt:
        print("\n❌ Annulé par l'utilisateur")
        sys.exit(0)
    
    asyncio.run(generate_dataset())
