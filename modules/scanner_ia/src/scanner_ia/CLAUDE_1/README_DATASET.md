# 🔥 GÉNÉRATION DATASET MASSIF - ShieldAI V2

**Génération automatique d'un dataset complet pour entraînement ML**

---

## 📊 VUE D'ENSEMBLE

Ce système génère automatiquement :
- **20 serveurs Flask** (19 vulnérables + 1 safe)
- **~300 URLs** à scanner  
- **Dataset ML** avec features (96) + labels (20)
- **Ground truth** 100% fiable

---

## 🚀 UTILISATION RAPIDE (3 COMMANDES)

```bash
# 1. Générer les 20 serveurs
python3 generate_all_servers.py

# 2. Lancer tous les serveurs (ports 5001-5020)
cd servers_generated
./start_all.sh

# 3. Générer le dataset (2-3h)
cd ..
python3 generate_dataset_massive.py
```

**C'EST TOUT ! Dataset prêt dans `dataset_generated/`**

---

## 📁 STRUCTURE FICHIERS

```
.
├── generate_all_servers.py      # Génère les 20 serveurs
├── generate_dataset_massive.py  # Scanne et génère dataset
│
├── servers_generated/           # Serveurs générés
│   ├── server_bufovr.py        # Port 5001
│   ├── server_cmdi.py          # Port 5002
│   ├── ...                     # Ports 5003-5019
│   ├── server_safe.py          # Port 5020
│   ├── ground_truth.json       # Mapping URL→vulns
│   ├── start_all.sh            # Lance tous les serveurs
│   └── stop_all.sh             # Arrête tous les serveurs
│
└── dataset_generated/           # Dataset final
    ├── dataset_X.csv           # Features (96 colonnes)
    ├── dataset_y.csv           # Labels (20 colonnes)
    └── generation_stats.json   # Statistiques
```

---

## 🎯 LES 20 TYPES DE DONNÉES

### 19 Vulnérabilités
1. **BufOvr** - Buffer Overflow
2. **CMDi** - Command Injection
3. **CRLF_Injection** - CRLF Injection
4. **CredsExpose** - Credentials Exposure
5. **DirTrav** - Directory Traversal
6. **GraphQLi** - GraphQL Injection
7. **InfoDisc** - Information Disclosure
8. **InsecDeser** - Insecure Deserialization
9. **InsecPerm** - Insecure Permissions
10. **JWT** - JWT Vulnerabilities
11. **NoSQLi** - NoSQL Injection
12. **Prototype_Pollution** - Prototype Pollution
13. **RateLimit** - Rate Limiting Issues
14. **SQLi** - SQL Injection
15. **SSRF** - Server-Side Request Forgery
16. **SSTI** - Server-Side Template Injection
17. **SessFix** - Session Fixation
18. **XSS** - Cross-Site Scripting
19. **XXE** - XML External Entity

### 1 Label SAFE
20. **SAFE** - Aucune vulnérabilité

---

## 📊 DATASET ATTENDU

```python
dataset_specs = {
    "Total samples": "~120,000",
    "Features": "96 colonnes (features_extractor.py)",
    "Labels": "20 colonnes (19 vulns + SAFE)",
    
    "Répartition": {
        "Vulns": "~60,000 samples (50%)",
        "SAFE": "~60,000 samples (50%)"
    },
    
    "Format": "CSV (pandas compatible)",
    
    "Ground truth": "100% fiable (serveurs générés)"
}
```

---

## 🛠️ DÉTAILS TECHNIQUES

### Serveurs générés (20 total)

Chaque serveur a :
- **10-15 endpoints vulnérables** (pour sa vuln spécifique)
- **2 endpoints safe** (pour diversité)
- **Port dédié** (5001-5020)

Exemple serveur CMDi (port 5002) :
```
/ping?host=localhost      → Vulnérable CMDi
/exec?cmd=whoami          → Vulnérable CMDi
/system?command=ls        → Vulnérable CMDi
...
/safe1                    → SAFE
/safe2                    → SAFE
```

### Ground Truth

Fichier `ground_truth.json` :
```json
{
  "http://localhost:5001/format?data=test": ["BufOvr"],
  "http://localhost:5002/ping?host=localhost": ["CMDi"],
  "http://localhost:5020/api/endpoint1": ["SAFE"],
  ...
}
```

### Génération Dataset

Le script `generate_dataset_massive.py` :

1. **Charge ground_truth.json**
2. **Pour chaque serveur (5001-5020)** :
   - Scanne avec ShieldAI V2
   - Extrait features (96 features via features_extractor.py)
   - Labellise avec ground_truth
3. **Combine tous les résultats**
4. **Sauvegarde** :
   - `dataset_X.csv` (features)
   - `dataset_y.csv` (labels one-hot encoded)

---

## 🚀 UTILISATION AVANCÉE

### 1. Vérifier les serveurs

```bash
# Vérifier qu'un serveur répond
curl http://localhost:5001/

# Tester endpoint vulnérable
curl "http://localhost:5002/ping?host=localhost"

# Vérifier tous les serveurs
for port in {5001..5020}; do
    curl -s http://localhost:$port/ > /dev/null && echo "Port $port: OK" || echo "Port $port: FAIL"
done
```

### 2. Génération progressive

Si tu veux générer dataset par étapes :

```python
# Scanner un seul serveur
python3 -c "
import asyncio
from generate_dataset_massive import scan_server, load_ground_truth
from main_scanner import Scanner

async def test():
    gt = load_ground_truth()
    scanner = Scanner('shieldai_scanner.config.json5')
    X, y = await scan_server('http://localhost:5001', scanner, gt)
    print(f'Samples: {len(X)}')

asyncio.run(test())
"
```

### 3. Arrêter les serveurs

```bash
cd servers_generated
./stop_all.sh

# Ou manuellement
pkill -f "python3 server_"
```

---

## 🎯 WORKFLOW COMPLET

```
┌─────────────────────────────────────────────────────────┐
│ 1. GÉNÉRATION SERVEURS                                  │
│    python3 generate_all_servers.py                      │
│    Output: 20 fichiers .py + ground_truth.json          │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 2. LANCEMENT SERVEURS                                   │
│    cd servers_generated && ./start_all.sh               │
│    20 serveurs Flask sur ports 5001-5020                │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 3. GÉNÉRATION DATASET                                   │
│    python3 generate_dataset_massive.py                  │
│    Scanne 300 URLs → Extrait features → Labellise       │
│    Durée: 2-3 heures                                    │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 4. DATASET PRÊT !                                       │
│    dataset_generated/dataset_X.csv (features)           │
│    dataset_generated/dataset_y.csv (labels)             │
│    → Ready pour ML training !                           │
└─────────────────────────────────────────────────────────┘
```

---

## 🔧 TROUBLESHOOTING

### Problème : Serveurs ne démarrent pas

```bash
# Vérifier ports occupés
netstat -tulpn | grep 500

# Libérer ports
pkill -f "python3 server_"
```

### Problème : Génération dataset échoue

```bash
# Vérifier que tous les serveurs répondent
for port in {5001..5020}; do
    curl -s http://localhost:$port/ && echo "✅ Port $port OK"
done

# Relancer un serveur spécifique
cd servers_generated
python3 server_cmdi.py  # Exemple
```

### Problème : Pas assez de RAM

Modifier dans `generate_dataset_massive.py` :
```python
# Ligne ~40
scanner = Scanner(
    config_path=SCANNER_CONFIG,
    semaphore=20,  # Réduire de 50 → 20
    ...
)
```

---

## 📈 APRÈS GÉNÉRATION

### 1. Vérifier le dataset

```python
import pandas as pd

# Charger
X = pd.read_csv('dataset_generated/dataset_X.csv')
y = pd.read_csv('dataset_generated/dataset_y.csv')

print(f"Samples: {len(X)}")
print(f"Features: {X.shape[1]}")
print(f"Labels: {y.shape[1]}")

# Distribution labels
print("\nDistribution:")
print(y.sum().sort_values(ascending=False))
```

### 2. Entraîner le modèle

```python
from ml_model.scanner_ia_v2 import ScannerIA

# Init
scanner_ia = ScannerIA()

# Train
scanner_ia.fit(X, y)

# Save
scanner_ia.save_model()

print("✅ Modèle entraîné et sauvegardé !")
```

---

## ⏱️ TEMPS ESTIMÉS

| Étape | Durée |
|-------|-------|
| Générer serveurs | 5 secondes |
| Lancer serveurs | 10 secondes |
| Générer dataset | **2-3 heures** |
| **TOTAL** | **~3 heures** |

---

## 🎯 RÉSULTAT FINAL

Après ces 3 commandes, tu as :

✅ **20 serveurs de test** (réutilisables)  
✅ **Dataset ML complet** (~120k samples)  
✅ **Ground truth fiable** (100%)  
✅ **Ready pour training** (sklearn compatible)

**Plus de blocage sur les données ! 🚀**

---

## 📞 SUPPORT

Si problème :
1. Vérifie que tous les serveurs répondent
2. Vérifie RAM disponible (>4GB recommandé)
3. Réduis `semaphore` si trop lent
4. Check logs dans `logs/`

---

**Créé pour ShieldAI V2 - Samuel Hounsou - 2026**
