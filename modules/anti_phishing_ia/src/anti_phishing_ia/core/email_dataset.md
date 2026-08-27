#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 13 15:14:06 2026

@author: hounsousamuel
"""

Voilà les chiffres exacts :

| Dataset | Échantillons | Format | Lien |
|---|---|---|---|
| **Enron Spam Data** (Kaggle) | **33 716** (17 171 spam + 16 545 ham) | CSV propre | https://www.kaggle.com/datasets/marcelwiechmann/enron-spam-data |
| **Phishing Email Dataset** (Kaggle all-in-one) | **~18 000** mails uniquement | CSV | https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset |
| **190K+ Spam/Ham** (Kaggle) | **190 000+** | CSV | https://www.kaggle.com/datasets/meruvulikith/190k-spam-ham-email-dataset-for-classification |
| **ealvaradob/phishing-dataset** (HuggingFace) | **~18 000** mails + 800K URLs + 80K sites + 5K SMS — total 1.7GB | colonnes `text`/`label` | https://huggingface.co/datasets/ealvaradob/phishing-dataset |

**Recommandation concrète pour toi :**

Prends le **Enron Spam (33K)** + **ealvaradob mails uniquement (18K)** = ~50K mails bien équilibrés. C'est au-dessus de ton seuil "bon modèle" de 20K et évite le bruit des URLs/HTML du combined full.

Pour charger uniquement les mails du HuggingFace :
```python
from datasets import load_dataset
dataset = load_dataset("ealvaradob/phishing-dataset", "emails", trust_remote_code=True)
```