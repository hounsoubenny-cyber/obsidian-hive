# Rapport de profilage IDS/IPS — 2026-10-06 20:20:35

- **Base des chiffres : CPU réel** (noyau, `/proc`) : **712.4 s** de CPU pour **364 s** de fenêtre = **1.96 cœur(s)** en moyenne. py-spy sert à **répartir** ce CPU par fonction, thread et étape. Pourcentages = part du CPU réel total.
- **Confiance de la mesure : 🔴 faible** (5 avertissement(s), voir ci-dessous).

## 🧪 Fiabilité de la mesure

- ✅ py-spy filtre les threads en attente d'après l'état OS (pas de `--idle`).
- ⚠️ « actif » py-spy = 519 s pour 376 s de CPU réel (×1.38). py-spy compte des **attentes comme du calcul** (corrigé par le recalage).
- ⚠️ **2 thread(s) « actifs » pour py-spy mais quasi sans CPU = en attente** (réseau/DNS/verrou…) : `-2 (_monitor)"` (123 s « actif » vs 58.2 s de CPU), `733901 "Capture-veth_rx"` (88 s « actif » vs 50.9 s de CPU). Ils sont neutralisés dans les tables.
- ⚠️ 35 thread(s) vus par py-spy ont disparu de /proc avant la fin de la fenêtre (leur CPU est compté dans « threads terminés »).
- ✅ fenêtre CPU (364 s) alignée sur celle de py-spy (364 s).
- ✅ machine à 61 % de CPU (IDS 2.0 cœur, générateur 0.2, py-spy 0.8 · 12 cœurs au total) : pas de famine de CPU.
- ⚠️ py-spy a eu 1 erreur(s) de lecture sur 41776 échantillons : stacks incomplètes ignorées.
- ✅ fenêtre de 364 s.
- ✅ 36 350 échantillons actifs.
- ✅ débit capturé stable à l'attache de py-spy (1 000 → 1 014 pkt/s).
- ⚠️ fichiers source introuvables pour une partie des frames : les `time.sleep`/`wait` ne peuvent pas être repérés par leur ligne. Relance l'analyse sur la machine qui a profilé.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (CPU réel, feuille) : **⟨threads natifs hors Python : BLAS / TF / OpenMP…⟩** (45.3 %)
- Étape du pipeline la plus coûteuse : **blocage nft (_run_command / block)** (11.4 %)
- Inférence (paquet + séquence) : **73 s (CPU réel) sur 364 s** de fenêtre (≈ 0.20 cœur) → le consommateur n'est pas saturé.
- 💡 Les logs coûtent cher → niveau WARNING en production / pendant les benchs, ou logger via une queue asynchrone.
- 💡 Les commandes nft sont bloquantes dans la boucle → file d'attente dédiée + ne pas re-bloquer une IP déjà bloquée.
- 💡 **45 % du CPU est consommé par des threads NATIFS invisibles pour py-spy** (BLAS/OpenMP/TensorFlow) : voir la table des threads natifs ; `perf top -p <pid>` les détaille.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **7133** → 19.60/s (≈ 392 paquets/s, **estimation** : séquences × stride=20 ; elle ignore les paquets écartés par le skipper)
- Anomalies paquet : 26935 · blocages nft : 7682
- Capture au début : 1 001 pkt/s gardés  pertes 0.0 % (noyau 0 · app 0)
- Capture à la fin : 1 395 pkt/s gardés  pertes 68.5 % (noyau 101 869 · app 2 479 230)
- Capture  moyenne des relevés : 3 124 pkt/s gardés
- ⚠️ La capture garde ~3 124 pkt/s mais seulement ~392 pkt/s arrivent aux séquences : le consommateur ne suit pas (ou le skipper écarte beaucoup de paquets). Compare avec le compteur `pkt_proccessed`.

## 🧱 Étapes du pipeline (inclusif, CPU réel)

| Étape | % du CPU réel | secondes |
|---|---:|---:|
| extract_pack_features (par paquet) |   0.4 % | 2.7 |
| predict_packet (AE + IF + LOF) |   8.2 % | 58.2 |
|   dont IsolationForest (paquet) |   7.6 % | 54.4 |
|   dont LOF (paquet) |   0.3 % | 2.3 |
| extract_seq_features |   0.4 % | 2.9 |
| predict_sequence (CNN + AE + IF + LOF) |   2.1 % | 14.8 |
|   dont IsolationForest (séquence) |   0.3 % | 2.0 |
|   dont LOF (séquence) |   1.2 % | 8.4 |
| AnomalyScorer.detect_pkt (voie lente) |   8.2 % | 58.7 |
| log_anomaly / _add_alert |   0.3 % | 2.1 |
| persistance joblib/pickle (dump) |   0.1 % | 0.7 |
| blocage nft (_run_command / block) |  11.4 % | 81.0 |
| graphes (add_data*) |   0.1 % | 0.7 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| ⟨threads natifs hors Python : BLAS / TF / OpenMP…⟩ |  45.3 % | 322.5 |
| logs / print |  16.4 % | 117.0 |
| réaction nft / subprocess |  11.7 % | 83.3 |
| Python pur (ton code / autre) |   9.3 % | 66.2 |
| capture |   7.6 % | 54.3 |
| asyncio / threads / queue |   1.8 % | 12.9 |
| scoring / corrélation |   1.6 % | 11.5 |
| scikit-learn |   1.5 % | 10.5 |
| ⟨threads terminés pendant la fenêtre⟩ |   1.4 % | 9.8 |
| dpkt (parsing paquets) |   1.0 % | 6.9 |
| TensorFlow / Keras |   0.7 % | 5.1 |
| ⟨threads Python sans échantillon actif⟩ |   0.6 % | 4.5 |
| extraction de features |   0.5 % | 3.5 |
| numpy / scipy |   0.4 % | 2.8 |
| json / pickle / dill / joblib |   0.2 % | 1.6 |

## 🧵 Par thread / process

| Thread | CPU réel (s) | % d'un cœur | py-spy « actif » (s) | statut | fonction la plus chaude |
|---|---:|---:|---:|---|---|
| Process 733780 Thread 733839 "Detection Thread" | 97.3 | 27 % | 115.8 | ✅ | emit (logger.py) |
| Process 733780 Thread 734068 "BlockBatcher" | 80.4 | 22 % | 97.9 | ✅ | cmd (nftables.py) |
| Process 733780 Thread 733785 "Thread-2 (_monitor)" | 58.2 | 16 % | 123.3 | ⚠️ attente comptée active | flush (__init__.py) |
| Process 733780 Thread 733901 "Capture-veth_rx" | 50.9 | 14 % | 87.7 | ⚠️ attente comptée active | _socket_capture (capture.py) |
| Process 733780 Thread 734025 "asyncio_0" | 41.4 | 11 % | 46.2 | ✅ | _depths (fast_iforest.py) |
| Process 733780 Thread 734073 "asyncio_2" | 22.9 | 6 % | 25.7 | ✅ | _depths (fast_iforest.py) |
| Process 733780 Thread 734067 "asyncio_1" | 16.6 | 5 % | 17.2 | ✅ | _depths (fast_iforest.py) |
| Process 733780 Thread 734069 "AnomalyWriter" | 3.5 | 1 % | 0.6 | ✅ | _write (anomaly_logger.py) |
| Process 733780 Thread 733900 "RefitQueue-save" | 3.5 | 1 % | 4.6 | ✅ | _save (capture.py) |
| Process 733780 Thread 733904 "Dashboard" | 0.7 | 0 % | 0.1 | ✅ | open_binary (_common.py) |
| Process 733780 Thread 736959 "ThreadPoolExecutor-0_0" | 0.2 | 0 % | 0.2 | ✅ | _save (capture.py) |

**Threads natifs (non Python — invisibles pour py-spy sans `--native`)**

| pid / tid | nom OS | CPU réel (s) | % d'un cœur |
|---|---|---:|---:|
| 733780 / 733842 | iou-sqp-733837 | 185.0 | 51 % |
| 733780 / 733856 | python3.11 | 6.6 | 2 % |
| 733780 / 733864 | python3.11 | 6.5 | 2 % |
| 733780 / 733858 | python3.11 | 6.5 | 2 % |
| 733780 / 733859 | python3.11 | 6.5 | 2 % |
| 733780 / 733867 | python3.11 | 6.5 | 2 % |
| 733780 / 733860 | python3.11 | 6.5 | 2 % |
| 733780 / 733865 | python3.11 | 6.5 | 2 % |
| 733780 / 733862 | python3.11 | 6.4 | 2 % |
| 733780 / 733861 | python3.11 | 6.4 | 2 % |

**Par process**

| pid | CPU réel (s) | % d'un cœur |
|---|---:|---:|
| 733780 | 694.0 | 191 % |
| 733925 | 17.5 | 5 % |
| 733841 | 0.6 | 0 % |
| 733880 | 0.3 | 0 % |
| 733922 | 0.0 | 0 % |
| 733852 | 0.0 | 0 % |

## ⏱️ Top 20 fonctions — temps propre (self, CPU réel)

| Fonction | % | s |
|---|---:|---:|
| `cmd` (nftables.py) |  11.2 % | 79.7 |
| `_depths` (fast_iforest.py) |   7.8 % | 55.8 |
| `_socket_capture` (capture.py) |   6.0 % | 42.8 |
| `flush` (__init__.py) |   2.5 % | 18.1 |
| `emit` (logger.py) |   2.3 % | 16.4 |
| `exists` (<frozen genericpath>) |   1.8 % | 12.8 |
| `isfile` (<frozen genericpath>) |   1.5 % | 10.3 |
| `compute` (_dispatcher.py) |   1.4 % | 9.7 |
| `formatTime` (__init__.py) |   0.9 % | 6.5 |
| `shouldRollover` (handlers.py) |   0.9 % | 6.1 |
| `_write_to_self` (selector_events.py) |   0.7 % | 5.1 |
| `_detect_consumer` (detection_module.py) |   0.7 % | 4.9 |
| `_format` (__init__.py) |   0.7 % | 4.7 |
| `quick_execute` (execute.py) |   0.6 % | 4.3 |
| `__init__` (__init__.py) |   0.6 % | 4.2 |
| `_read_from_self` (selector_events.py) |   0.6 % | 4.0 |
| `put` (queue.py) |   0.5 % | 3.5 |
| `_save` (capture.py) |   0.5 % | 3.4 |
| `_write` (anomaly_logger.py) |   0.4 % | 3.2 |
| `format` (__init__.py) |   0.4 % | 3.1 |

## ⏱️ Top 20 fonctions — temps inclusif (CPU réel)

| Fonction | % | s |
|---|---:|---:|
| `run` (threading.py) |  52.7 % | 375.6 |
| `_bootstrap_inner` (threading.py) |  52.7 % | 375.6 |
| `_bootstrap` (threading.py) |  52.7 % | 375.6 |
| `run_until_complete` (nest_asyncio.py) |  13.7 % | 97.3 |
| `run` (nest_asyncio.py) |  13.7 % | 97.3 |
| `_run_async_detection` (orchestrator.py) |  13.7 % | 97.3 |
| `_run_once` (nest_asyncio.py) |  13.6 % | 97.1 |
| `_run` (events.py) |  13.6 % | 96.8 |
| `handle` (__init__.py) |  13.6 % | 96.7 |
| `__wakeup` (tasks.py) |  12.8 % | 91.4 |
| `__step` (tasks.py) |  12.8 % | 91.4 |
| `_worker` (thread.py) |  11.4 % | 81.0 |
| `run` (thread.py) |  11.4 % | 81.0 |
| `_flush` (block_batcher.py) |  11.3 % | 80.4 |
| `_run` (block_batcher.py) |  11.3 % | 80.4 |
| `_commit_bisect` (block_batcher.py) |  11.3 % | 80.4 |
| `_commit` (block_batcher.py) |  11.3 % | 80.4 |
| `_run_command` (reaction_module.py) |  11.3 % | 80.4 |
| `cmd` (nftables.py) |  11.2 % | 79.7 |
| `_detect_consumer` (detection_module.py) |  11.1 % | 78.8 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif (CPU réel)

| Fonction | % | s |
|---|---:|---:|
| `_run_async_detection` (orchestrator.py) |  13.7 % | 97.3 |
| `_flush` (block_batcher.py) |  11.3 % | 80.4 |
| `_run` (block_batcher.py) |  11.3 % | 80.4 |
| `_commit_bisect` (block_batcher.py) |  11.3 % | 80.4 |
| `_commit` (block_batcher.py) |  11.3 % | 80.4 |
| `_run_command` (reaction_module.py) |  11.3 % | 80.4 |
| `_detect_consumer` (detection_module.py) |  11.1 % | 78.8 |
| `_score_batch` (models.py) |   9.4 % | 67.2 |
| `detect_pkt` (anomaly_scorer.py) |   8.2 % | 58.7 |
| `predict_packet_batch` (models.py) |   8.2 % | 58.1 |
| `decision_function` (fast_iforest.py) |   7.9 % | 56.4 |
| `score_samples` (fast_iforest.py) |   7.9 % | 56.4 |
| `_depths` (fast_iforest.py) |   7.9 % | 56.0 |
| `_socket_capture` (capture.py) |   7.1 % | 50.9 |
| `update` (anomaly_scorer.py) |   4.1 % | 29.3 |
| `predict_sequence_batch` (models.py) |   2.1 % | 14.7 |
| `_detect_producer` (detection_module.py) |   1.4 % | 10.2 |
| `_put` (capture.py) |   1.1 % | 8.1 |
| `_drain_entries` (detection_module.py) |   1.0 % | 7.3 |
| `calculate_ip_score_dangerous` (anomaly_scorer.py) |   0.8 % | 5.4 |

## 📍 Top 20 lignes chaudes (CPU réel)

| Ligne | % |
|---|---:|
| `cmd` — nftables.py:410 |  11.1 % |
| `_socket_capture` — capture.py:1003 |   5.2 % |
| `_depths` — fast_iforest.py:98 |   4.6 % |
| `flush` — __init__.py:1094 |   2.5 % |
| `_depths` — fast_iforest.py:99 |   2.2 % |
| `emit` — logger.py:123 |   2.2 % |
| `exists` — <frozen genericpath>:19 |   1.8 % |
| `isfile` — <frozen genericpath>:30 |   1.4 % |
| `compute` — _dispatcher.py:278 |   1.4 % |
| `_write_to_self` — selector_events.py:139 |   0.7 % |
| `_depths` — fast_iforest.py:97 |   0.7 % |
| `_socket_capture` — capture.py:1017 |   0.6 % |
| `quick_execute` — execute.py:53 |   0.6 % |
| `_format` — __init__.py:445 |   0.6 % |
| `formatTime` — __init__.py:624 |   0.6 % |
| `_read_from_self` — selector_events.py:119 |   0.6 % |
| `_save` — capture.py:317 |   0.5 % |
| `shouldRollover` — handlers.py:198 |   0.4 % |
| `_write` — anomaly_logger.py:263 |   0.4 % |
| `shouldRollover` — handlers.py:197 |   0.3 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **11.1 %** cmd (nftables.py) ← _run_command (reaction_module.py) ← _commit (block_batcher.py) ← _commit_bisect (block_batcher.py) ← _flush (block_batcher.py) ← _run (block_batcher.py) ← run (threading.py)
- **5.2 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **4.4 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **2.5 %** flush (__init__.py) ← emit (__init__.py) ← emit (__init__.py) ← emit (handlers.py) ← handle (__init__.py) ← handle (handlers.py) ← _monitor (handlers.py)
- **2.2 %** emit (logger.py) ← handle (__init__.py) ← callHandlers (__init__.py) ← handle (__init__.py) ← _log (__init__.py) ← log (__init__.py) ← _emit (logger.py)
- **2.1 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **1.8 %** exists (<frozen genericpath>) ← shouldRollover (handlers.py) ← emit (handlers.py) ← handle (__init__.py) ← handle (handlers.py) ← _monitor (handlers.py) ← run (threading.py)
- **1.4 %** isfile (<frozen genericpath>) ← shouldRollover (handlers.py) ← emit (handlers.py) ← handle (__init__.py) ← handle (handlers.py) ← _monitor (handlers.py) ← run (threading.py)
- **1.1 %** compute (_dispatcher.py) ← kneighbors (_base.py) ← score_samples (_lof.py) ← decision_function (_lof.py) ← _score_batch (models.py) ← predict_sequence_batch (models.py) ← run (thread.py)
- **0.7 %** _write_to_self (selector_events.py) ← call_soon_threadsafe (base_events.py) ← _call_set_state (futures.py) ← _invoke_callbacks (_base.py) ← set_result (_base.py) ← run (thread.py) ← _worker (thread.py)


## 🎚️ Phases de trafic (débit mesuré par l'IDS)

| Début | Fin | Trafic injecté | Relevés | pkt/s moyen | pkt/s max | Perte cumulée (fin de phase) |
|---|---|---|---|---|---|---|
| 0s | 60s | `normal @ pps=1000` | 12 | 1 006 | 1 065 | 0.00 % |
| 60s | 60s | `attack @ pps=1000` | 0 | – | – | – |
| 60s | 120s | `attack @ pps=5000` | 12 | 4 596 | 5 702 | 0.00 % |
| 120s | 200s | `attack @ pps=10000` | 16 | 8 878 | 10 826 | 3.31 % |
| 200s | 300s | `attack @ pps=15000` | 20 | 388 | 511 | 51.66 % |
| 300s | 364s | `attack @ pps=20000` | 13 | 845 | 1 395 | 68.45 % |
