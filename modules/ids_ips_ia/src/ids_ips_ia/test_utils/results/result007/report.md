# Rapport de profilage IDS/IPS — 2026-10-02 04:59:28

- Temps **actif** (hors attentes) : **709.7 s** cumulés sur 51 thread(s)/process pour **360 s** de fenêtre · attentes ignorées (wait/sleep/queue.get/epoll…) : 4729.9 s
- Les pourcentages sont relatifs au temps actif total. ⚠️ `--native` en mode bloquant ralentit fortement la cible : fie-toi aux PROPORTIONS, pas au débit absolu.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (feuille) : **capture** (51.4 %)
- Étape du pipeline la plus coûteuse : **blocage nft (_run_command / block)** (20.6 %)
- Inférence (paquet + séquence) active **105 s sur 360 s** de fenêtre (29 %) → le consommateur n'est pas saturé.
- 💡 Les commandes nft sont bloquantes dans la boucle → file d'attente dédiée + ne pas re-bloquer une IP déjà bloquée.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **7296** → 20.24/s (≈ 404.90 paquets/s traités, stride=20)
- Anomalies paquet : 10535 · blocages nft : 16699
- Capture au début : 1 000 pkt/s gardés  pertes 0.0 % (noyau 0 · app 0)
- Capture à la fin : 836 pkt/s gardés  pertes 65.7 % (noyau 0 · app 2 343 903)

## 🧱 Étapes du pipeline (temps inclusif)

| Étape | % temps actif | secondes |
|---|---:|---:|
| detect() — boucle consommateur (total) |   9.7 % | 69.2 |
| extract_pack_features (par paquet) |   0.3 % | 2.4 |
| predict_packet (AE + IF + LOF) |   8.7 % | 61.6 |
|   dont IsolationForest (paquet) |   7.9 % | 56.2 |
|   dont LOF (paquet) |   0.3 % | 2.1 |
| extract_seq_features |   0.5 % | 3.4 |
| predict_sequence (CNN + AE + IF + LOF) |   6.1 % | 43.5 |
|   dont IsolationForest (séquence) |   0.3 % | 1.9 |
|   dont LOF (séquence) |   1.4 % | 9.7 |
| AnomalyScorer.detect_pkt (voie lente) |   5.2 % | 36.8 |
| log_anomaly / _add_alert |   0.3 % | 2.1 |
| persistance joblib/pickle (dump) |   0.1 % | 0.8 |
| logger.print |   4.9 % | 34.5 |
| blocage nft (_run_command / block) |  20.6 % | 146.5 |
| graphes (add_data*) |   0.1 % | 0.9 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| capture |  51.4 % | 365.1 |
| réaction nft / subprocess |  20.7 % | 146.6 |
| Python pur (ton code / autre) |  10.1 % | 71.5 |
| logs / print |   5.2 % | 37.2 |
| TensorFlow / Keras |   4.7 % | 33.6 |
| asyncio / threads / queue |   2.3 % | 16.0 |
| scikit-learn |   1.7 % | 11.7 |
| scoring / corrélation |   1.4 % | 10.2 |
| dpkt (parsing paquets) |   1.2 % | 8.2 |
| extraction de features |   0.5 % | 3.7 |
| numpy / scipy |   0.4 % | 3.1 |
| json / pickle / dill / joblib |   0.4 % | 2.7 |

## 🧵 Par thread / process

| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |
|---|---:|---:|---:|---|
| Process 161956 Thread 162070 "Capture-veth_rx" | 365.0 |  51.4 % | 0.0 | _socket_capture (capture.py) |
| Process 161956 Thread 162115 "asyncio_0" | 173.4 |  24.4 % | 191.6 | cmd (nftables.py) |
| Process 161956 Thread 162007 "Detection Thread" | 78.5 |  11.1 % | 286.4 | detect (detection_module.py) |
| Process 161956 Thread 162205 "asyncio_1" | 45.8 |   6.4 % | 319.2 | cmd (nftables.py) |
| Process 161956 Thread 162279 "asyncio_2" | 30.7 |   4.3 % | 334.2 | cmd (nftables.py) |
| Process 161956 Thread 162939 "asyncio_3" | 15.2 |   2.1 % | 314.8 | cmd (nftables.py) |
| Process 161956 Thread 162206 "AnomalyWriter" | 0.7 |   0.1 % | 364.3 | _write (anomaly_logger.py) |
| Process 161956 Thread 162005 "API Thread" | 0.2 |   0.0 % | 364.7 | __schedule_callbacks (futures.py) |
| Process 161956 Thread 162071 "Capture-Reporter" | 0.1 |   0.0 % | 364.8 | _rss_mb (capture.py) |
| Process 161956 Thread 161956 "MainThread" | 0.1 |   0.0 % | 364.9 | time (base_events.py) |
| Process 161956 Thread 162008 "Thread-2 (start_server)" | 0.0 |   0.0 % | 364.9 | _run (ioloop.py) |

## ⏱️ Top 20 fonctions — temps propre (self)

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  48.7 % | 345.4 |
| `cmd` (nftables.py) |  20.2 % | 143.5 |
| `_depths` (fast_iforest.py) |   8.1 % | 57.2 |
| `quick_execute` (execute.py) |   4.4 % | 30.9 |
| `compute` (_dispatcher.py) |   1.5 % | 10.3 |
| `_write_to_self` (selector_events.py) |   1.1 % | 8.0 |
| `put` (queue.py) |   1.0 % | 7.2 |
| `emit` (logger.py) |   0.9 % | 6.7 |
| `detect` (detection_module.py) |   0.9 % | 6.4 |
| `_detect_level` (logger.py) |   0.9 % | 6.1 |
| `unpack` (dpkt.py) |   0.7 % | 4.8 |
| `__init__` (__init__.py) |   0.6 % | 3.9 |
| `_put` (capture.py) |   0.5 % | 3.9 |
| `__enter__` (threading.py) |   0.4 % | 3.1 |
| `formatTime` (__init__.py) |   0.4 % | 2.9 |
| `format` (logger.py) |   0.3 % | 2.2 |
| `__exit__` (threading.py) |   0.3 % | 2.1 |
| `extract_seq_features` (features_extractor.py) |   0.3 % | 2.0 |
| `_to_alert_entry` (detection_module.py) |   0.3 % | 2.0 |
| `_read_from_self` (selector_events.py) |   0.2 % | 1.8 |

## ⏱️ Top 20 fonctions — temps inclusif

| Fonction | % | s |
|---|---:|---:|
| `run` (threading.py) | 100.0 % | 709.6 |
| `_bootstrap_inner` (threading.py) | 100.0 % | 709.6 |
| `_bootstrap` (threading.py) | 100.0 % | 709.6 |
| `_socket_capture` (capture.py) |  51.4 % | 365.0 |
| `_worker` (thread.py) |  37.3 % | 265.0 |
| `run` (thread.py) |  37.3 % | 264.9 |
| `action` (anomaly_scorer.py) |  21.2 % | 150.6 |
| `block` (reaction_module.py) |  20.6 % | 146.5 |
| `_run_command` (reaction_module.py) |  20.6 % | 146.4 |
| `cmd` (nftables.py) |  20.2 % | 143.5 |
| `run_until_complete` (nest_asyncio.py) |  11.1 % | 78.6 |
| `run` (nest_asyncio.py) |  11.1 % | 78.6 |
| `_run_async_detection` (orchestrator.py) |  11.1 % | 78.5 |
| `_run_once` (nest_asyncio.py) |  11.0 % | 78.4 |
| `_run` (events.py) |  11.0 % | 78.1 |
| `__wakeup` (tasks.py) |  10.5 % | 74.5 |
| `__step` (tasks.py) |  10.5 % | 74.4 |
| `_score_batch` (models.py) |   9.9 % | 70.1 |
| `_detection_coroutine` (orchestrator.py) |   9.8 % | 69.2 |
| `detect` (detection_module.py) |   9.7 % | 69.2 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  51.4 % | 365.0 |
| `action` (anomaly_scorer.py) |  21.2 % | 150.6 |
| `block` (reaction_module.py) |  20.6 % | 146.5 |
| `_run_command` (reaction_module.py) |  20.6 % | 146.4 |
| `_run_async_detection` (orchestrator.py) |  11.1 % | 78.5 |
| `_score_batch` (models.py) |   9.9 % | 70.1 |
| `_detection_coroutine` (orchestrator.py) |   9.8 % | 69.2 |
| `detect` (detection_module.py) |   9.7 % | 69.2 |
| `predict_packet_batch` (models.py) |   8.7 % | 61.5 |
| `decision_function` (fast_iforest.py) |   8.2 % | 58.1 |
| `score_samples` (fast_iforest.py) |   8.2 % | 58.0 |
| `_depths` (fast_iforest.py) |   8.1 % | 57.5 |
| `predict_sequence_batch` (models.py) |   6.1 % | 43.5 |
| `detect_pkt` (anomaly_scorer.py) |   5.2 % | 36.8 |
| `_run_bucketed` (models.py) |   4.8 % | 33.9 |
| `_put` (capture.py) |   2.7 % | 19.5 |
| `_predict_ae_seq` (models.py) |   2.7 % | 19.2 |
| `update` (anomaly_scorer.py) |   2.4 % | 17.0 |
| `_drain_entries` (detection_module.py) |   1.4 % | 9.6 |
| `_predict_cnn_seq` (models.py) |   1.3 % | 9.3 |

## 📍 Top 20 lignes chaudes

| Ligne | % |
|---|---:|
| `_socket_capture` — capture.py:984 |  33.4 % |
| `cmd` — nftables.py:410 |  20.2 % |
| `_socket_capture` — capture.py:988 |  13.0 % |
| `_depths` — fast_iforest.py:97 |   4.7 % |
| `quick_execute` — execute.py:53 |   4.4 % |
| `_depths` — fast_iforest.py:98 |   2.3 % |
| `compute` — _dispatcher.py:278 |   1.5 % |
| `_write_to_self` — selector_events.py:139 |   1.1 % |
| `_socket_capture` — capture.py:1002 |   1.0 % |
| `emit` — logger.py:57 |   0.8 % |
| `_depths` — fast_iforest.py:96 |   0.8 % |
| `unpack` — dpkt.py:344 |   0.5 % |
| `put` — queue.py:133 |   0.5 % |
| `__enter__` — threading.py:272 |   0.4 % |
| `_detect_level` — logger.py:219 |   0.3 % |
| `_put` — capture.py:847 |   0.3 % |
| `__exit__` — threading.py:275 |   0.3 % |
| `extract_seq_features` — features_extractor.py:262 |   0.3 % |
| `formatTime` — __init__.py:624 |   0.3 % |
| `_to_alert_entry` — detection_module.py:403 |   0.2 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **33.4 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **14.5 %** cmd (nftables.py) ← _run_command (reaction_module.py) ← block (reaction_module.py) ← action (anomaly_scorer.py) ← run (thread.py) ← _worker (thread.py) ← run (threading.py)
- **13.0 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **4.6 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **4.5 %** cmd (nftables.py) ← _run_command (reaction_module.py) ← block (reaction_module.py) ← action (anomaly_scorer.py) ← run (thread.py) ← _worker (thread.py) ← run (threading.py)
- **4.4 %** quick_execute (execute.py) ← call_function (context.py) ← call_flat (atomic_function.py) ← call_preflattened (atomic_function.py) ← _call_flat (concrete_function.py) ← call_function (tracing_compilation.py) ← _call (polymorphic_function.py)
- **2.2 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **1.2 %** compute (_dispatcher.py) ← kneighbors (_base.py) ← score_samples (_lof.py) ← decision_function (_lof.py) ← _score_batch (models.py) ← predict_sequence_batch (models.py) ← run (thread.py)
- **1.1 %** _write_to_self (selector_events.py) ← call_soon_threadsafe (base_events.py) ← _call_set_state (futures.py) ← _invoke_callbacks (_base.py) ← set_result (_base.py) ← run (thread.py) ← _worker (thread.py)
- **1.0 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)


## 🎚️ Phases de trafic (débit mesuré par l'IDS)

| Début | Fin | Trafic injecté | Relevés | pkt/s moyen | pkt/s max | Perte cumulée (fin de phase) |
|---|---|---|---|---|---|---|
| 0s | 60s | `normal @ pps=1000` | 12 | 1 002 | 1 025 | 0.00 % |
| 60s | 60s | `attack @ pps=1000` | 0 | – | – | – |
| 60s | 120s | `attack @ pps=5000` | 12 | 4 598 | 4 808 | 0.00 % |
| 120s | 200s | `attack @ pps=10000` | 16 | 9 274 | 11 121 | 0.61 % |
| 200s | 300s | `attack @ pps=15000` | 19 | 660 | 1 121 | 52.90 % |
| 300s | 360s | `attack @ pps=20000` | 12 | 1 112 | 1 543 | 65.68 % |
