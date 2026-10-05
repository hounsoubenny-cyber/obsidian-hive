# Rapport de profilage IDS/IPS — 2026-10-04 11:12:58

- Temps **actif** (hors attentes) : **1842.7 s** cumulés sur 54 thread(s)/process pour **369 s** de fenêtre · attentes ignorées (wait/sleep/queue.get/epoll…) : 5091.8 s
- Les pourcentages sont relatifs au temps actif total. ⚠️ `--native` en mode bloquant ralentit fortement la cible : fie-toi aux PROPORTIONS, pas au débit absolu.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (feuille) : **Python pur (ton code / autre)** (74.1 %)
- Étape du pipeline la plus coûteuse : **predict_packet (AE + IF + LOF)** (8.5 %)
- Inférence (paquet + séquence) active **261 s sur 369 s** de fenêtre (71 %) → le consommateur n'est pas saturé.
- 💡 Pas de règle évidente déclenchée : regarde les tables ci-dessous et le flamegraph.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **16815** → 45.55/s (≈ 911.07 paquets/s traités, stride=20)
- Anomalies paquet : 2169 · blocages nft : 3690
- Capture au début : 1 000 pkt/s gardés  pertes 0.0 % (noyau 0 · app 0)
- Capture à la fin : 5 316 pkt/s gardés  pertes 27.0 % (noyau 0 · app 1 021 774)

## 🧱 Étapes du pipeline (temps inclusif)

| Étape | % temps actif | secondes |
|---|---:|---:|
| extract_pack_features (par paquet) |   0.3 % | 5.1 |
| predict_packet (AE + IF + LOF) |   8.5 % | 156.7 |
|   dont IsolationForest (paquet) |   6.2 % | 113.6 |
|   dont LOF (paquet) |   0.3 % | 6.3 |
| extract_seq_features |   0.3 % | 5.2 |
| predict_sequence (CNN + AE + IF + LOF) |   5.7 % | 104.4 |
|   dont IsolationForest (séquence) |   0.2 % | 3.8 |
|   dont LOF (séquence) |   1.1 % | 20.3 |
| AnomalyScorer.detect_pkt (voie lente) |   1.7 % | 30.9 |
| log_anomaly / _add_alert |   0.1 % | 1.7 |
| persistance joblib/pickle (dump) |   0.0 % | 0.6 |
| logger.print |   1.8 % | 33.4 |
| blocage nft (_run_command / block) |   3.6 % | 65.9 |
| graphes (add_data*) |   0.1 % | 1.3 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| Python pur (ton code / autre) |  74.1 % | 1364.7 |
| capture |   9.6 % | 177.0 |
| TensorFlow / Keras |   5.2 % | 96.1 |
| réaction nft / subprocess |   3.6 % | 67.0 |
| logs / print |   2.0 % | 37.1 |
| scikit-learn |   2.0 % | 37.0 |
| asyncio / threads / queue |   1.1 % | 20.7 |
| dpkt (parsing paquets) |   0.9 % | 16.8 |
| numpy / scipy |   0.6 % | 10.3 |
| scoring / corrélation |   0.4 % | 8.3 |
| extraction de features |   0.4 % | 6.6 |
| json / pickle / dill / joblib |   0.1 % | 1.2 |

## 🧵 Par thread / process

| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |
|---|---:|---:|---:|---|
| Process 483596 Thread 484581 "rdns_0" | 305.9 |  16.6 % | 59.1 | _lookup_hostname (resolve_hostname.py) |
| Process 483596 Thread 484654 "rdns_2" | 304.9 |  16.5 % | 60.1 | _lookup_hostname (resolve_hostname.py) |
| Process 483596 Thread 484585 "rdns_1" | 304.5 |  16.5 % | 60.5 | _lookup_hostname (resolve_hostname.py) |
| Process 483596 Thread 484672 "rdns_3" | 303.8 |  16.5 % | 61.2 | _lookup_hostname (resolve_hostname.py) |
| Process 483596 Thread 483759 "Capture-veth_rx" | 176.7 |   9.6 % | 188.2 | _socket_capture (capture.py) |
| Process 483596 Thread 484540 "asyncio_0" | 153.3 |   8.3 % | 211.7 | _depths (fast_iforest.py) |
| Process 483596 Thread 483645 "Detection Thread" | 108.1 |   5.9 % | 256.9 | unpack (dpkt.py) |
| Process 483596 Thread 484719 "asyncio_2" | 67.0 |   3.6 % | 298.0 | _depths (fast_iforest.py) |
| Process 483596 Thread 484583 "BlockBatcher" | 66.3 |   3.6 % | 298.7 | cmd (nftables.py) |
| Process 483596 Thread 484582 "asyncio_1" | 49.7 |   2.7 % | 315.3 | _depths (fast_iforest.py) |
| Process 483596 Thread 484584 "AnomalyWriter" | 2.0 |   0.1 % | 363.0 | _write (anomaly_logger.py) |
| Process 483596 Thread 483760 "Capture-Reporter" | 0.4 |   0.0 % | 364.6 | _rss_mb (capture.py) |
| Process 483596 Thread 483643 "API Thread" | 0.2 |   0.0 % | 364.8 | __step (tasks.py) |
| Process 483596 Thread 483596 "MainThread" | 0.0 |   0.0 % | 364.9 | __step (tasks.py) |
| Process 483596 Thread 483646 "Thread-2 (start_server)" | 0.0 |   0.0 % | 364.9 | __subclasscheck__ (<frozen abc>) |

## ⏱️ Top 20 fonctions — temps propre (self)

| Fonction | % | s |
|---|---:|---:|
| `_lookup_hostname` (resolve_hostname.py) |  66.2 % | 1219.0 |
| `_socket_capture` (capture.py) |   8.6 % | 158.6 |
| `_depths` (fast_iforest.py) |   6.3 % | 115.6 |
| `quick_execute` (execute.py) |   4.4 % | 80.5 |
| `cmd` (nftables.py) |   3.3 % | 60.2 |
| `compute` (_dispatcher.py) |   1.2 % | 21.5 |
| `emit` (logger.py) |   0.6 % | 10.2 |
| `unpack` (dpkt.py) |   0.5 % | 8.8 |
| `transform` (_data.py) |   0.5 % | 8.5 |
| `_detect_consumer` (detection_module.py) |   0.4 % | 8.0 |
| `_write_to_self` (selector_events.py) |   0.4 % | 7.5 |
| `put` (queue.py) |   0.4 % | 6.8 |
| `_wrapreduction` (fromnumeric.py) |   0.3 % | 5.8 |
| `convert_to_eager_tensor` (constant_op.py) |   0.3 % | 5.1 |
| `_detect_level` (logger.py) |   0.2 % | 4.2 |
| `src_ip_from_raw` (blocked_skip.py) |   0.2 % | 4.2 |
| `is_blocked` (reaction_module.py) |   0.2 % | 4.1 |
| `_to_alert_entry` (detection_module.py) |   0.2 % | 3.8 |
| `__enter__` (threading.py) |   0.2 % | 3.6 |
| `extract_pack_features` (features_extractor.py) |   0.2 % | 3.4 |

## ⏱️ Top 20 fonctions — temps inclusif

| Fonction | % | s |
|---|---:|---:|
| `_bootstrap` (threading.py) | 100.0 % | 1842.7 |
| `_bootstrap_inner` (threading.py) | 100.0 % | 1842.7 |
| `run` (threading.py) | 100.0 % | 1842.7 |
| `_worker` (thread.py) |  80.8 % | 1489.0 |
| `run` (thread.py) |  80.8 % | 1488.9 |
| `_lookup_hostname` (resolve_hostname.py) |  66.2 % | 1219.0 |
| `_socket_capture` (capture.py) |   9.6 % | 176.7 |
| `predict_packet_batch` (models.py) |   8.5 % | 156.6 |
| `_score_batch` (models.py) |   7.9 % | 144.9 |
| `decision_function` (fast_iforest.py) |   6.4 % | 117.4 |
| `score_samples` (fast_iforest.py) |   6.4 % | 117.3 |
| `_depths` (fast_iforest.py) |   6.3 % | 116.2 |
| `run_until_complete` (nest_asyncio.py) |   5.9 % | 108.1 |
| `run` (nest_asyncio.py) |   5.9 % | 108.1 |
| `_run_async_detection` (orchestrator.py) |   5.9 % | 108.1 |
| `_run_once` (nest_asyncio.py) |   5.9 % | 107.8 |
| `_run` (events.py) |   5.8 % | 107.5 |
| `predict_sequence_batch` (models.py) |   5.7 % | 104.2 |
| `__step` (tasks.py) |   5.6 % | 102.4 |
| `__wakeup` (tasks.py) |   5.5 % | 102.2 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif

| Fonction | % | s |
|---|---:|---:|
| `_lookup_hostname` (resolve_hostname.py) |  66.2 % | 1219.0 |
| `_socket_capture` (capture.py) |   9.6 % | 176.7 |
| `predict_packet_batch` (models.py) |   8.5 % | 156.6 |
| `_score_batch` (models.py) |   7.9 % | 144.9 |
| `decision_function` (fast_iforest.py) |   6.4 % | 117.4 |
| `score_samples` (fast_iforest.py) |   6.4 % | 117.3 |
| `_depths` (fast_iforest.py) |   6.3 % | 116.2 |
| `_run_async_detection` (orchestrator.py) |   5.9 % | 108.1 |
| `predict_sequence_batch` (models.py) |   5.7 % | 104.2 |
| `_run_bucketed` (models.py) |   5.3 % | 97.0 |
| `_run` (block_batcher.py) |   3.6 % | 66.3 |
| `_flush` (block_batcher.py) |   3.6 % | 66.2 |
| `_commit` (block_batcher.py) |   3.6 % | 66.2 |
| `_run_command` (reaction_module.py) |   3.6 % | 65.9 |
| `_detect_consumer` (detection_module.py) |   3.2 % | 58.8 |
| `_predict_ae_seq` (models.py) |   2.5 % | 46.3 |
| `_detect_producer` (detection_module.py) |   2.1 % | 39.2 |
| `_drain_entries` (detection_module.py) |   1.8 % | 33.7 |
| `detect_pkt` (anomaly_scorer.py) |   1.7 % | 30.9 |
| `_predict_cnn_seq` (models.py) |   1.2 % | 22.6 |

## 📍 Top 20 lignes chaudes

| Ligne | % |
|---|---:|
| `_lookup_hostname` — resolve_hostname.py:53 |  66.2 % |
| `_socket_capture` — capture.py:988 |   7.6 % |
| `quick_execute` — execute.py:53 |   4.4 % |
| `_depths` — fast_iforest.py:98 |   3.8 % |
| `cmd` — nftables.py:410 |   3.2 % |
| `_depths` — fast_iforest.py:99 |   1.6 % |
| `compute` — _dispatcher.py:278 |   1.2 % |
| `_socket_capture` — capture.py:1002 |   0.6 % |
| `_depths` — fast_iforest.py:97 |   0.6 % |
| `emit` — logger.py:57 |   0.5 % |
| `_write_to_self` — selector_events.py:139 |   0.4 % |
| `unpack` — dpkt.py:344 |   0.3 % |
| `_wrapreduction` — fromnumeric.py:83 |   0.3 % |
| `transform` — _data.py:1062 |   0.3 % |
| `_to_alert_entry` — detection_module.py:411 |   0.2 % |
| `__enter__` — threading.py:272 |   0.2 % |
| `_asarray_with_order` — _array_api.py:744 |   0.2 % |
| `extract_pack_features` — features_extractor.py:255 |   0.2 % |
| `put` — queue.py:133 |   0.2 % |
| `transform` — _data.py:1064 |   0.2 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **66.2 %** _lookup_hostname (resolve_hostname.py) ← run (thread.py) ← _worker (thread.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **7.6 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **4.4 %** quick_execute (execute.py) ← call_function (context.py) ← call_flat (atomic_function.py) ← call_preflattened (atomic_function.py) ← _call_flat (concrete_function.py) ← call_function (tracing_compilation.py) ← _call (polymorphic_function.py)
- **3.7 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **3.2 %** cmd (nftables.py) ← _run_command (reaction_module.py) ← _commit (block_batcher.py) ← _flush (block_batcher.py) ← _run (block_batcher.py) ← run (threading.py) ← _bootstrap_inner (threading.py)
- **1.5 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **0.9 %** compute (_dispatcher.py) ← kneighbors (_base.py) ← score_samples (_lof.py) ← decision_function (_lof.py) ← _score_batch (models.py) ← predict_sequence_batch (models.py) ← run (thread.py)
- **0.6 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **0.5 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **0.5 %** emit (logger.py) ← handle (__init__.py) ← callHandlers (__init__.py) ← handle (__init__.py) ← _log (__init__.py) ← log (__init__.py) ← print (logger.py)


## 🎚️ Phases de trafic (débit mesuré par l'IDS)

| Début | Fin | Trafic injecté | Relevés | pkt/s moyen | pkt/s max | Perte cumulée (fin de phase) |
|---|---|---|---|---|---|---|
| 0s | 60s | `normal @ pps=1000` | 12 | 1 000 | 1 001 | 0.00 % |
| 60s | 60s | `attack @ pps=1000` | 0 | – | – | – |
| 60s | 120s | `attack @ pps=5000` | 12 | 4 412 | 5 433 | 0.00 % |
| 120s | 200s | `attack @ pps=10000` | 16 | 9 197 | 11 228 | 0.00 % |
| 200s | 300s | `attack @ pps=15000` | 20 | 11 409 | 17 785 | 9.90 % |
| 300s | 369s | `attack @ pps=20000` | 14 | 7 073 | 8 299 | 27.03 % |
