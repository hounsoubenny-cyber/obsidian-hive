# Rapport de profilage IDS/IPS — 2026-10-04 12:02:36

- Temps **actif** (hors attentes) : **638.7 s** cumulés sur 57 thread(s)/process pour **366 s** de fenêtre · attentes ignorées (wait/sleep/queue.get/epoll…) : 5201.1 s
- Les pourcentages sont relatifs au temps actif total. ⚠️ `--native` en mode bloquant ralentit fortement la cible : fie-toi aux PROPORTIONS, pas au débit absolu.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (feuille) : **capture** (27.2 %)
- Étape du pipeline la plus coûteuse : **predict_packet (AE + IF + LOF)** (25.9 %)
- Inférence (paquet + séquence) active **278 s sur 366 s** de fenêtre (76 %) → le consommateur n'est pas saturé.
- 💡 `predict_packet` pèse lourd → vérifier la taille des lots (`detect_batch_size`) ; sinon réduire `n_estimators` / `n_neighbors`.
- 💡 Les commandes nft sont bloquantes dans la boucle → file d'attente dédiée + ne pas re-bloquer une IP déjà bloquée.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **0** → 0.00/s (≈ 0.00 paquets/s traités, stride=20)
- Anomalies paquet : 0 · blocages nft : 0

## 🧱 Étapes du pipeline (temps inclusif)

| Étape | % temps actif | secondes |
|---|---:|---:|
| extract_pack_features (par paquet) |   1.0 % | 6.6 |
| predict_packet (AE + IF + LOF) |  25.9 % | 165.5 |
|   dont IsolationForest (paquet) |  18.6 % | 118.9 |
|   dont LOF (paquet) |   1.0 % | 6.4 |
| extract_seq_features |   1.1 % | 6.8 |
| predict_sequence (CNN + AE + IF + LOF) |  17.7 % | 112.8 |
|   dont IsolationForest (séquence) |   0.6 % | 3.9 |
|   dont LOF (séquence) |   3.3 % | 21.1 |
| AnomalyScorer.detect_pkt (voie lente) |   2.5 % | 15.9 |
| log_anomaly / _add_alert |   0.3 % | 2.2 |
| persistance joblib/pickle (dump) |   0.1 % | 0.5 |
| logger.print |   1.0 % | 6.4 |
| blocage nft (_run_command / block) |  10.7 % | 68.3 |
| graphes (add_data*) |   0.3 % | 1.9 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| capture |  27.2 % | 173.9 |
| Python pur (ton code / autre) |  24.7 % | 157.7 |
| TensorFlow / Keras |  16.5 % | 105.3 |
| réaction nft / subprocess |  12.0 % | 76.5 |
| scikit-learn |   6.0 % | 38.5 |
| asyncio / threads / queue |   4.0 % | 25.8 |
| dpkt (parsing paquets) |   2.9 % | 18.3 |
| logs / print |   2.0 % | 12.9 |
| numpy / scipy |   1.7 % | 10.8 |
| extraction de features |   1.4 % | 9.2 |
| scoring / corrélation |   1.3 % | 8.5 |
| json / pickle / dill / joblib |   0.2 % | 1.3 |

## 🧵 Par thread / process

| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |
|---|---:|---:|---:|---|
| Process 507172 Thread 507355 "Capture-veth_rx" | 173.7 |  27.2 % | 191.3 | _socket_capture (capture.py) |
| Process 507172 Thread 507446 "asyncio_0" | 157.8 |  24.7 % | 207.1 | quick_execute (execute.py) |
| Process 507172 Thread 507279 "Detection Thread" | 101.8 |  15.9 % | 263.1 | unpack (dpkt.py) |
| Process 507172 Thread 507489 "BlockBatcher" | 68.5 |  10.7 % | 296.5 | cmd (nftables.py) |
| Process 507172 Thread 507516 "asyncio_2" | 50.3 |   7.9 % | 314.7 | _depths (fast_iforest.py) |
| Process 507172 Thread 507488 "asyncio_1" | 47.3 |   7.4 % | 317.7 | _depths (fast_iforest.py) |
| Process 507172 Thread 508251 "asyncio_3" | 34.6 |   5.4 % | 330.4 | _depths (fast_iforest.py) |
| Process 507172 Thread 507490 "AnomalyWriter" | 4.3 |   0.7 % | 360.7 | _write (anomaly_logger.py) |
| Process 507172 Thread 507356 "Capture-Reporter" | 0.2 |   0.0 % | 364.8 | _rss_mb (capture.py) |
| Process 507172 Thread 507172 "MainThread" | 0.1 |   0.0 % | 364.9 | __exit__ (synchronize.py) |
| Process 507172 Thread 507277 "API Thread" | 0.1 |   0.0 % | 364.9 | __schedule_callbacks (futures.py) |
| Process 507172 Thread 507280 "Thread-2 (start_server)" | 0.0 |   0.0 % | 364.9 | iscoroutine (coroutines.py) |

## ⏱️ Top 20 fonctions — temps propre (self)

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  23.7 % | 151.4 |
| `_depths` (fast_iforest.py) |  19.0 % | 121.4 |
| `quick_execute` (execute.py) |  14.5 % | 92.7 |
| `cmd` (nftables.py) |  10.7 % | 68.1 |
| `compute` (_dispatcher.py) |   3.8 % | 24.2 |
| `_write_to_self` (selector_events.py) |   1.8 % | 11.3 |
| `unpack` (dpkt.py) |   1.4 % | 8.8 |
| `put` (queue.py) |   1.3 % | 8.5 |
| `_detect_consumer` (detection_module.py) |   1.3 % | 8.2 |
| `transform` (_data.py) |   1.2 % | 7.8 |
| `_wrapreduction` (fromnumeric.py) |   0.9 % | 6.0 |
| `is_blocked` (reaction_module.py) |   0.9 % | 5.9 |
| `_detect_level` (logger.py) |   0.9 % | 5.7 |
| `_to_alert_entry` (detection_module.py) |   0.9 % | 5.6 |
| `src_ip_from_raw` (blocked_skip.py) |   0.9 % | 5.5 |
| `extract_pack_features` (features_extractor.py) |   0.7 % | 4.7 |
| `extract_seq_features` (features_extractor.py) |   0.7 % | 4.5 |
| `_asarray_with_order` (_array_api.py) |   0.7 % | 4.3 |
| `_write` (anomaly_logger.py) |   0.7 % | 4.2 |
| `__enter__` (threading.py) |   0.6 % | 4.1 |

## ⏱️ Top 20 fonctions — temps inclusif

| Fonction | % | s |
|---|---:|---:|
| `_bootstrap_inner` (threading.py) | 100.0 % | 638.6 |
| `run` (threading.py) | 100.0 % | 638.6 |
| `_bootstrap` (threading.py) | 100.0 % | 638.6 |
| `_worker` (thread.py) |  45.4 % | 290.0 |
| `run` (thread.py) |  45.4 % | 290.0 |
| `_socket_capture` (capture.py) |  27.2 % | 173.7 |
| `predict_packet_batch` (models.py) |  25.9 % | 165.4 |
| `_score_batch` (models.py) |  23.6 % | 150.8 |
| `decision_function` (fast_iforest.py) |  19.2 % | 122.8 |
| `score_samples` (fast_iforest.py) |  19.2 % | 122.8 |
| `_depths` (fast_iforest.py) |  19.1 % | 121.9 |
| `predict_sequence_batch` (models.py) |  17.6 % | 112.7 |
| `_run_bucketed` (models.py) |  16.7 % | 106.7 |
| `error_handler` (traceback_utils.py) |  16.1 % | 102.6 |
| `__call__` (polymorphic_function.py) |  16.1 % | 102.6 |
| `_call` (polymorphic_function.py) |  16.1 % | 102.6 |
| `run_until_complete` (nest_asyncio.py) |  16.0 % | 101.9 |
| `run` (nest_asyncio.py) |  16.0 % | 101.9 |
| `_run_async_detection` (orchestrator.py) |  15.9 % | 101.8 |
| `_run_once` (nest_asyncio.py) |  15.9 % | 101.7 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  27.2 % | 173.7 |
| `predict_packet_batch` (models.py) |  25.9 % | 165.4 |
| `_score_batch` (models.py) |  23.6 % | 150.8 |
| `decision_function` (fast_iforest.py) |  19.2 % | 122.8 |
| `score_samples` (fast_iforest.py) |  19.2 % | 122.8 |
| `_depths` (fast_iforest.py) |  19.1 % | 121.9 |
| `predict_sequence_batch` (models.py) |  17.6 % | 112.7 |
| `_run_bucketed` (models.py) |  16.7 % | 106.7 |
| `_run_async_detection` (orchestrator.py) |  15.9 % | 101.8 |
| `_run` (block_batcher.py) |  10.7 % | 68.5 |
| `_flush` (block_batcher.py) |  10.7 % | 68.4 |
| `_commit` (block_batcher.py) |  10.7 % | 68.4 |
| `_run_command` (reaction_module.py) |  10.7 % | 68.3 |
| `_predict_ae_seq` (models.py) |   8.7 % | 55.3 |
| `_detect_producer` (detection_module.py) |   7.4 % | 47.4 |
| `_detect_consumer` (detection_module.py) |   6.8 % | 43.6 |
| `_drain_entries` (detection_module.py) |   6.3 % | 40.3 |
| `_predict_cnn_seq` (models.py) |   3.6 % | 22.9 |
| `_put` (capture.py) |   3.5 % | 22.1 |
| `_predict_ae_pkt` (models.py) |   3.2 % | 20.3 |

## 📍 Top 20 lignes chaudes

| Ligne | % |
|---|---:|
| `_socket_capture` — capture.py:988 |  20.2 % |
| `quick_execute` — execute.py:53 |  14.5 % |
| `_depths` — fast_iforest.py:98 |  11.5 % |
| `cmd` — nftables.py:410 |  10.3 % |
| `_depths` — fast_iforest.py:99 |   4.6 % |
| `compute` — _dispatcher.py:278 |   3.8 % |
| `_socket_capture` — capture.py:1002 |   2.2 % |
| `_write_to_self` — selector_events.py:139 |   1.8 % |
| `_depths` — fast_iforest.py:97 |   1.7 % |
| `_wrapreduction` — fromnumeric.py:83 |   0.9 % |
| `unpack` — dpkt.py:344 |   0.9 % |
| `_to_alert_entry` — detection_module.py:411 |   0.8 % |
| `extract_pack_features` — features_extractor.py:255 |   0.7 % |
| `extract_seq_features` — features_extractor.py:262 |   0.7 % |
| `_asarray_with_order` — _array_api.py:744 |   0.7 % |
| `put` — queue.py:133 |   0.6 % |
| `transform` — _data.py:1062 |   0.6 % |
| `_depths` — fast_iforest.py:95 |   0.6 % |
| `_write` — anomaly_logger.py:263 |   0.6 % |
| `transform` — _data.py:1064 |   0.6 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **20.2 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **14.5 %** quick_execute (execute.py) ← call_function (context.py) ← call_flat (atomic_function.py) ← call_preflattened (atomic_function.py) ← _call_flat (concrete_function.py) ← call_function (tracing_compilation.py) ← _call (polymorphic_function.py)
- **11.1 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **10.3 %** cmd (nftables.py) ← _run_command (reaction_module.py) ← _commit (block_batcher.py) ← _flush (block_batcher.py) ← _run (block_batcher.py) ← run (threading.py) ← _bootstrap_inner (threading.py)
- **4.4 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **3.0 %** compute (_dispatcher.py) ← kneighbors (_base.py) ← score_samples (_lof.py) ← decision_function (_lof.py) ← _score_batch (models.py) ← predict_sequence_batch (models.py) ← run (thread.py)
- **2.2 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **1.8 %** _write_to_self (selector_events.py) ← call_soon_threadsafe (base_events.py) ← _call_set_state (futures.py) ← _invoke_callbacks (_base.py) ← set_result (_base.py) ← run (thread.py) ← _worker (thread.py)
- **1.7 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **0.8 %** _to_alert_entry (detection_module.py) ← _detect_consumer (detection_module.py) ← __step (tasks.py) ← __wakeup (tasks.py) ← _run (events.py) ← _run_once (nest_asyncio.py) ← run_until_complete (nest_asyncio.py)


## 🎚️ Phases de trafic (débit mesuré par l'IDS)

| Début | Fin | Trafic injecté | Relevés | pkt/s moyen | pkt/s max | Perte cumulée (fin de phase) |
|---|---|---|---|---|---|---|
| 0s | 60s | `normal @ pps=1000` | 0 | – | – | – |
| 60s | 60s | `attack @ pps=1000` | 0 | – | – | – |
| 60s | 120s | `attack @ pps=5000` | 0 | – | – | – |
| 120s | 200s | `attack @ pps=10000` | 0 | – | – | – |
| 200s | 300s | `attack @ pps=15000` | 0 | – | – | – |
| 300s | 366s | `attack @ pps=20000` | 0 | – | – | – |
