# Rapport de profilage IDS/IPS — 2026-10-04 07:07:46

- Temps **actif** (hors attentes) : **4105.4 s** cumulés sur 64 thread(s)/process pour **365 s** de fenêtre · attentes ignorées (wait/sleep/queue.get/epoll…) : 4031.0 s
- Les pourcentages sont relatifs au temps actif total. ⚠️ `--native` en mode bloquant ralentit fortement la cible : fie-toi aux PROPORTIONS, pas au débit absolu.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (feuille) : **capture** (2.3 %)
- Étape du pipeline la plus coûteuse : **predict_packet (AE + IF + LOF)** (1.5 %)
- Inférence (paquet + séquence) active **95 s sur 365 s** de fenêtre (26 %) → le consommateur n'est pas saturé.
- 💡 Pas de règle évidente déclenchée : regarde les tables ci-dessous et le flamegraph.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **9156** → 25.08/s (≈ 501.70 paquets/s traités, stride=20)
- Anomalies paquet : 3016 · blocages nft : 3005
- Capture au début : 1 000 pkt/s gardés  pertes 0.0 % (noyau 0 · app 0)
- Capture à la fin : 5 194 pkt/s gardés  pertes 72.1 % (noyau 0 · app 3 501 151)

## 🧱 Étapes du pipeline (temps inclusif)

| Étape | % temps actif | secondes |
|---|---:|---:|
| extract_pack_features (par paquet) |   0.1 % | 2.2 |
| predict_packet (AE + IF + LOF) |   1.5 % | 59.8 |
|   dont IsolationForest (paquet) |   1.1 % | 45.7 |
|   dont LOF (paquet) |   0.0 % | 1.7 |
| extract_seq_features |   0.1 % | 2.4 |
| predict_sequence (CNN + AE + IF + LOF) |   0.9 % | 35.0 |
|   dont IsolationForest (séquence) |   0.0 % | 1.2 |
|   dont LOF (séquence) |   0.2 % | 6.5 |
| AnomalyScorer.detect_pkt (voie lente) |   0.4 % | 15.3 |
| log_anomaly / _add_alert |   0.0 % | 1.2 |
| persistance joblib/pickle (dump) |   0.0 % | 0.4 |
| logger.print |   0.3 % | 13.6 |
| blocage nft (_run_command / block) |   0.8 % | 32.5 |
| graphes (add_data*) |   0.0 % | 0.5 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| asyncio / threads / queue |  93.6 % | 3843.5 |
| capture |   2.3 % | 92.6 |
| Python pur (ton code / autre) |   1.3 % | 55.4 |
| réaction nft / subprocess |   0.8 % | 32.5 |
| TensorFlow / Keras |   0.8 % | 30.8 |
| logs / print |   0.4 % | 15.8 |
| scikit-learn |   0.3 % | 12.6 |
| dpkt (parsing paquets) |   0.2 % | 7.7 |
| numpy / scipy |   0.1 % | 5.5 |
| scoring / corrélation |   0.1 % | 4.7 |
| extraction de features |   0.1 % | 3.0 |
| json / pickle / dill / joblib |   0.0 % | 1.3 |

## 🧵 Par thread / process

| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |
|---|---:|---:|---:|---|
| Process 446007 Thread 446284 "asyncio_5" | 258.4 |   6.3 % | 32.2 | run (thread.py) |
| Process 446007 Thread 446328 "asyncio_7" | 252.9 |   6.2 % | 37.7 | run (thread.py) |
| Process 446007 Thread 446488 "asyncio_13" | 250.7 |   6.1 % | 39.9 | run (thread.py) |
| Process 446007 Thread 446357 "asyncio_10" | 250.6 |   6.1 % | 40.0 | run (thread.py) |
| Process 446007 Thread 446270 "asyncio_2" | 250.0 |   6.1 % | 40.6 | run (thread.py) |
| Process 446007 Thread 446267 "asyncio_1" | 249.5 |   6.1 % | 41.1 | run (thread.py) |
| Process 446007 Thread 446282 "asyncio_3" | 248.8 |   6.1 % | 41.8 | run (thread.py) |
| Process 446007 Thread 446226 "asyncio_0" | 248.7 |   6.1 % | 41.9 | run (thread.py) |
| Process 446007 Thread 446356 "asyncio_9" | 246.5 |   6.0 % | 44.1 | run (thread.py) |
| Process 446007 Thread 446487 "asyncio_12" | 243.8 |   5.9 % | 46.8 | run (thread.py) |
| Process 446007 Thread 446507 "asyncio_15" | 242.8 |   5.9 % | 47.8 | run (thread.py) |
| Process 446007 Thread 446338 "asyncio_8" | 240.2 |   5.9 % | 50.4 | run (thread.py) |
| Process 446007 Thread 446506 "asyncio_14" | 238.5 |   5.8 % | 52.1 | run (thread.py) |
| Process 446007 Thread 446283 "asyncio_4" | 237.8 |   5.8 % | 52.8 | run (thread.py) |
| Process 446007 Thread 446375 "asyncio_11" | 236.9 |   5.8 % | 53.6 | run (thread.py) |
| Process 446007 Thread 446302 "asyncio_6" | 235.5 |   5.7 % | 55.1 | run (thread.py) |
| Process 446007 Thread 446115 "Capture-veth_rx" | 92.5 |   2.3 % | 198.1 | _socket_capture (capture.py) |
| Process 446007 Thread 446058 "Detection Thread" | 47.6 |   1.2 % | 243.0 | unpack (dpkt.py) |
| Process 446007 Thread 446268 "BlockBatcher" | 32.6 |   0.8 % | 258.0 | cmd (nftables.py) |
| Process 446007 Thread 446269 "AnomalyWriter" | 1.0 |   0.0 % | 289.6 | _write (anomaly_logger.py) |

## ⏱️ Top 20 fonctions — temps propre (self)

| Fonction | % | s |
|---|---:|---:|
| `run` (thread.py) |  93.4 % | 3832.7 |
| `_socket_capture` (capture.py) |   1.9 % | 77.9 |
| `_depths` (fast_iforest.py) |   1.1 % | 46.2 |
| `cmd` (nftables.py) |   0.7 % | 30.7 |
| `quick_execute` (execute.py) |   0.7 % | 27.0 |
| `compute` (_dispatcher.py) |   0.2 % | 7.4 |
| `put` (queue.py) |   0.1 % | 5.1 |
| `unpack` (dpkt.py) |   0.1 % | 4.7 |
| `_write_to_self` (selector_events.py) |   0.1 % | 4.3 |
| `_wrapreduction` (fromnumeric.py) |   0.1 % | 4.0 |
| `emit` (logger.py) |   0.1 % | 3.6 |
| `_put` (capture.py) |   0.1 % | 3.5 |
| `_detect_consumer` (detection_module.py) |   0.1 % | 3.1 |
| `transform` (_data.py) |   0.1 % | 2.6 |
| `__enter__` (threading.py) |   0.1 % | 2.1 |
| `_asarray_with_order` (_array_api.py) |   0.0 % | 2.0 |
| `_detect_level` (logger.py) |   0.0 % | 1.9 |
| `convert_to_eager_tensor` (constant_op.py) |   0.0 % | 1.7 |
| `extract_pack_features` (features_extractor.py) |   0.0 % | 1.6 |
| `_to_alert_entry` (detection_module.py) |   0.0 % | 1.5 |

## ⏱️ Top 20 fonctions — temps inclusif

| Fonction | % | s |
|---|---:|---:|
| `run` (threading.py) | 100.0 % | 4105.4 |
| `_bootstrap` (threading.py) | 100.0 % | 4105.4 |
| `_bootstrap_inner` (threading.py) | 100.0 % | 4105.4 |
| `_worker` (thread.py) |  95.8 % | 3931.4 |
| `run` (thread.py) |  95.8 % | 3931.4 |
| `_socket_capture` (capture.py) |   2.3 % | 92.5 |
| `predict_packet_batch` (models.py) |   1.5 % | 59.7 |
| `_score_batch` (models.py) |   1.3 % | 55.3 |
| `run` (nest_asyncio.py) |   1.2 % | 47.7 |
| `run_until_complete` (nest_asyncio.py) |   1.2 % | 47.7 |
| `_run_async_detection` (orchestrator.py) |   1.2 % | 47.6 |
| `_run_once` (nest_asyncio.py) |   1.2 % | 47.5 |
| `_run` (events.py) |   1.2 % | 47.3 |
| `decision_function` (fast_iforest.py) |   1.1 % | 46.9 |
| `score_samples` (fast_iforest.py) |   1.1 % | 46.9 |
| `_depths` (fast_iforest.py) |   1.1 % | 46.5 |
| `__step` (tasks.py) |   1.1 % | 43.2 |
| `__wakeup` (tasks.py) |   1.0 % | 42.6 |
| `predict_sequence_batch` (models.py) |   0.9 % | 35.0 |
| `_run` (block_batcher.py) |   0.8 % | 32.6 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |   2.3 % | 92.5 |
| `predict_packet_batch` (models.py) |   1.5 % | 59.7 |
| `_score_batch` (models.py) |   1.3 % | 55.3 |
| `_run_async_detection` (orchestrator.py) |   1.2 % | 47.6 |
| `score_samples` (fast_iforest.py) |   1.1 % | 46.9 |
| `decision_function` (fast_iforest.py) |   1.1 % | 46.9 |
| `_depths` (fast_iforest.py) |   1.1 % | 46.5 |
| `predict_sequence_batch` (models.py) |   0.9 % | 35.0 |
| `_run` (block_batcher.py) |   0.8 % | 32.6 |
| `_flush` (block_batcher.py) |   0.8 % | 32.5 |
| `_commit` (block_batcher.py) |   0.8 % | 32.5 |
| `_run_command` (reaction_module.py) |   0.8 % | 32.5 |
| `_run_bucketed` (models.py) |   0.8 % | 31.0 |
| `_detect_consumer` (detection_module.py) |   0.7 % | 26.7 |
| `detect_pkt` (anomaly_scorer.py) |   0.4 % | 15.3 |
| `_predict_ae_seq` (models.py) |   0.4 % | 15.1 |
| `_put` (capture.py) |   0.4 % | 14.5 |
| `_detect_producer` (detection_module.py) |   0.3 % | 11.9 |
| `_drain_entries` (detection_module.py) |   0.2 % | 9.6 |
| `_predict_cnn_seq` (models.py) |   0.2 % | 8.3 |

## 📍 Top 20 lignes chaudes

| Ligne | % |
|---|---:|
| `run` — thread.py:58 |  93.4 % |
| `_socket_capture` — capture.py:989 |   1.6 % |
| `cmd` — nftables.py:410 |   0.7 % |
| `quick_execute` — execute.py:53 |   0.7 % |
| `_depths` — fast_iforest.py:98 |   0.7 % |
| `_depths` — fast_iforest.py:99 |   0.3 % |
| `compute` — _dispatcher.py:278 |   0.2 % |
| `_socket_capture` — capture.py:1003 |   0.2 % |
| `_depths` — fast_iforest.py:97 |   0.1 % |
| `_write_to_self` — selector_events.py:139 |   0.1 % |
| `_wrapreduction` — fromnumeric.py:83 |   0.1 % |
| `unpack` — dpkt.py:344 |   0.1 % |
| `emit` — logger.py:57 |   0.1 % |
| `put` — queue.py:133 |   0.1 % |
| `_asarray_with_order` — _array_api.py:744 |   0.0 % |
| `__enter__` — threading.py:272 |   0.0 % |
| `transform` — _data.py:1062 |   0.0 % |
| `_put` — capture.py:848 |   0.0 % |
| `extract_pack_features` — features_extractor.py:255 |   0.0 % |
| `put` — queue.py:137 |   0.0 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **93.4 %** run (thread.py) ← _worker (thread.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **1.6 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **0.7 %** cmd (nftables.py) ← _run_command (reaction_module.py) ← _commit (block_batcher.py) ← _flush (block_batcher.py) ← _run (block_batcher.py) ← run (threading.py) ← _bootstrap_inner (threading.py)
- **0.7 %** quick_execute (execute.py) ← call_function (context.py) ← call_flat (atomic_function.py) ← call_preflattened (atomic_function.py) ← _call_flat (concrete_function.py) ← call_function (tracing_compilation.py) ← _call (polymorphic_function.py)
- **0.6 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **0.3 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **0.2 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **0.2 %** compute (_dispatcher.py) ← kneighbors (_base.py) ← score_samples (_lof.py) ← decision_function (_lof.py) ← _score_batch (models.py) ← predict_sequence_batch (models.py) ← run (thread.py)
- **0.1 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **0.1 %** _wrapreduction (fromnumeric.py) ← sum (fromnumeric.py) ← _assert_all_finite (validation.py) ← check_array (validation.py) ← _validate_data (base.py) ← transform (_data.py) ← wrapped (_set_output.py)


## 🎚️ Phases de trafic (débit mesuré par l'IDS)

| Début | Fin | Trafic injecté | Relevés | pkt/s moyen | pkt/s max | Perte cumulée (fin de phase) |
|---|---|---|---|---|---|---|
| 0s | 60s | `normal @ pps=1000` | 12 | 1 014 | 1 102 | 0.00 % |
| 60s | 60s | `attack @ pps=1000` | 0 | – | – | – |
| 60s | 120s | `attack @ pps=5000` | 12 | 4 362 | 5 285 | 0.00 % |
| 120s | 200s | `attack @ pps=10000` | 16 | 9 135 | 9 479 | 0.00 % |
| 200s | 300s | `attack @ pps=15000` | 20 | 229 | 2 425 | 55.41 % |
| 300s | 365s | `attack @ pps=20000` | 13 | 796 | 1 081 | 68.74 % |
