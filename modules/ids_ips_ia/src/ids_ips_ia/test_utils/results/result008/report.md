# Rapport de profilage IDS/IPS — 2026-10-02 11:23:33

- Temps **actif** (hors attentes) : **606.9 s** cumulés sur 48 thread(s)/process pour **364 s** de fenêtre · attentes ignorées (wait/sleep/queue.get/epoll…) : 4949.8 s
- Les pourcentages sont relatifs au temps actif total. ⚠️ `--native` en mode bloquant ralentit fortement la cible : fie-toi aux PROPORTIONS, pas au débit absolu.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (feuille) : **capture** (30.6 %)
- Étape du pipeline la plus coûteuse : **predict_packet (AE + IF + LOF)** (20.9 %)
- Inférence (paquet + séquence) active **224 s sur 364 s** de fenêtre (62 %) → le consommateur n'est pas saturé.
- 💡 `predict_packet` pèse lourd → vérifier la taille des lots (`detect_batch_size`) ; sinon réduire `n_estimators` / `n_neighbors`.
- 💡 Les commandes nft sont bloquantes dans la boucle → file d'attente dédiée + ne pas re-bloquer une IP déjà bloquée.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **17179** → 47.25/s (≈ 945.01 paquets/s traités, stride=20)
- Anomalies paquet : 3273 · blocages nft : 3481
- Capture au début : 1 000 pkt/s gardés  pertes 0.0 % (noyau 0 · app 0)
- Capture à la fin : 7 560 pkt/s gardés  pertes 21.7 % (noyau 0 · app 792 876)

## 🧱 Étapes du pipeline (temps inclusif)

| Étape | % temps actif | secondes |
|---|---:|---:|
| detect() — boucle consommateur (total) |  17.5 % | 106.4 |
| extract_pack_features (par paquet) |   0.9 % | 5.7 |
| predict_packet (AE + IF + LOF) |  20.9 % | 126.5 |
|   dont IsolationForest (paquet) |  18.8 % | 114.0 |
|   dont LOF (paquet) |   0.8 % | 4.8 |
| extract_seq_features |   1.0 % | 5.9 |
| predict_sequence (CNN + AE + IF + LOF) |  16.0 % | 97.2 |
|   dont IsolationForest (séquence) |   0.7 % | 4.0 |
|   dont LOF (séquence) |   3.3 % | 20.0 |
| AnomalyScorer.detect_pkt (voie lente) |   5.8 % | 34.9 |
| log_anomaly / _add_alert |   0.4 % | 2.4 |
| persistance joblib/pickle (dump) |   0.4 % | 2.7 |
| logger.print |   6.1 % | 37.0 |
| blocage nft (_run_command / block) |  10.5 % | 63.8 |
| graphes (add_data*) |   0.2 % | 1.5 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| capture |  30.6 % | 185.9 |
| Python pur (ton code / autre) |  23.9 % | 145.1 |
| TensorFlow / Keras |  12.8 % | 77.7 |
| réaction nft / subprocess |  10.6 % | 64.6 |
| logs / print |   7.3 % | 44.2 |
| scikit-learn |   4.0 % | 24.6 |
| asyncio / threads / queue |   3.2 % | 19.7 |
| dpkt (parsing paquets) |   3.0 % | 18.3 |
| scoring / corrélation |   1.7 % | 10.1 |
| extraction de features |   1.3 % | 7.7 |
| numpy / scipy |   0.9 % | 5.3 |
| json / pickle / dill / joblib |   0.6 % | 3.6 |

## 🧵 Par thread / process

| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |
|---|---:|---:|---:|---|
| Process 190541 Thread 190701 "asyncio_0" | 187.5 |  30.9 % | 177.4 | _depths (fast_iforest.py) |
| Process 190541 Thread 190666 "Capture-veth_rx" | 185.7 |  30.6 % | 179.3 | _socket_capture (capture.py) |
| Process 190541 Thread 190595 "Detection Thread" | 116.2 |  19.1 % | 248.8 | unpack (dpkt.py) |
| Process 190541 Thread 190793 "BlockBatcher" | 64.0 |  10.5 % | 301.0 | cmd (nftables.py) |
| Process 190541 Thread 190792 "asyncio_1" | 27.9 |   4.6 % | 337.0 | quick_execute (execute.py) |
| Process 190541 Thread 190814 "asyncio_2" | 19.7 |   3.2 % | 345.3 | quick_execute (execute.py) |
| Process 190541 Thread 190794 "AnomalyWriter" | 4.8 |   0.8 % | 360.2 | _write (anomaly_logger.py) |
| Process 190541 Thread 195819 "asyncio_3" | 0.5 |   0.1 % | 81.6 | _write_to_self (selector_events.py) |
| Process 190541 Thread 190667 "Capture-Reporter" | 0.3 |   0.1 % | 364.7 | _rss_mb (capture.py) |
| Process 190541 Thread 190593 "API Thread" | 0.2 |   0.0 % | 364.8 | __schedule_callbacks (futures.py) |
| Process 190541 Thread 190541 "MainThread" | 0.0 |   0.0 % | 365.0 | time (base_events.py) |

## ⏱️ Top 20 fonctions — temps propre (self)

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  27.8 % | 168.6 |
| `_depths` (fast_iforest.py) |  19.3 % | 117.1 |
| `quick_execute` (execute.py) |  11.2 % | 67.8 |
| `cmd` (nftables.py) |   9.5 % | 57.5 |
| `compute` (_dispatcher.py) |   3.6 % | 21.7 |
| `unpack` (dpkt.py) |   1.8 % | 11.1 |
| `emit` (logger.py) |   1.8 % | 11.0 |
| `_write_to_self` (selector_events.py) |   1.4 % | 8.2 |
| `detect` (detection_module.py) |   1.3 % | 8.2 |
| `put` (queue.py) |   1.1 % | 6.4 |
| `_write` (anomaly_logger.py) |   0.8 % | 4.8 |
| `_detect_level` (logger.py) |   0.8 % | 4.6 |
| `is_blocked` (reaction_module.py) |   0.7 % | 4.4 |
| `_to_alert_entry` (detection_module.py) |   0.7 % | 4.1 |
| `extract_pack_features` (features_extractor.py) |   0.7 % | 4.1 |
| `src_ip_from_raw` (blocked_skip.py) |   0.6 % | 3.9 |
| `extract_seq_features` (features_extractor.py) |   0.6 % | 3.6 |
| `__init__` (__init__.py) |   0.6 % | 3.5 |
| `__enter__` (threading.py) |   0.5 % | 3.0 |
| `_is_blocked_inbound` (blocked_skip.py) |   0.5 % | 2.8 |

## ⏱️ Top 20 fonctions — temps inclusif

| Fonction | % | s |
|---|---:|---:|
| `_bootstrap` (threading.py) | 100.0 % | 606.9 |
| `run` (threading.py) | 100.0 % | 606.9 |
| `_bootstrap_inner` (threading.py) | 100.0 % | 606.9 |
| `_worker` (thread.py) |  38.8 % | 235.7 |
| `run` (thread.py) |  38.8 % | 235.6 |
| `_socket_capture` (capture.py) |  30.6 % | 185.7 |
| `_score_batch` (models.py) |  23.6 % | 143.3 |
| `predict_packet_batch` (models.py) |  20.8 % | 126.5 |
| `decision_function` (fast_iforest.py) |  19.4 % | 118.0 |
| `score_samples` (fast_iforest.py) |  19.4 % | 118.0 |
| `_depths` (fast_iforest.py) |  19.4 % | 117.7 |
| `run` (nest_asyncio.py) |  19.1 % | 116.2 |
| `run_until_complete` (nest_asyncio.py) |  19.1 % | 116.2 |
| `_run_async_detection` (orchestrator.py) |  19.1 % | 116.2 |
| `_run_once` (nest_asyncio.py) |  19.1 % | 116.0 |
| `_run` (events.py) |  19.1 % | 115.6 |
| `__wakeup` (tasks.py) |  18.3 % | 111.2 |
| `__step` (tasks.py) |  18.3 % | 111.1 |
| `_detection_coroutine` (orchestrator.py) |  17.5 % | 106.4 |
| `detect` (detection_module.py) |  17.5 % | 106.4 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  30.6 % | 185.7 |
| `_score_batch` (models.py) |  23.6 % | 143.3 |
| `predict_packet_batch` (models.py) |  20.8 % | 126.5 |
| `decision_function` (fast_iforest.py) |  19.4 % | 118.0 |
| `score_samples` (fast_iforest.py) |  19.4 % | 118.0 |
| `_depths` (fast_iforest.py) |  19.4 % | 117.7 |
| `_run_async_detection` (orchestrator.py) |  19.1 % | 116.2 |
| `_detection_coroutine` (orchestrator.py) |  17.5 % | 106.4 |
| `detect` (detection_module.py) |  17.5 % | 106.4 |
| `predict_sequence_batch` (models.py) |  16.0 % | 97.2 |
| `_run_bucketed` (models.py) |  12.9 % | 78.5 |
| `_run` (block_batcher.py) |  10.5 % | 64.0 |
| `_flush` (block_batcher.py) |  10.5 % | 64.0 |
| `_commit` (block_batcher.py) |  10.5 % | 64.0 |
| `_run_command` (reaction_module.py) |  10.5 % | 63.8 |
| `_predict_ae_seq` (models.py) |   7.2 % | 43.9 |
| `_drain_entries` (detection_module.py) |   5.8 % | 35.1 |
| `detect_pkt` (anomaly_scorer.py) |   5.8 % | 34.9 |
| `_predict_cnn_seq` (models.py) |   3.5 % | 21.0 |
| `update` (anomaly_scorer.py) |   2.8 % | 17.1 |

## 📍 Top 20 lignes chaudes

| Ligne | % |
|---|---:|
| `_socket_capture` — capture.py:988 |  24.7 % |
| `_depths` — fast_iforest.py:97 |  11.8 % |
| `quick_execute` — execute.py:53 |  11.2 % |
| `cmd` — nftables.py:410 |   9.1 % |
| `_depths` — fast_iforest.py:98 |   5.1 % |
| `compute` — _dispatcher.py:278 |   3.6 % |
| `_socket_capture` — capture.py:1002 |   1.9 % |
| `emit` — logger.py:57 |   1.7 % |
| `_depths` — fast_iforest.py:96 |   1.6 % |
| `unpack` — dpkt.py:344 |   1.5 % |
| `_write_to_self` — selector_events.py:139 |   1.4 % |
| `_write` — anomaly_logger.py:228 |   0.7 % |
| `extract_pack_features` — features_extractor.py:255 |   0.6 % |
| `_to_alert_entry` — detection_module.py:403 |   0.6 % |
| `_depths` — fast_iforest.py:99 |   0.6 % |
| `extract_seq_features` — features_extractor.py:262 |   0.6 % |
| `put` — queue.py:133 |   0.5 % |
| `__enter__` — threading.py:272 |   0.5 % |
| `src_ip_from_raw` — blocked_skip.py:68 |   0.4 % |
| `_is_owned` — threading.py:289 |   0.4 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **24.7 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **11.4 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **11.2 %** quick_execute (execute.py) ← call_function (context.py) ← call_flat (atomic_function.py) ← call_preflattened (atomic_function.py) ← _call_flat (concrete_function.py) ← call_function (tracing_compilation.py) ← _call (polymorphic_function.py)
- **9.1 %** cmd (nftables.py) ← _run_command (reaction_module.py) ← _commit (block_batcher.py) ← _flush (block_batcher.py) ← _run (block_batcher.py) ← run (threading.py) ← _bootstrap_inner (threading.py)
- **5.0 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **3.0 %** compute (_dispatcher.py) ← kneighbors (_base.py) ← score_samples (_lof.py) ← decision_function (_lof.py) ← _score_batch (models.py) ← predict_sequence_batch (models.py) ← run (thread.py)
- **1.9 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **1.7 %** emit (logger.py) ← handle (__init__.py) ← callHandlers (__init__.py) ← handle (__init__.py) ← _log (__init__.py) ← log (__init__.py) ← print (logger.py)
- **1.6 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **1.4 %** _write_to_self (selector_events.py) ← call_soon_threadsafe (base_events.py) ← _call_set_state (futures.py) ← _invoke_callbacks (_base.py) ← set_result (_base.py) ← run (thread.py) ← _worker (thread.py)


## 🎚️ Phases de trafic (débit mesuré par l'IDS)

| Début | Fin | Trafic injecté | Relevés | pkt/s moyen | pkt/s max | Perte cumulée (fin de phase) |
|---|---|---|---|---|---|---|
| 0s | 60s | `normal @ pps=1000` | 12 | 1 000 | 1 011 | 0.00 % |
| 60s | 60s | `attack @ pps=1000` | 0 | – | – | – |
| 60s | 120s | `attack @ pps=5000` | 12 | 4 666 | 5 267 | 0.00 % |
| 120s | 200s | `attack @ pps=10000` | 16 | 9 328 | 10 263 | 0.00 % |
| 200s | 300s | `attack @ pps=15000` | 20 | 12 798 | 15 584 | 5.35 % |
| 300s | 364s | `attack @ pps=20000` | 12 | 7 827 | 8 796 | 21.73 % |
