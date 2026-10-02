# Rapport de profilage IDS/IPS — 2026-10-01 08:24:22

- Temps **actif** (hors attentes) : **2598.2 s** cumulés sur 30 thread(s)/process pour **363 s** de fenêtre · attentes ignorées (epoll/futex/sleep/wait) : 2146.4 s
- Les pourcentages sont relatifs au temps actif total. ⚠️ `--native` en mode bloquant ralentit fortement la cible : fie-toi aux PROPORTIONS, pas au débit absolu.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (feuille) : **asyncio / threads / queue** (43.4 %)
- Étape du pipeline la plus coûteuse : **predict_sequence (CNN + AE + IF + LOF)** (8.8 %)
- 💡 Les logs coûtent cher → verbose=0 pendant les benchs, ou logger via une queue asynchrone.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **2899** → 7.99/s (≈ 7.99 paquets/s traités si stride=1)
- Anomalies paquet : 81 · blocages nft : 1083
- Capture au début : 22 393 pkt/s gardés  pertes 85.5 % (noyau 4 281 159 · app 0)
- Capture à la fin : 5 pkt/s gardés  pertes 99.4 % (noyau 167 027 213 · app 12 310 345)

## 🧱 Étapes du pipeline (temps inclusif)

| Étape | % temps actif | secondes |
|---|---:|---:|
| detect() — boucle consommateur (total) |   0.2 % | 4.1 |
| extract_pack_features (par paquet) |   0.0 % | 0.1 |
| predict_packet (AE + IF + LOF, batch=1) |   4.5 % | 117.3 |
| extract_seq_features |   0.0 % | 0.8 |
| predict_sequence (CNN + AE + IF + LOF) |   8.8 % | 228.0 |
|   dont IsolationForest.decision_function |  10.4 % | 269.5 |
|   dont LOF.decision_function |   0.7 % | 17.0 |
| AnomalyScorer.detect_pkt (voie lente) |   0.0 % | 1.3 |
| log_anomaly / _add_alert |   0.0 % | 0.1 |
| persistance joblib/pickle (dump) |   0.0 % | 0.1 |
| logger.print |   0.1 % | 1.7 |
| blocage nft (_run_command / block) |   0.1 % | 2.8 |
| graphes (add_data*) |   0.0 % | 0.1 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| asyncio / threads / queue |  43.4 % | 1127.1 |
| capture |  28.1 % | 729.9 |
| logs / print |  14.1 % | 366.8 |
| scikit-learn |  10.8 % | 280.7 |
| TensorFlow / Keras |   2.2 % | 56.2 |
| Python pur (ton code / autre) |   0.9 % | 22.7 |
| numpy / scipy |   0.3 % | 7.0 |
| json / pickle / dill / joblib |   0.1 % | 3.6 |
| réaction nft / subprocess |   0.1 % | 3.0 |
| extraction de features |   0.0 % | 0.6 |
| scoring / corrélation |   0.0 % | 0.5 |
| dpkt (parsing paquets) |   0.0 % | 0.1 |

## 🧵 Par thread / process

| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |
|---|---:|---:|---:|---|
| Process 40156 Thread 40406 "AnomalyWriter" | 729.9 |  28.1 % | 0.0 | wait (threading.py) |
| Process 40156 Thread 40206 "API Thread" | 365.0 |  14.0 % | 0.0 | run (runners.py) |
| Process 40156 Thread 40256 "Thread-3 (save_periodic)" | 365.0 |  14.0 % | 0.0 | save_periodic (refit_queue.py) |
| Process 40156 Thread 40257 "Capture-veth_rx" | 365.0 |  14.0 % | 0.0 | _socket_capture (capture.py) |
| Process 40156 Thread 40258 "Capture-Reporter" | 365.0 |  14.0 % | 0.0 | wait (threading.py) |
| Process 40156 Thread 40395 "asyncio_1" | 365.0 |  14.0 % | 0.0 | _worker (thread.py) |
| Process 40156 Thread 40208 "Detection Thread" | 43.3 |   1.7 % | 321.6 | _strptime (_strptime.py) |
| Process 40156 Thread 40156 "MainThread" | 0.0 |   0.0 % | 364.9 | sleep (tasks.py) |
| Process 40156 Thread 40209 "Thread-2 (start_server)" | 0.0 |   0.0 % | 365.0 | isEnabledFor (__init__.py) |

## ⏱️ Top 20 fonctions — temps propre (self)

| Fonction | % | s |
|---|---:|---:|
| `wait` (threading.py) |  28.1 % | 729.6 |
| `_worker` (thread.py) |  14.6 % | 380.3 |
| `save_periodic` (refit_queue.py) |  14.0 % | 365.0 |
| `run` (runners.py) |  14.0 % | 364.7 |
| `_socket_capture` (capture.py) |  13.2 % | 343.1 |
| `_compute_score_samples` (_iforest.py) |   6.3 % | 162.7 |
| `apply` (_classes.py) |   1.9 % | 49.7 |
| `quick_execute` (execute.py) |   1.7 % | 44.3 |
| `<listcomp>` (validation.py) |   0.8 % | 21.6 |
| `_num_features` (validation.py) |   0.5 % | 11.8 |
| `compute` (_dispatcher.py) |   0.4 % | 11.2 |
| `put` (queue.py) |   0.3 % | 7.6 |
| `_is_fitted` (validation.py) |   0.3 % | 6.9 |
| `_put` (capture.py) |   0.2 % | 6.0 |
| `_strptime` (_strptime.py) |   0.2 % | 5.6 |
| `check_is_fitted` (validation.py) |   0.2 % | 4.2 |
| `_check_n_features` (base.py) |   0.1 % | 3.0 |
| `_run_once` (nest_asyncio.py) |   0.1 % | 2.9 |
| `_parse_eve_timestamp` (suricata_integration.py) |   0.1 % | 2.8 |
| `cmd` (nftables.py) |   0.1 % | 2.7 |

## ⏱️ Top 20 fonctions — temps inclusif

| Fonction | % | s |
|---|---:|---:|
| `run` (threading.py) | 100.0 % | 2598.2 |
| `_bootstrap` (threading.py) | 100.0 % | 2598.2 |
| `_bootstrap_inner` (threading.py) | 100.0 % | 2598.2 |
| `_worker` (thread.py) |  28.1 % | 729.9 |
| `wait` (threading.py) |  28.1 % | 729.6 |
| `run` (server.py) |  14.0 % | 365.0 |
| `run` (runners.py) |  14.0 % | 365.0 |
| `asyncio_run` (_compat.py) |  14.0 % | 365.0 |
| `save_periodic` (refit_queue.py) |  14.0 % | 365.0 |
| `_socket_capture` (capture.py) |  14.0 % | 365.0 |
| `_reporter` (capture.py) |  14.0 % | 365.0 |
| `_run` (anomaly_logger.py) |  14.0 % | 365.0 |
| `get` (queue.py) |  14.0 % | 364.8 |
| `run` (thread.py) |  13.5 % | 349.6 |
| `decision_function` (_iforest.py) |  10.4 % | 269.5 |
| `score_samples` (_iforest.py) |  10.4 % | 269.4 |
| `_score_samples` (_iforest.py) |  10.3 % | 268.1 |
| `_compute_chunked_score_samples` (_iforest.py) |  10.3 % | 268.0 |
| `_compute_score_samples` (_iforest.py) |  10.3 % | 267.0 |
| `predict_sequence` (models.py) |   8.8 % | 227.8 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif

| Fonction | % | s |
|---|---:|---:|
| `save_periodic` (refit_queue.py) |  14.0 % | 365.0 |
| `_socket_capture` (capture.py) |  14.0 % | 365.0 |
| `_reporter` (capture.py) |  14.0 % | 365.0 |
| `_run` (anomaly_logger.py) |  14.0 % | 365.0 |
| `predict_sequence` (models.py) |   8.8 % | 227.8 |
| `predict_packet` (models.py) |   4.5 % | 117.2 |
| `_run_async_detection` (orchestrator.py) |   1.7 % | 43.3 |
| `monitor_suricata_alerts` (detection_module.py) |   1.1 % | 29.6 |
| `_predict_ae_seq` (models.py) |   0.9 % | 24.5 |
| `parse_eve_line` (suricata_integration.py) |   0.9 % | 22.3 |
| `_put` (capture.py) |   0.8 % | 21.8 |
| `_predict_cnn_seq` (models.py) |   0.6 % | 16.1 |
| `_parse_eve_timestamp` (suricata_integration.py) |   0.4 % | 11.7 |
| `_predict_cnn_memory` (models.py) |   0.4 % | 10.0 |
| `_predict_ae_pkt` (models.py) |   0.2 % | 5.8 |
| `__contains__` (suricata_integration.py) |   0.2 % | 5.3 |
| `is_local_ip` (suricata_integration.py) |   0.2 % | 5.1 |
| `detect` (detection_module.py) |   0.2 % | 4.1 |
| `_detection_coroutine` (orchestrator.py) |   0.2 % | 4.1 |
| `action` (anomaly_scorer.py) |   0.1 % | 3.0 |

## 📍 Top 20 lignes chaudes

| Ligne | % |
|---|---:|
| `wait` — threading.py:331 |  28.1 % |
| `_worker` — thread.py:81 |  14.6 % |
| `save_periodic` — refit_queue.py:102 |  14.0 % |
| `run` — runners.py:118 |  14.0 % |
| `_socket_capture` — capture.py:971 |  12.3 % |
| `_compute_score_samples` — _iforest.py:506 |   3.9 % |
| `apply` — _classes.py:582 |   1.8 % |
| `quick_execute` — execute.py:53 |   1.7 % |
| `_compute_score_samples` — _iforest.py:511 |   0.9 % |
| `_compute_score_samples` — _iforest.py:512 |   0.7 % |
| `<listcomp>` — validation.py:1553 |   0.7 % |
| `_socket_capture` — capture.py:985 |   0.6 % |
| `_compute_score_samples` — _iforest.py:513 |   0.4 % |
| `compute` — _dispatcher.py:278 |   0.4 % |
| `_compute_score_samples` — _iforest.py:508 |   0.2 % |
| `<listcomp>` — validation.py:1552 |   0.2 % |
| `put` — queue.py:137 |   0.1 % |
| `_put` — capture.py:830 |   0.1 % |
| `_num_features` — validation.py:336 |   0.1 % |
| `put` — queue.py:133 |   0.1 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **14.6 %** _worker (thread.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **14.0 %** save_periodic (refit_queue.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **14.0 %** wait (threading.py) ← get (queue.py) ← _run (anomaly_logger.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **14.0 %** wait (threading.py) ← wait (threading.py) ← _reporter (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **14.0 %** run (runners.py) ← asyncio_run (_compat.py) ← run (server.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **12.3 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **2.6 %** _compute_score_samples (_iforest.py) ← _compute_chunked_score_samples (_iforest.py) ← _score_samples (_iforest.py) ← score_samples (_iforest.py) ← decision_function (_iforest.py) ← predict_sequence (models.py) ← run (thread.py)
- **1.7 %** quick_execute (execute.py) ← call_function (context.py) ← call_flat (atomic_function.py) ← call_preflattened (atomic_function.py) ← _call_flat (concrete_function.py) ← call_function (tracing_compilation.py) ← _call (polymorphic_function.py)
- **1.0 %** apply (_classes.py) ← _compute_score_samples (_iforest.py) ← _compute_chunked_score_samples (_iforest.py) ← _score_samples (_iforest.py) ← score_samples (_iforest.py) ← decision_function (_iforest.py) ← predict_packet (models.py)
- **0.7 %** _compute_score_samples (_iforest.py) ← _compute_chunked_score_samples (_iforest.py) ← _score_samples (_iforest.py) ← score_samples (_iforest.py) ← decision_function (_iforest.py) ← predict (_iforest.py) ← predict_sequence (models.py)
