# Rapport de profilage IDS/IPS — 2026-10-01 10:48:13

- Temps **actif** (hors attentes) : **767.2 s** cumulés sur 41 thread(s)/process pour **371 s** de fenêtre · attentes ignorées (wait/sleep/queue.get/epoll…) : 4065.1 s
- Les pourcentages sont relatifs au temps actif total. ⚠️ `--native` en mode bloquant ralentit fortement la cible : fie-toi aux PROPORTIONS, pas au débit absolu.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (feuille) : **capture** (47.6 %)
- Étape du pipeline la plus coûteuse : **predict_packet (AE + IF + LOF)** (22.4 %)
- Inférence (paquet + séquence) active **340 s sur 371 s** de fenêtre (92 %) → 🚨 **consommateur SATURÉ** : le débit max est celui de l'inférence, la capture/la file débordent.
- 💡 `predict_packet` pèse lourd → vérifier la taille des lots (`detect_batch_size`) ; sinon réduire `n_estimators` / `n_neighbors`.
- 💡 sklearn domine (IF/LOF sur 1 échantillon) → batcher, réduire `n_estimators` / `n_neighbors`, éviter le lock.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **3212** → 8.67/s (≈ 86.68 paquets/s traités, stride=10)
- Anomalies paquet : 985 · blocages nft : 1497
- Capture au début : 30 815 pkt/s gardés  pertes 80.1 % (noyau 4 190 982 · app 0)
- Capture à la fin : 102 pkt/s gardés  pertes 98.8 % (noyau 87 478 189 · app 7 459 264)

## 🧱 Étapes du pipeline (temps inclusif)

| Étape | % temps actif | secondes |
|---|---:|---:|
| detect() — boucle consommateur (total) |   1.3 % | 9.7 |
| extract_pack_features (par paquet) |   0.1 % | 0.5 |
| predict_packet (AE + IF + LOF) |  22.4 % | 171.9 |
|   dont IsolationForest (paquet) |  20.3 % | 155.4 |
|   dont LOF (paquet) |   1.1 % | 8.3 |
| extract_seq_features |   0.2 % | 1.4 |
| predict_sequence (CNN + AE + IF + LOF) |  21.9 % | 168.1 |
|   dont IsolationForest (séquence) |  15.7 % | 120.2 |
|   dont LOF (séquence) |   1.3 % | 9.7 |
| AnomalyScorer.detect_pkt (voie lente) |   0.4 % | 3.3 |
| log_anomaly / _add_alert |   0.0 % | 0.2 |
| persistance joblib/pickle (dump) |   0.0 % | 0.1 |
| logger.print |   0.5 % | 3.5 |
| blocage nft (_run_command / block) |   0.3 % | 2.5 |
| graphes (add_data*) |   0.0 % | 0.1 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| capture |  47.6 % | 365.4 |
| scikit-learn |  37.6 % | 288.5 |
| TensorFlow / Keras |   5.8 % | 44.1 |
| Python pur (ton code / autre) |   3.6 % | 27.8 |
| asyncio / threads / queue |   2.4 % | 18.4 |
| numpy / scipy |   0.9 % | 6.7 |
| json / pickle / dill / joblib |   0.7 % | 5.3 |
| logs / print |   0.5 % | 3.9 |
| réaction nft / subprocess |   0.3 % | 2.6 |
| dpkt (parsing paquets) |   0.2 % | 1.9 |
| scoring / corrélation |   0.2 % | 1.4 |
| extraction de features |   0.2 % | 1.2 |

## 🧵 Par thread / process

| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |
|---|---:|---:|---:|---|
| Process 68773 Thread 68877 "Capture-veth_rx" | 365.0 |  47.6 % | 0.0 | _socket_capture (capture.py) |
| Process 68773 Thread 68932 "asyncio_0" | 204.8 |  26.7 % | 160.2 | _compute_score_samples (_iforest.py) |
| Process 68773 Thread 69025 "asyncio_1" | 129.0 |  16.8 % | 236.0 | _compute_score_samples (_iforest.py) |
| Process 68773 Thread 68823 "Detection Thread" | 56.0 |   7.3 % | 309.0 | _strptime (_strptime.py) |
| Process 68773 Thread 69522 "asyncio_2" | 11.4 |   1.5 % | 76.1 | _compute_score_samples (_iforest.py) |
| Process 68773 Thread 68878 "Capture-Reporter" | 0.5 |   0.1 % | 364.5 | _rss_mb (capture.py) |
| Process 68773 Thread 69035 "AnomalyWriter" | 0.2 |   0.0 % | 364.7 | _write (anomaly_logger.py) |
| Process 68773 Thread 68821 "API Thread" | 0.2 |   0.0 % | 364.8 | __schedule_callbacks (futures.py) |
| Process 68773 Thread 68773 "MainThread" | 0.0 |   0.0 % | 365.0 | __step (tasks.py) |
| Process 68773 Thread 68824 "Thread-2 (start_server)" | 0.0 |   0.0 % | 365.0 | create_task (base_events.py) |

## ⏱️ Top 20 fonctions — temps propre (self)

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  44.6 % | 342.4 |
| `_compute_score_samples` (_iforest.py) |  20.8 % | 159.5 |
| `apply` (_classes.py) |   8.6 % | 65.6 |
| `quick_execute` (execute.py) |   4.6 % | 35.3 |
| `<listcomp>` (validation.py) |   2.4 % | 18.1 |
| `compute` (_dispatcher.py) |   1.7 % | 13.1 |
| `_num_features` (validation.py) |   1.4 % | 10.6 |
| `put` (queue.py) |   1.0 % | 8.0 |
| `_strptime` (_strptime.py) |   1.0 % | 7.3 |
| `_put` (capture.py) |   0.9 % | 6.7 |
| `_is_fitted` (validation.py) |   0.8 % | 6.0 |
| `_parse_eve_timestamp` (suricata_integration.py) |   0.5 % | 4.1 |
| `raw_decode` (decoder.py) |   0.5 % | 3.6 |
| `check_is_fitted` (validation.py) |   0.5 % | 3.6 |
| `_check_n_features` (base.py) |   0.4 % | 2.9 |
| `_strptime_datetime` (_strptime.py) |   0.3 % | 2.4 |
| `__instancecheck__` (<frozen abc>) |   0.3 % | 2.2 |
| `cmd` (nftables.py) |   0.3 % | 2.2 |
| `_read_from_self` (selector_events.py) |   0.3 % | 2.2 |
| `parse_eve_line` (suricata_integration.py) |   0.3 % | 2.1 |

## ⏱️ Top 20 fonctions — temps inclusif

| Fonction | % | s |
|---|---:|---:|
| `run` (threading.py) | 100.0 % | 767.1 |
| `_bootstrap_inner` (threading.py) | 100.0 % | 767.1 |
| `_bootstrap` (threading.py) | 100.0 % | 767.1 |
| `_socket_capture` (capture.py) |  47.6 % | 365.0 |
| `_worker` (thread.py) |  45.0 % | 345.1 |
| `run` (thread.py) |  45.0 % | 345.1 |
| `decision_function` (_iforest.py) |  35.9 % | 275.6 |
| `score_samples` (_iforest.py) |  35.9 % | 275.5 |
| `_score_samples` (_iforest.py) |  35.7 % | 274.3 |
| `_compute_chunked_score_samples` (_iforest.py) |  35.7 % | 274.2 |
| `_compute_score_samples` (_iforest.py) |  35.6 % | 273.1 |
| `predict_packet` (models.py) |  18.8 % | 144.2 |
| `predict_sequence` (models.py) |  15.4 % | 118.0 |
| `apply` (_classes.py) |  14.7 % | 112.6 |
| `predict` (_iforest.py) |  13.8 % | 106.1 |
| `_score_batch` (models.py) |   8.2 % | 62.9 |
| `run_until_complete` (nest_asyncio.py) |   7.3 % | 56.0 |
| `run` (nest_asyncio.py) |   7.3 % | 56.0 |
| `_run_async_detection` (orchestrator.py) |   7.3 % | 56.0 |
| `_run_once` (nest_asyncio.py) |   7.2 % | 55.4 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  47.6 % | 365.0 |
| `predict_packet` (models.py) |  18.8 % | 144.2 |
| `predict_sequence` (models.py) |  15.4 % | 118.0 |
| `_score_batch` (models.py) |   8.2 % | 62.9 |
| `_run_async_detection` (orchestrator.py) |   7.3 % | 56.0 |
| `predict_sequence_batch` (models.py) |   6.5 % | 50.0 |
| `monitor_suricata_alerts` (detection_module.py) |   4.7 % | 36.3 |
| `parse_eve_line` (suricata_integration.py) |   3.7 % | 28.7 |
| `predict_packet_batch` (models.py) |   3.6 % | 27.5 |
| `_put` (capture.py) |   2.9 % | 22.6 |
| `_predict_ae_seq` (models.py) |   2.4 % | 18.4 |
| `_parse_eve_timestamp` (suricata_integration.py) |   2.0 % | 15.2 |
| `_run_bucketed` (models.py) |   1.8 % | 14.1 |
| `_predict_cnn_seq` (models.py) |   1.6 % | 12.0 |
| `_detection_coroutine` (orchestrator.py) |   1.3 % | 9.7 |
| `detect` (detection_module.py) |   1.3 % | 9.7 |
| `_predict_ae_pkt` (models.py) |   1.0 % | 7.4 |
| `_predict_cnn_memory` (models.py) |   0.8 % | 6.5 |
| `__contains__` (suricata_integration.py) |   0.8 % | 6.4 |
| `is_local_ip` (suricata_integration.py) |   0.8 % | 6.3 |

## 📍 Top 20 lignes chaudes

| Ligne | % |
|---|---:|
| `_socket_capture` — capture.py:971 |  41.7 % |
| `_compute_score_samples` — _iforest.py:506 |  13.3 % |
| `apply` — _classes.py:582 |   8.3 % |
| `quick_execute` — execute.py:53 |   4.6 % |
| `_compute_score_samples` — _iforest.py:511 |   2.6 % |
| `_compute_score_samples` — _iforest.py:512 |   2.4 % |
| `_socket_capture` — capture.py:985 |   1.9 % |
| `<listcomp>` — validation.py:1553 |   1.9 % |
| `compute` — _dispatcher.py:278 |   1.7 % |
| `_compute_score_samples` — _iforest.py:513 |   1.3 % |
| `_compute_score_samples` — _iforest.py:508 |   0.7 % |
| `_put` — capture.py:830 |   0.5 % |
| `<listcomp>` — validation.py:1552 |   0.5 % |
| `raw_decode` — decoder.py:353 |   0.5 % |
| `put` — queue.py:133 |   0.4 % |
| `_compute_score_samples` — _iforest.py:503 |   0.4 % |
| `put` — queue.py:137 |   0.4 % |
| `_num_features` — validation.py:336 |   0.4 % |
| `_put` — capture.py:831 |   0.3 % |
| `_is_fitted` — validation.py:1553 |   0.3 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **41.7 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **4.6 %** quick_execute (execute.py) ← call_function (context.py) ← call_flat (atomic_function.py) ← call_preflattened (atomic_function.py) ← _call_flat (concrete_function.py) ← call_function (tracing_compilation.py) ← _call (polymorphic_function.py)
- **3.7 %** _compute_score_samples (_iforest.py) ← _compute_chunked_score_samples (_iforest.py) ← _score_samples (_iforest.py) ← score_samples (_iforest.py) ← decision_function (_iforest.py) ← _score_batch (models.py) ← predict_sequence_batch (models.py)
- **3.2 %** _compute_score_samples (_iforest.py) ← _compute_chunked_score_samples (_iforest.py) ← _score_samples (_iforest.py) ← score_samples (_iforest.py) ← decision_function (_iforest.py) ← predict_sequence (models.py) ← run (thread.py)
- **3.2 %** _compute_score_samples (_iforest.py) ← _compute_chunked_score_samples (_iforest.py) ← _score_samples (_iforest.py) ← score_samples (_iforest.py) ← decision_function (_iforest.py) ← predict (_iforest.py) ← predict_sequence (models.py)
- **3.0 %** apply (_classes.py) ← _compute_score_samples (_iforest.py) ← _compute_chunked_score_samples (_iforest.py) ← _score_samples (_iforest.py) ← score_samples (_iforest.py) ← decision_function (_iforest.py) ← predict (_iforest.py)
- **2.5 %** apply (_classes.py) ← _compute_score_samples (_iforest.py) ← _compute_chunked_score_samples (_iforest.py) ← _score_samples (_iforest.py) ← score_samples (_iforest.py) ← decision_function (_iforest.py) ← predict_packet (models.py)
- **2.1 %** apply (_classes.py) ← _compute_score_samples (_iforest.py) ← _compute_chunked_score_samples (_iforest.py) ← _score_samples (_iforest.py) ← score_samples (_iforest.py) ← decision_function (_iforest.py) ← _score_batch (models.py)
- **1.9 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **1.9 %** <listcomp> (validation.py) ← _is_fitted (validation.py) ← check_is_fitted (validation.py) ← apply (_classes.py) ← _compute_score_samples (_iforest.py) ← _compute_chunked_score_samples (_iforest.py) ← _score_samples (_iforest.py)
