# Rapport de profilage IDS/IPS — 2026-10-01 17:53:08

- Temps **actif** (hors attentes) : **740.5 s** cumulés sur 41 thread(s)/process pour **365 s** de fenêtre · attentes ignorées (wait/sleep/queue.get/epoll…) : 4173.6 s
- Les pourcentages sont relatifs au temps actif total. ⚠️ `--native` en mode bloquant ralentit fortement la cible : fie-toi aux PROPORTIONS, pas au débit absolu.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (feuille) : **capture** (49.3 %)
- Étape du pipeline la plus coûteuse : **blocage nft (_run_command / block)** (13.4 %)
- Inférence (paquet + séquence) active **99 s sur 365 s** de fenêtre (27 %) → le consommateur n'est pas saturé.
- 💡 Les commandes nft sont bloquantes dans la boucle → file d'attente dédiée + ne pas re-bloquer une IP déjà bloquée.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **5248** → 14.39/s (≈ 287.78 paquets/s traités, stride=20)
- Anomalies paquet : 14896 · blocages nft : 19245
- Capture au début : 47 430 pkt/s gardés  pertes 73.7 % (noyau 2 728 081 · app 0)
- Capture à la fin : 411 pkt/s gardés  pertes 98.5 % (noyau 69 907 867 · app 12 026 477)

## 🧱 Étapes du pipeline (temps inclusif)

| Étape | % temps actif | secondes |
|---|---:|---:|
| detect() — boucle consommateur (total) |  13.5 % | 99.7 |
| extract_pack_features (par paquet) |   0.4 % | 2.9 |
| predict_packet (AE + IF + LOF) |   7.8 % | 57.9 |
|   dont IsolationForest (paquet) |   7.0 % | 51.8 |
|   dont LOF (paquet) |   0.4 % | 2.8 |
| extract_seq_features |   0.8 % | 5.9 |
| predict_sequence (CNN + AE + IF + LOF) |   5.6 % | 41.2 |
|   dont IsolationForest (séquence) |   0.5 % | 3.6 |
|   dont LOF (séquence) |   1.2 % | 8.6 |
| AnomalyScorer.detect_pkt (voie lente) |   8.3 % | 61.1 |
| log_anomaly / _add_alert |   0.4 % | 2.8 |
| persistance joblib/pickle (dump) |   0.1 % | 1.1 |
| logger.print |   7.4 % | 55.0 |
| blocage nft (_run_command / block) |  13.4 % | 99.1 |
| graphes (add_data*) |   0.2 % | 1.2 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| capture |  49.3 % | 365.1 |
| réaction nft / subprocess |  13.5 % | 99.7 |
| Python pur (ton code / autre) |  10.8 % | 80.3 |
| logs / print |   7.9 % | 58.7 |
| asyncio / threads / queue |   6.5 % | 48.1 |
| TensorFlow / Keras |   4.2 % | 30.9 |
| scoring / corrélation |   2.3 % | 16.7 |
| scikit-learn |   1.5 % | 11.1 |
| dpkt (parsing paquets) |   1.5 % | 11.1 |
| json / pickle / dill / joblib |   1.2 % | 9.2 |
| extraction de features |   0.7 % | 5.3 |
| numpy / scipy |   0.6 % | 4.2 |

## 🧵 Par thread / process

| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |
|---|---:|---:|---:|---|
| Process 123542 Thread 123661 "Capture-veth_rx" | 365.0 |  49.3 % | 0.0 | _socket_capture (capture.py) |
| Process 123542 Thread 123695 "asyncio_0" | 159.0 |  21.5 % | 206.0 | cmd (nftables.py) |
| Process 123542 Thread 123589 "Detection Thread" | 144.9 |  19.6 % | 220.1 | emit (logger.py) |
| Process 123542 Thread 123787 "asyncio_1" | 53.6 |   7.2 % | 311.3 | cmd (nftables.py) |
| Process 123542 Thread 125328 "asyncio_2" | 16.8 |   2.3 % | 152.5 | cmd (nftables.py) |
| Process 123542 Thread 123786 "AnomalyWriter" | 0.9 |   0.1 % | 364.1 | _write (anomaly_logger.py) |
| Process 123542 Thread 123662 "Capture-Reporter" | 0.2 |   0.0 % | 364.8 | _rss_mb (capture.py) |
| Process 123542 Thread 123587 "API Thread" | 0.1 |   0.0 % | 364.8 | main_loop (server.py) |
| Process 123542 Thread 123590 "Thread-2 (start_server)" | 0.0 |   0.0 % | 365.0 | result (futures.py) |

## ⏱️ Top 20 fonctions — temps propre (self)

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  41.7 % | 308.7 |
| `cmd` (nftables.py) |  12.8 % | 94.8 |
| `_depths` (fast_iforest.py) |   7.4 % | 55.0 |
| `quick_execute` (execute.py) |   3.8 % | 28.2 |
| `_write_to_self` (selector_events.py) |   3.0 % | 22.1 |
| `put` (queue.py) |   3.0 % | 21.9 |
| `_put` (capture.py) |   2.1 % | 15.4 |
| `emit` (logger.py) |   1.9 % | 13.8 |
| `compute` (_dispatcher.py) |   1.4 % | 10.0 |
| `_detect_level` (logger.py) |   1.2 % | 8.9 |
| `_read_from_self` (selector_events.py) |   1.0 % | 7.3 |
| `unpack` (dpkt.py) |   0.9 % | 6.3 |
| `__init__` (__init__.py) |   0.7 % | 5.4 |
| `__enter__` (threading.py) |   0.7 % | 5.2 |
| `detect` (detection_module.py) |   0.7 % | 5.1 |
| `__exit__` (threading.py) |   0.7 % | 5.0 |
| `put_nowait` (queue.py) |   0.6 % | 4.7 |
| `_parse_eve_timestamp` (suricata_integration.py) |   0.6 % | 4.4 |
| `formatTime` (__init__.py) |   0.5 % | 3.9 |
| `raw_decode` (decoder.py) |   0.5 % | 3.8 |

## ⏱️ Top 20 fonctions — temps inclusif

| Fonction | % | s |
|---|---:|---:|
| `_bootstrap` (threading.py) | 100.0 % | 740.5 |
| `run` (threading.py) | 100.0 % | 740.5 |
| `_bootstrap_inner` (threading.py) | 100.0 % | 740.5 |
| `_socket_capture` (capture.py) |  49.3 % | 365.0 |
| `_worker` (thread.py) |  31.0 % | 229.4 |
| `run` (thread.py) |  31.0 % | 229.2 |
| `_run_async_detection` (orchestrator.py) |  19.6 % | 144.9 |
| `run` (nest_asyncio.py) |  19.6 % | 144.9 |
| `run_until_complete` (nest_asyncio.py) |  19.6 % | 144.9 |
| `_run_once` (nest_asyncio.py) |  19.5 % | 144.3 |
| `_run` (events.py) |  19.4 % | 143.4 |
| `__wakeup` (tasks.py) |  17.7 % | 130.8 |
| `__step` (tasks.py) |  17.6 % | 130.4 |
| `action` (anomaly_scorer.py) |  14.4 % | 106.3 |
| `_detection_coroutine` (orchestrator.py) |  13.5 % | 99.7 |
| `detect` (detection_module.py) |  13.5 % | 99.7 |
| `block` (reaction_module.py) |  13.4 % | 99.1 |
| `_run_command` (reaction_module.py) |  13.4 % | 99.0 |
| `cmd` (nftables.py) |  12.8 % | 94.8 |
| `_score_batch` (models.py) |   9.0 % | 66.8 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  49.3 % | 365.0 |
| `_run_async_detection` (orchestrator.py) |  19.6 % | 144.9 |
| `action` (anomaly_scorer.py) |  14.4 % | 106.3 |
| `_detection_coroutine` (orchestrator.py) |  13.5 % | 99.7 |
| `detect` (detection_module.py) |  13.5 % | 99.7 |
| `block` (reaction_module.py) |  13.4 % | 99.1 |
| `_run_command` (reaction_module.py) |  13.4 % | 99.0 |
| `_score_batch` (models.py) |   9.0 % | 66.8 |
| `detect_pkt` (anomaly_scorer.py) |   8.3 % | 61.1 |
| `predict_packet_batch` (models.py) |   7.8 % | 57.8 |
| `_put` (capture.py) |   7.6 % | 56.2 |
| `decision_function` (fast_iforest.py) |   7.5 % | 55.4 |
| `score_samples` (fast_iforest.py) |   7.5 % | 55.3 |
| `_depths` (fast_iforest.py) |   7.5 % | 55.3 |
| `predict_sequence_batch` (models.py) |   5.6 % | 41.2 |
| `_run_bucketed` (models.py) |   4.2 % | 31.4 |
| `monitor_suricata_alerts` (detection_module.py) |   3.8 % | 28.4 |
| `update` (anomaly_scorer.py) |   3.7 % | 27.3 |
| `parse_eve_line` (suricata_integration.py) |   2.6 % | 19.2 |
| `_predict_ae_seq` (models.py) |   2.4 % | 17.6 |

## 📍 Top 20 lignes chaudes

| Ligne | % |
|---|---:|
| `_socket_capture` — capture.py:971 |  36.0 % |
| `cmd` — nftables.py:410 |  12.7 % |
| `_depths` — fast_iforest.py:97 |   4.5 % |
| `quick_execute` — execute.py:53 |   3.8 % |
| `_socket_capture` — capture.py:985 |   3.5 % |
| `_write_to_self` — selector_events.py:139 |   3.0 % |
| `_depths` — fast_iforest.py:98 |   2.0 % |
| `emit` — logger.py:57 |   1.7 % |
| `compute` — _dispatcher.py:278 |   1.4 % |
| `put` — queue.py:137 |   1.2 % |
| `put` — queue.py:133 |   1.1 % |
| `_put` — capture.py:830 |   1.1 % |
| `_read_from_self` — selector_events.py:119 |   1.0 % |
| `_put` — capture.py:831 |   0.8 % |
| `unpack` — dpkt.py:344 |   0.7 % |
| `__enter__` — threading.py:272 |   0.7 % |
| `__exit__` — threading.py:275 |   0.6 % |
| `_depths` — fast_iforest.py:96 |   0.6 % |
| `put_nowait` — queue.py:191 |   0.6 % |
| `raw_decode` — decoder.py:353 |   0.5 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **36.0 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **12.7 %** cmd (nftables.py) ← _run_command (reaction_module.py) ← block (reaction_module.py) ← action (anomaly_scorer.py) ← run (thread.py) ← _worker (thread.py) ← run (threading.py)
- **4.2 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **3.8 %** quick_execute (execute.py) ← call_function (context.py) ← call_flat (atomic_function.py) ← call_preflattened (atomic_function.py) ← _call_flat (concrete_function.py) ← call_function (tracing_compilation.py) ← _call (polymorphic_function.py)
- **3.5 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **3.0 %** _write_to_self (selector_events.py) ← call_soon_threadsafe (base_events.py) ← _call_set_state (futures.py) ← _invoke_callbacks (_base.py) ← set_result (_base.py) ← run (thread.py) ← _worker (thread.py)
- **1.9 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **1.7 %** emit (logger.py) ← handle (__init__.py) ← callHandlers (__init__.py) ← handle (__init__.py) ← _log (__init__.py) ← log (__init__.py) ← print (logger.py)
- **1.2 %** put (queue.py) ← put_nowait (queue.py) ← _put (capture.py) ← _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **1.1 %** put (queue.py) ← put_nowait (queue.py) ← _put (capture.py) ← _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
