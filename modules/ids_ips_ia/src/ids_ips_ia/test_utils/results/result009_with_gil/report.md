# Rapport de profilage IDS/IPS — 2026-10-04 07:15:48

- Temps **actif** (hors attentes) : **120.2 s** cumulés sur 24 thread(s)/process pour **362 s** de fenêtre · attentes ignorées (wait/sleep/queue.get/epoll…) : 7.4 s
- Les pourcentages sont relatifs au temps actif total. ⚠️ `--native` en mode bloquant ralentit fortement la cible : fie-toi aux PROPORTIONS, pas au débit absolu.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (feuille) : **capture** (34.5 %)
- Étape du pipeline la plus coûteuse : **AnomalyScorer.detect_pkt (voie lente)** (20.4 %)
- Inférence (paquet + séquence) active **7 s sur 362 s** de fenêtre (2 %) → le consommateur n'est pas saturé.
- 💡 Les logs coûtent cher → verbose=0 pendant les benchs, ou logger via une queue asynchrone.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **9344** → 25.78/s (≈ 515.59 paquets/s traités, stride=20)
- Anomalies paquet : 2775 · blocages nft : 2936
- Capture au début : 1 000 pkt/s gardés  pertes 0.0 % (noyau 0 · app 0)
- Capture à la fin : 0 pkt/s gardés  pertes 62.6 % (noyau 0 · app 2 318 832)

## 🧱 Étapes du pipeline (temps inclusif)

| Étape | % temps actif | secondes |
|---|---:|---:|
| extract_pack_features (par paquet) |   2.4 % | 2.9 |
| predict_packet (AE + IF + LOF) |   2.8 % | 3.4 |
|   dont IsolationForest (paquet) |   1.9 % | 2.3 |
|   dont LOF (paquet) |   0.3 % | 0.4 |
| extract_seq_features |   2.4 % | 2.9 |
| predict_sequence (CNN + AE + IF + LOF) |   2.7 % | 3.3 |
|   dont IsolationForest (séquence) |   0.4 % | 0.5 |
|   dont LOF (séquence) |   0.5 % | 0.6 |
| AnomalyScorer.detect_pkt (voie lente) |  20.4 % | 24.5 |
| log_anomaly / _add_alert |   0.8 % | 1.0 |
| persistance joblib/pickle (dump) |   0.5 % | 0.6 |
| logger.print |  15.5 % | 18.7 |
| blocage nft (_run_command / block) |   0.4 % | 0.5 |
| graphes (add_data*) |   0.6 % | 0.8 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| capture |  34.5 % | 41.5 |
| logs / print |  16.5 % | 19.8 |
| Python pur (ton code / autre) |  12.9 % | 15.5 |
| asyncio / threads / queue |   9.5 % | 11.4 |
| dpkt (parsing paquets) |   7.7 % | 9.3 |
| scoring / corrélation |   6.9 % | 8.3 |
| extraction de features |   3.1 % | 3.8 |
| réaction nft / subprocess |   2.3 % | 2.7 |
| json / pickle / dill / joblib |   2.3 % | 2.7 |
| TensorFlow / Keras |   2.1 % | 2.5 |
| numpy / scipy |   1.5 % | 1.8 |
| scikit-learn |   0.7 % | 0.9 |

## 🧵 Par thread / process

| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |
|---|---:|---:|---:|---|
| Process 451522 Thread 451574 "Detection Thread" | 67.7 |  56.3 % | 5.1 | unpack (dpkt.py) |
| Process 451522 Thread 451640 "Capture-veth_rx" | 41.4 |  34.5 % | 2.0 | _socket_capture (capture.py) |
| Process 451522 Thread 451787 "asyncio_0" | 3.4 |   2.8 % | 0.0 | _make_iterencode (encoder.py) |
| Process 451522 Thread 451838 "asyncio_2" | 1.5 |   1.2 % | 0.0 | filter (__init__.py) |
| Process 451522 Thread 451906 "asyncio_10" | 0.8 |   0.7 % | 0.0 | save (pickle.py) |
| Process 451522 Thread 451840 "BlockBatcher" | 0.6 |   0.5 % | 0.1 | _detect_level (logger.py) |
| Process 451522 Thread 451835 "asyncio_1" | 0.6 |   0.5 % | 0.0 | _depths (fast_iforest.py) |
| Process 451522 Thread 451865 "asyncio_3" | 0.5 |   0.4 % | 0.0 | _depths (fast_iforest.py) |
| Process 451522 Thread 451885 "asyncio_6" | 0.5 |   0.4 % | 0.0 | _depths (fast_iforest.py) |
| Process 451522 Thread 451895 "asyncio_8" | 0.4 |   0.4 % | 0.0 | _depths (fast_iforest.py) |
| Process 451522 Thread 451894 "asyncio_7" | 0.4 |   0.3 % | 0.0 | _depths (fast_iforest.py) |
| Process 451522 Thread 451884 "asyncio_5" | 0.4 |   0.3 % | 0.0 | _depths (fast_iforest.py) |
| Process 451522 Thread 451883 "asyncio_4" | 0.3 |   0.2 % | 0.0 | _depths (fast_iforest.py) |
| Process 451522 Thread 451572 "API Thread" | 0.3 |   0.2 % | 0.2 | __schedule_callbacks (futures.py) |
| Process 451522 Thread 451935 "asyncio_13" | 0.3 |   0.2 % | 0.0 | _depths (fast_iforest.py) |
| Process 451522 Thread 451896 "asyncio_9" | 0.2 |   0.2 % | 0.0 | _depths (fast_iforest.py) |
| Process 451522 Thread 451934 "asyncio_12" | 0.2 |   0.2 % | 0.0 | _depths (fast_iforest.py) |
| Process 451522 Thread 451936 "asyncio_14" | 0.2 |   0.1 % | 0.0 | convert_to_eager_tensor (constant_op.py) |
| Process 451522 Thread 451933 "asyncio_11" | 0.2 |   0.1 % | 0.0 | _depths (fast_iforest.py) |
| Process 451522 Thread 451937 "asyncio_15" | 0.1 |   0.1 % | 0.0 | _depths (fast_iforest.py) |

## ⏱️ Top 20 fonctions — temps propre (self)

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  20.7 % | 24.9 |
| `put` (queue.py) |   4.9 % | 5.9 |
| `unpack` (dpkt.py) |   4.1 % | 4.9 |
| `_detect_consumer` (detection_module.py) |   4.1 % | 4.9 |
| `_put` (capture.py) |   3.1 % | 3.7 |
| `_detect_level` (logger.py) |   2.9 % | 3.5 |
| `__enter__` (threading.py) |   2.2 % | 2.6 |
| `__init__` (__init__.py) |   1.9 % | 2.3 |
| `__step` (tasks.py) |   1.9 % | 2.3 |
| `extract_pack_features` (features_extractor.py) |   1.8 % | 2.2 |
| `_depths` (fast_iforest.py) |   1.7 % | 2.0 |
| `__exit__` (threading.py) |   1.6 % | 1.9 |
| `_to_alert_entry` (detection_module.py) |   1.5 % | 1.8 |
| `extract_seq_features` (features_extractor.py) |   1.3 % | 1.6 |
| `formatTime` (__init__.py) |   1.3 % | 1.6 |
| `_make_iterencode` (encoder.py) |   1.2 % | 1.4 |
| `emit` (logger.py) |   1.2 % | 1.4 |
| `filter` (__init__.py) |   1.2 % | 1.4 |
| `put_nowait` (queue.py) |   1.0 % | 1.2 |
| `update` (anomaly_scorer.py) |   1.0 % | 1.2 |

## ⏱️ Top 20 fonctions — temps inclusif

| Fonction | % | s |
|---|---:|---:|
| `_bootstrap` (threading.py) | 100.0 % | 120.2 |
| `run` (threading.py) | 100.0 % | 120.2 |
| `_bootstrap_inner` (threading.py) | 100.0 % | 120.2 |
| `run` (nest_asyncio.py) |  56.3 % | 67.7 |
| `run_until_complete` (nest_asyncio.py) |  56.3 % | 67.7 |
| `_run_async_detection` (orchestrator.py) |  56.3 % | 67.7 |
| `_run_once` (nest_asyncio.py) |  56.1 % | 67.4 |
| `_run` (events.py) |  55.8 % | 67.0 |
| `__step` (tasks.py) |  53.0 % | 63.7 |
| `__wakeup` (tasks.py) |  52.2 % | 62.8 |
| `_socket_capture` (capture.py) |  34.5 % | 41.4 |
| `_detect_consumer` (detection_module.py) |  32.8 % | 39.4 |
| `detect_pkt` (anomaly_scorer.py) |  20.4 % | 24.5 |
| `print` (logger.py) |  15.5 % | 18.7 |
| `_put` (capture.py) |  13.8 % | 16.5 |
| `_detect_producer` (detection_module.py) |  13.4 % | 16.1 |
| `log` (__init__.py) |  12.3 % | 14.8 |
| `_log` (__init__.py) |  11.9 % | 14.3 |
| `_drain_entries` (detection_module.py) |  10.8 % | 13.0 |
| `put_nowait` (queue.py) |   9.9 % | 11.9 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif

| Fonction | % | s |
|---|---:|---:|
| `_run_async_detection` (orchestrator.py) |  56.3 % | 67.7 |
| `_socket_capture` (capture.py) |  34.5 % | 41.4 |
| `_detect_consumer` (detection_module.py) |  32.8 % | 39.4 |
| `detect_pkt` (anomaly_scorer.py) |  20.4 % | 24.5 |
| `_put` (capture.py) |  13.8 % | 16.5 |
| `_detect_producer` (detection_module.py) |  13.4 % | 16.1 |
| `_drain_entries` (detection_module.py) |  10.8 % | 13.0 |
| `update` (anomaly_scorer.py) |   8.4 % | 10.1 |
| `_score_batch` (models.py) |   3.3 % | 3.9 |
| `calculate_ip_score_dangerous` (anomaly_scorer.py) |   3.0 % | 3.6 |
| `monitor_suricata_alerts` (detection_module.py) |   3.0 % | 3.6 |
| `predict_packet_batch` (models.py) |   2.8 % | 3.3 |
| `predict_sequence_batch` (models.py) |   2.7 % | 3.3 |
| `should_skip` (blocked_skip.py) |   2.5 % | 3.0 |
| `extract_seq_features` (features_extractor.py) |   2.4 % | 2.9 |
| `extract_pack_features` (features_extractor.py) |   2.4 % | 2.9 |
| `score_samples` (fast_iforest.py) |   2.3 % | 2.8 |
| `decision_function` (fast_iforest.py) |   2.3 % | 2.8 |
| `action` (anomaly_scorer.py) |   2.2 % | 2.7 |
| `parse_eve_line` (suricata_integration.py) |   2.2 % | 2.6 |

## 📍 Top 20 lignes chaudes

| Ligne | % |
|---|---:|
| `_socket_capture` — capture.py:1003 |   8.0 % |
| `_socket_capture` — capture.py:989 |   6.7 % |
| `unpack` — dpkt.py:344 |   3.2 % |
| `__enter__` — threading.py:272 |   2.0 % |
| `put` — queue.py:133 |   2.0 % |
| `extract_pack_features` — features_extractor.py:255 |   1.8 % |
| `_put` — capture.py:849 |   1.4 % |
| `__exit__` — threading.py:275 |   1.4 % |
| `_put` — capture.py:848 |   1.4 % |
| `extract_seq_features` — features_extractor.py:262 |   1.3 % |
| `put` — queue.py:137 |   1.3 % |
| `_to_alert_entry` — detection_module.py:411 |   1.3 % |
| `__step` — tasks.py:279 |   1.2 % |
| `_make_iterencode` — encoder.py:260 |   1.2 % |
| `_detect_level` — logger.py:219 |   1.1 % |
| `_depths` — fast_iforest.py:98 |   1.1 % |
| `put_nowait` — queue.py:191 |   1.0 % |
| `filter` — __init__.py:829 |   0.9 % |
| `formatTime` — __init__.py:624 |   0.9 % |
| `_get` — database.py:271 |   0.8 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **8.0 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **6.7 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **2.4 %** unpack (dpkt.py) ← unpack (ip.py) ← __init__ (dpkt.py) ← __init__ (ip.py) ← _unpack_data (ethernet.py) ← unpack (ethernet.py) ← __init__ (dpkt.py)
- **1.8 %** put (queue.py) ← put_nowait (queue.py) ← _put (capture.py) ← _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **1.8 %** extract_pack_features (features_extractor.py) ← _detect_producer (detection_module.py) ← __step (tasks.py) ← __wakeup (tasks.py) ← _run (events.py) ← _run_once (nest_asyncio.py) ← run_until_complete (nest_asyncio.py)
- **1.6 %** __enter__ (threading.py) ← put (queue.py) ← put_nowait (queue.py) ← _put (capture.py) ← _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py)
- **1.4 %** _put (capture.py) ← _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **1.3 %** extract_seq_features (features_extractor.py) ← _detect_consumer (detection_module.py) ← __step (tasks.py) ← __wakeup (tasks.py) ← _run (events.py) ← _run_once (nest_asyncio.py) ← run_until_complete (nest_asyncio.py)
- **1.3 %** put (queue.py) ← put_nowait (queue.py) ← _put (capture.py) ← _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **1.3 %** _to_alert_entry (detection_module.py) ← _detect_consumer (detection_module.py) ← __step (tasks.py) ← __wakeup (tasks.py) ← _run (events.py) ← _run_once (nest_asyncio.py) ← run_until_complete (nest_asyncio.py)


## 🎚️ Phases de trafic (débit mesuré par l'IDS)

| Début | Fin | Trafic injecté | Relevés | pkt/s moyen | pkt/s max | Perte cumulée (fin de phase) |
|---|---|---|---|---|---|---|
| 0s | 60s | `normal @ pps=1000` | 12 | 1 009 | 1 088 | 0.00 % |
| 60s | 60s | `attack @ pps=1000` | 0 | – | – | – |
| 60s | 120s | `attack @ pps=5000` | 12 | 4 423 | 5 501 | 0.00 % |
| 120s | 200s | `attack @ pps=10000` | 16 | 9 182 | 9 751 | 0.00 % |
| 200s | 300s | `attack @ pps=15000` | 20 | 1 073 | 3 212 | 52.08 % |
| 300s | 362s | `attack @ pps=20000` | 13 | 2 881 | 5 947 | 62.61 % |
