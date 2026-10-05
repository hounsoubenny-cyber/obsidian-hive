# Rapport de profilage IDS/IPS — 2026-10-05 10:29:28

- Temps **actif** (hors attentes) : **1602.1 s** cumulés sur 51 thread(s)/process pour **366 s** de fenêtre · attentes ignorées (wait/sleep/queue.get/epoll…) : 6997.3 s
- Les pourcentages sont relatifs au temps actif total. ⚠️ `--native` en mode bloquant ralentit fortement la cible : fie-toi aux PROPORTIONS, pas au débit absolu.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (feuille) : **Python pur (ton code / autre)** (56.6 %)
- Étape du pipeline la plus coûteuse : **predict_packet (AE + IF + LOF)** (10.4 %)
- Inférence (paquet + séquence) active **256 s sur 366 s** de fenêtre (70 %) → le consommateur n'est pas saturé.
- 💡 Les logs coûtent cher → verbose=0 pendant les benchs, ou logger via une queue asynchrone.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **15232** → 41.56/s (≈ 831.22 paquets/s traités, stride=20)
- Anomalies paquet : 1941 · blocages nft : 3454
- Capture au début : 1 009 pkt/s gardés  pertes 0.0 % (noyau 0 · app 0)
- Capture à la fin : 4 688 pkt/s gardés  pertes 39.7 % (noyau 0 · app 1 474 992)

## 🧱 Étapes du pipeline (temps inclusif)

| Étape | % temps actif | secondes |
|---|---:|---:|
| extract_pack_features (par paquet) |   0.4 % | 6.9 |
| predict_packet (AE + IF + LOF) |  10.4 % | 166.8 |
|   dont IsolationForest (paquet) |   7.8 % | 125.5 |
|   dont LOF (paquet) |   0.3 % | 4.5 |
| extract_seq_features |   0.4 % | 6.1 |
| predict_sequence (CNN + AE + IF + LOF) |   5.6 % | 89.0 |
|   dont IsolationForest (séquence) |   0.2 % | 3.7 |
|   dont LOF (séquence) |   1.1 % | 17.9 |
| AnomalyScorer.detect_pkt (voie lente) |   2.2 % | 34.8 |
| log_anomaly / _add_alert |   0.2 % | 2.6 |
| persistance joblib/pickle (dump) |   0.1 % | 1.1 |
| blocage nft (_run_command / block) |   3.8 % | 60.8 |
| graphes (add_data*) |   0.1 % | 1.3 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| Python pur (ton code / autre) |  56.6 % | 907.5 |
| capture |  14.2 % | 226.9 |
| logs / print |  13.7 % | 218.8 |
| TensorFlow / Keras |   5.2 % | 82.7 |
| réaction nft / subprocess |   3.7 % | 59.9 |
| scikit-learn |   2.1 % | 33.1 |
| asyncio / threads / queue |   1.5 % | 24.5 |
| dpkt (parsing paquets) |   1.2 % | 19.6 |
| numpy / scipy |   0.7 % | 10.5 |
| scoring / corrélation |   0.5 % | 8.3 |
| extraction de features |   0.5 % | 7.8 |
| json / pickle / dill / joblib |   0.2 % | 2.5 |

## 🧵 Par thread / process

| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |
|---|---:|---:|---:|---|
| Process 604893 Thread 605002 "Capture-veth_rx" | 219.1 |  13.7 % | 145.9 | _socket_capture (capture.py) |
| Process 604893 Thread 605155 "rdns_0" | 187.9 |  11.7 % | 177.1 | _lookup_hostname (resolve_hostname.py) |
| Process 604893 Thread 605160 "rdns_2" | 187.5 |  11.7 % | 177.5 | _lookup_hostname (resolve_hostname.py) |
| Process 604893 Thread 605159 "rdns_1" | 186.6 |  11.6 % | 178.4 | _lookup_hostname (resolve_hostname.py) |
| Process 604893 Thread 605161 "rdns_3" | 186.2 |  11.6 % | 178.8 | _lookup_hostname (resolve_hostname.py) |
| Process 604893 Thread 604899 "Thread-2 (_monitor)" | 170.2 |  10.6 % | 194.8 | flush (__init__.py) |
| Process 604893 Thread 605114 "asyncio_0" | 156.3 |   9.8 % | 573.7 | _depths (fast_iforest.py) |
| Process 604893 Thread 604945 "Detection Thread" | 116.6 |   7.3 % | 248.4 | unpack (dpkt.py) |
| Process 604893 Thread 605187 "asyncio_2" | 62.5 |   3.9 % | 302.5 | _depths (fast_iforest.py) |
| Process 604893 Thread 605156 "BlockBatcher" | 61.0 |   3.8 % | 304.0 | cmd (nftables.py) |
| Process 604893 Thread 605157 "asyncio_1" | 39.4 |   2.5 % | 325.6 | _depths (fast_iforest.py) |
| Process 604893 Thread 609150 "asyncio_3" | 14.9 |   0.9 % | 189.8 | _depths (fast_iforest.py) |
| Process 604893 Thread 605001 "RefitQueue-save" | 8.3 |   0.5 % | 356.6 | _save (capture.py) |
| Process 604893 Thread 605004 "Dashboard" | 3.1 |   0.2 % | 361.9 | open_binary (_common.py) |
| Process 604893 Thread 605158 "AnomalyWriter" | 2.2 |   0.1 % | 362.8 | _write (anomaly_logger.py) |
| Process 604893 Thread 604943 "API Thread" | 0.2 |   0.0 % | 364.8 | __schedule_callbacks (futures.py) |
| Process 604893 Thread 604893 "MainThread" | 0.1 |   0.0 % | 364.9 | call_at (base_events.py) |
| Process 604947 Thread 604947 "MainThread" | 0.0 |   0.0 % | 365.0 | is_set (synchronize.py) |

## ⏱️ Top 20 fonctions — temps propre (self)

| Fonction | % | s |
|---|---:|---:|
| `_lookup_hostname` (resolve_hostname.py) |  46.7 % | 748.2 |
| `_socket_capture` (capture.py) |  12.1 % | 193.6 |
| `_depths` (fast_iforest.py) |   7.9 % | 126.7 |
| `quick_execute` (execute.py) |   4.2 % | 67.5 |
| `flush` (__init__.py) |   3.7 % | 58.7 |
| `cmd` (nftables.py) |   3.4 % | 53.7 |
| `exists` (<frozen genericpath>) |   2.9 % | 46.4 |
| `isfile` (<frozen genericpath>) |   2.4 % | 39.0 |
| `compute` (_dispatcher.py) |   1.2 % | 19.8 |
| `emit` (logger.py) |   1.0 % | 15.2 |
| `_write_to_self` (selector_events.py) |   0.8 % | 12.6 |
| `shouldRollover` (handlers.py) |   0.7 % | 11.6 |
| `unpack` (dpkt.py) |   0.6 % | 10.0 |
| `put` (queue.py) |   0.5 % | 8.4 |
| `_detect_consumer` (detection_module.py) |   0.5 % | 7.8 |
| `_save` (capture.py) |   0.5 % | 7.5 |
| `transform` (_data.py) |   0.5 % | 7.3 |
| `_wrapreduction` (fromnumeric.py) |   0.4 % | 6.3 |
| `formatTime` (__init__.py) |   0.4 % | 6.1 |
| `_put` (capture.py) |   0.3 % | 5.5 |

## ⏱️ Top 20 fonctions — temps inclusif

| Fonction | % | s |
|---|---:|---:|
| `_bootstrap` (threading.py) | 100.0 % | 1602.0 |
| `run` (threading.py) | 100.0 % | 1602.0 |
| `_bootstrap_inner` (threading.py) | 100.0 % | 1602.0 |
| `_worker` (thread.py) |  63.7 % | 1020.9 |
| `run` (thread.py) |  63.7 % | 1020.9 |
| `_lookup_hostname` (resolve_hostname.py) |  46.7 % | 748.2 |
| `_socket_capture` (capture.py) |  13.7 % | 219.1 |
| `handle` (__init__.py) |  12.6 % | 201.2 |
| `emit` (handlers.py) |  10.7 % | 171.9 |
| `_monitor` (handlers.py) |  10.6 % | 170.2 |
| `handle` (handlers.py) |  10.5 % | 167.8 |
| `predict_packet_batch` (models.py) |  10.4 % | 166.7 |
| `_score_batch` (models.py) |   9.5 % | 152.0 |
| `score_samples` (fast_iforest.py) |   8.1 % | 129.2 |
| `decision_function` (fast_iforest.py) |   8.1 % | 129.2 |
| `_depths` (fast_iforest.py) |   7.9 % | 127.3 |
| `run_until_complete` (nest_asyncio.py) |   7.3 % | 116.7 |
| `run` (nest_asyncio.py) |   7.3 % | 116.7 |
| `_run_async_detection` (orchestrator.py) |   7.3 % | 116.6 |
| `_run_once` (nest_asyncio.py) |   7.3 % | 116.5 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif

| Fonction | % | s |
|---|---:|---:|
| `_lookup_hostname` (resolve_hostname.py) |  46.7 % | 748.2 |
| `_socket_capture` (capture.py) |  13.7 % | 219.1 |
| `predict_packet_batch` (models.py) |  10.4 % | 166.7 |
| `_score_batch` (models.py) |   9.5 % | 152.0 |
| `decision_function` (fast_iforest.py) |   8.1 % | 129.2 |
| `score_samples` (fast_iforest.py) |   8.1 % | 129.2 |
| `_depths` (fast_iforest.py) |   7.9 % | 127.3 |
| `_run_async_detection` (orchestrator.py) |   7.3 % | 116.6 |
| `predict_sequence_batch` (models.py) |   5.5 % | 88.9 |
| `_run_bucketed` (models.py) |   5.2 % | 83.8 |
| `_detect_consumer` (detection_module.py) |   4.2 % | 67.4 |
| `_run` (block_batcher.py) |   3.8 % | 61.0 |
| `_flush` (block_batcher.py) |   3.8 % | 60.9 |
| `_commit` (block_batcher.py) |   3.8 % | 60.9 |
| `_run_command` (reaction_module.py) |   3.8 % | 60.8 |
| `_predict_ae_seq` (models.py) |   2.6 % | 41.4 |
| `_detect_producer` (detection_module.py) |   2.5 % | 39.3 |
| `detect_pkt` (anomaly_scorer.py) |   2.2 % | 34.8 |
| `_drain_entries` (detection_module.py) |   2.0 % | 31.9 |
| `_put` (capture.py) |   1.6 % | 25.4 |

## 📍 Top 20 lignes chaudes

| Ligne | % |
|---|---:|
| `_lookup_hostname` — resolve_hostname.py:53 |  46.7 % |
| `_socket_capture` — capture.py:1003 |  10.8 % |
| `_depths` — fast_iforest.py:98 |   4.6 % |
| `quick_execute` — execute.py:53 |   4.2 % |
| `flush` — __init__.py:1094 |   3.6 % |
| `cmd` — nftables.py:410 |   3.2 % |
| `exists` — <frozen genericpath>:19 |   2.9 % |
| `isfile` — <frozen genericpath>:30 |   2.4 % |
| `_depths` — fast_iforest.py:99 |   2.2 % |
| `compute` — _dispatcher.py:278 |   1.2 % |
| `emit` — logger.py:105 |   0.9 % |
| `_socket_capture` — capture.py:1017 |   0.9 % |
| `_write_to_self` — selector_events.py:139 |   0.8 % |
| `_depths` — fast_iforest.py:97 |   0.6 % |
| `unpack` — dpkt.py:344 |   0.5 % |
| `_save` — capture.py:317 |   0.5 % |
| `shouldRollover` — handlers.py:198 |   0.4 % |
| `_wrapreduction` — fromnumeric.py:83 |   0.4 % |
| `put` — queue.py:133 |   0.3 % |
| `shouldRollover` — handlers.py:197 |   0.3 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **46.7 %** _lookup_hostname (resolve_hostname.py) ← run (thread.py) ← _worker (thread.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **10.8 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **4.5 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **4.2 %** quick_execute (execute.py) ← call_function (context.py) ← call_flat (atomic_function.py) ← call_preflattened (atomic_function.py) ← _call_flat (concrete_function.py) ← call_function (tracing_compilation.py) ← _call (polymorphic_function.py)
- **3.6 %** flush (__init__.py) ← emit (__init__.py) ← emit (__init__.py) ← emit (handlers.py) ← handle (__init__.py) ← handle (handlers.py) ← _monitor (handlers.py)
- **3.2 %** cmd (nftables.py) ← _run_command (reaction_module.py) ← _commit (block_batcher.py) ← _flush (block_batcher.py) ← _run (block_batcher.py) ← run (threading.py) ← _bootstrap_inner (threading.py)
- **2.9 %** exists (<frozen genericpath>) ← shouldRollover (handlers.py) ← emit (handlers.py) ← handle (__init__.py) ← handle (handlers.py) ← _monitor (handlers.py) ← run (threading.py)
- **2.4 %** isfile (<frozen genericpath>) ← shouldRollover (handlers.py) ← emit (handlers.py) ← handle (__init__.py) ← handle (handlers.py) ← _monitor (handlers.py) ← run (threading.py)
- **2.1 %** _depths (fast_iforest.py) ← score_samples (fast_iforest.py) ← decision_function (fast_iforest.py) ← _score_batch (models.py) ← predict_packet_batch (models.py) ← run (thread.py) ← _worker (thread.py)
- **1.0 %** compute (_dispatcher.py) ← kneighbors (_base.py) ← score_samples (_lof.py) ← decision_function (_lof.py) ← _score_batch (models.py) ← predict_sequence_batch (models.py) ← run (thread.py)


## 🎚️ Phases de trafic (débit mesuré par l'IDS)

| Début | Fin | Trafic injecté | Relevés | pkt/s moyen | pkt/s max | Perte cumulée (fin de phase) |
|---|---|---|---|---|---|---|
| 0s | 60s | `normal @ pps=1000` | 12 | 999 | 1 120 | 0.00 % |
| 60s | 60s | `attack @ pps=1000` | 0 | – | – | – |
| 60s | 120s | `attack @ pps=5000` | 12 | 4 674 | 5 498 | 0.00 % |
| 120s | 200s | `attack @ pps=10000` | 15 | 9 350 | 10 753 | 0.00 % |
| 200s | 300s | `attack @ pps=15000` | 20 | 8 156 | 14 793 | 23.38 % |
| 300s | 366s | `attack @ pps=20000` | 13 | 5 156 | 5 750 | 39.73 % |
