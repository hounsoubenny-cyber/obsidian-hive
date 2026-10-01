# Rapport de profilage IDS/IPS — 2026-10-01 00:40:30

- Échantillons : **2065.5 s** de temps actif cumulé sur 29 thread(s)/process pour **365 s** de fenêtre
- py-spy n'échantillonne que les threads **actifs** (pas ceux qui dorment). Les pourcentages sont relatifs au temps actif total.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (feuille) : **Python pur (ton code / autre)** (75.6 %)
- Étape du pipeline la plus coûteuse : **log_anomaly / _add_alert** (7.3 %)
- 💡 Pas de règle évidente déclenchée : regarde les tables ci-dessous et le flamegraph.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **7** → 0.02/s (≈ 0.02 paquets/s traités si stride=1)
- Anomalies paquet : 19 · blocages nft : 25
- Capture au début : 1 724 pkt/s gardés  pertes 94.4 % (noyau 4 898 459 · app 0)
- Capture à la fin : 1 840 pkt/s gardés  pertes 99.5 % (noyau 167 301 600 · app 0)

## 🧱 Étapes du pipeline (temps inclusif)

| Étape | % temps actif | secondes |
|---|---:|---:|
| detect() — boucle consommateur (total) |   7.3 % | 151.3 |
| predict_packet (AE + IF + LOF, batch=1) |   0.4 % | 8.0 |
| predict_sequence (CNN + AE + IF + LOF) |   0.4 % | 7.7 |
|   dont IsolationForest.decision_function |   0.4 % | 8.9 |
|   dont LOF.decision_function |   0.0 % | 0.5 |
| AnomalyScorer.detect_pkt (voie lente) |   0.0 % | 0.1 |
| log_anomaly / _add_alert |   7.3 % | 151.2 |
| logger.print |   0.0 % | 0.4 |
| blocage nft (_run_command / block) |   0.0 % | 0.1 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| Python pur (ton code / autre) |  75.6 % | 1562.0 |
| capture |  16.2 % | 334.6 |
| json / pickle / dill |   5.7 % | 117.2 |
| scikit-learn / joblib |   1.9 % | 39.0 |
| TensorFlow / Keras |   0.3 % | 6.2 |
| numpy / scipy |   0.2 % | 4.8 |
| asyncio / threads / queue |   0.0 % | 1.0 |
| logs / print |   0.0 % | 0.7 |
| réaction nft / subprocess |   0.0 % | 0.1 |
| scoring / corrélation |   0.0 % | 0.0 |

## 🧵 Par thread / process

| Thread | actif (s) | % | fonction la plus chaude |
|---|---:|---:|---|
| Process 27711 Thread 27711 "MainThread" | 167.4 |   8.1 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27762 "API Thread" | 167.4 |   8.1 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27764 "Detection Thread" | 167.4 |   8.1 % | save (pickle.py) |
| Process 27711 Thread 27765 "Thread-2 (start_server)" | 167.4 |   8.1 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27788 "asyncio-waitpid-0" | 167.4 |   8.1 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27818 "Suricata - ids" | 167.4 |   8.1 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27856 "asyncio-waitpid-1" | 167.4 |   8.1 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27861 "Thread-3 (save_periodic)" | 167.4 |   8.1 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27862 "Capture-veth_rx" | 167.4 |   8.1 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27863 "Capture-Reporter" | 167.4 |   8.1 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27882 "asyncio_0" | 167.4 |   8.1 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27965 "asyncio_1" | 167.4 |   8.1 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 28454 "asyncio_2" | 55.8 |   2.7 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27956 "" | 0.0 |   0.0 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27957 "" | 0.0 |   0.0 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27959 "" | 0.0 |   0.0 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27962 "" | 0.0 |   0.0 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27963 "" | 0.0 |   0.0 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27958 "" | 0.0 |   0.0 % | 0x7fed55287fe2 (libc.so.6) |
| Process 27711 Thread 27960 "" | 0.0 |   0.0 % | 0x7fed55287fe2 (libc.so.6) |

## ⏱️ Top 20 fonctions — temps propre (self)

| Fonction | % | s |
|---|---:|---:|
| `0x7fed55287fe2` (libc.so.6) |  91.8 % | 1895.7 |
| `save` (pickle.py) |   2.1 % | 43.9 |
| `save` (numpy_pickle.py) |   1.6 % | 33.3 |
| `_batch_appends` (pickle.py) |   0.7 % | 15.2 |
| `save_float` (pickle.py) |   0.7 % | 14.9 |
| `commit_frame` (pickle.py) |   0.6 % | 12.0 |
| `write` (pickle.py) |   0.4 % | 8.1 |
| `0x7fed46cbd7eb` (_struct.cpython-311-x86_64-linux-gnu.so) |   0.1 % | 2.5 |
| `0x7fed46cbe01d` (_struct.cpython-311-x86_64-linux-gnu.so) |   0.1 % | 2.1 |
| `_socket_capture` (capture.py) |   0.1 % | 2.0 |
| `persistent_id` (pickle.py) |   0.1 % | 1.6 |
| `memoize` (pickle.py) |   0.1 % | 1.6 |
| `__lll_lock_wake` (libc.so.6) |   0.1 % | 1.3 |
| `__lll_lock_wait` (libc.so.6) |   0.1 % | 1.3 |
| `_int_malloc` (libc.so.6) |   0.1 % | 1.2 |
| `0x7fed46cbe06c` (_struct.cpython-311-x86_64-linux-gnu.so) |   0.1 % | 1.1 |
| `save_list` (pickle.py) |   0.1 % | 1.1 |
| `__memmove_avx_unaligned_erms` (libc.so.6) |   0.0 % | 0.9 |
| `put` (queue.py) |   0.0 % | 0.8 |
| `<listcomp>` (validation.py) |   0.0 % | 0.8 |

## ⏱️ Top 20 fonctions — temps inclusif

| Fonction | % | s |
|---|---:|---:|
| `run` (threading.py) |  91.9 % | 1897.8 |
| `_bootstrap` (threading.py) |  91.9 % | 1897.8 |
| `_bootstrap_inner` (threading.py) |  91.9 % | 1897.8 |
| `__internal_syscall_cancel` (libc.so.6) |  91.8 % | 1895.8 |
| `0x7fed55287fe2` (libc.so.6) |  91.8 % | 1895.7 |
| `start_thread` (libc.so.6) |  91.7 % | 1893.5 |
| `__clone3` (libc.so.6) |  91.7 % | 1893.5 |
| `__syscall_cancel` (libc.so.6) |  42.5 % | 876.9 |
| `__futex_abstimed_wait_common` (libc.so.6) |  41.2 % | 851.4 |
| `_run_once` (nest_asyncio.py) |  32.4 % | 669.8 |
| `PyThread_acquire_lock_timed` (libpython3.11.so.1.0) |  26.1 % | 540.0 |
| `select` (selectors.py) |  25.0 % | 516.2 |
| `run` (nest_asyncio.py) |  24.3 % | 502.3 |
| `run_until_complete` (nest_asyncio.py) |  24.3 % | 502.3 |
| `0x7fed5595223d` (select.cpython-311-x86_64-linux-gnu.so) |  18.9 % | 391.2 |
| `epoll_wait` (libc.so.6) |  18.9 % | 391.2 |
| `_worker` (thread.py) |  18.9 % | 390.7 |
| `0x7fed46b43c77` (_queue.cpython-311-x86_64-linux-gnu.so) |  18.2 % | 374.9 |
| `__new_sem_wait_slow64.constprop.0` (libc.so.6) |  18.1 % | 374.7 |
| `0x7fed46b43a6a` (_queue.cpython-311-x86_64-linux-gnu.so) |  18.1 % | 374.7 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif

| Fonction | % | s |
|---|---:|---:|
| `main` (orchestrator.py) |   8.1 % | 167.4 |
| `<module>` (api.py) |   8.1 % | 167.4 |
| `_run_async_detection` (orchestrator.py) |   8.1 % | 167.4 |
| `start_server` (real_time_plot.py) |   8.1 % | 167.4 |
| `run_suricata_sync` (suricata_integration.py) |   8.1 % | 167.4 |
| `save_periodic` (refit_queue.py) |   8.1 % | 167.4 |
| `_socket_capture` (capture.py) |   8.1 % | 167.4 |
| `_reporter` (capture.py) |   8.1 % | 167.4 |
| `detect` (detection_module.py) |   7.3 % | 151.3 |
| `_detection_coroutine` (orchestrator.py) |   7.3 % | 151.3 |
| `log_anomaly` (detection_module.py) |   7.3 % | 151.2 |
| `predict_packet` (models.py) |   0.4 % | 8.0 |
| `predict_sequence` (models.py) |   0.4 % | 7.7 |
| `_predict_ae_seq` (models.py) |   0.2 % | 3.3 |
| `_put` (capture.py) |   0.1 % | 2.2 |
| `_predict_cnn_seq` (models.py) |   0.1 % | 1.9 |
| `monitor_suricata_alerts` (detection_module.py) |   0.1 % | 1.7 |
| `parse_eve_line` (suricata_integration.py) |   0.1 % | 1.2 |
| `_rss_mb` (capture.py) |   0.1 % | 1.2 |
| `_status_line` (capture.py) |   0.1 % | 1.2 |

## 📍 Top 20 lignes chaudes

| Ligne | % |
|---|---:|
| `0x7fed55287fe2` — libc.so.6:0 |  91.8 % |
| `save` — pickle.py:545 |   0.6 % |
| `save_float` — pickle.py:784 |   0.6 % |
| `commit_frame` — pickle.py:220 |   0.4 % |
| `save` — numpy_pickle.py:370 |   0.4 % |
| `_batch_appends` — pickle.py:951 |   0.4 % |
| `save` — pickle.py:558 |   0.3 % |
| `save` — numpy_pickle.py:395 |   0.3 % |
| `save` — numpy_pickle.py:371 |   0.3 % |
| `save` — pickle.py:536 |   0.2 % |
| `save` — numpy_pickle.py:373 |   0.2 % |
| `write` — pickle.py:243 |   0.2 % |
| `save` — numpy_pickle.py:372 |   0.2 % |
| `save` — pickle.py:551 |   0.2 % |
| `save` — pickle.py:560 |   0.2 % |
| `_batch_appends` — pickle.py:956 |   0.2 % |
| `save` — pickle.py:539 |   0.2 % |
| `0x7fed46cbd7eb` — _struct.cpython-311-x86_64-linux-gnu.so:0 |   0.1 % |
| `write` — pickle.py:242 |   0.1 % |
| `_batch_appends` — pickle.py:955 |   0.1 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **18.9 %** 0x7fed55287fe2 (libc.so.6) ← __internal_syscall_cancel (libc.so.6) ← __syscall_cancel (libc.so.6) ← epoll_wait (libc.so.6) ← 0x7fed5595223d (select.cpython-311-x86_64-linux-gnu.so) ← select (selectors.py) ← _run_once (nest_asyncio.py)
- **18.1 %** 0x7fed55287fe2 (libc.so.6) ← __internal_syscall_cancel (libc.so.6) ← __futex_abstimed_wait_common (libc.so.6) ← __new_sem_wait_slow64.constprop.0 (libc.so.6) ← PyThread_acquire_lock_timed (libpython3.11.so.1.0) ← 0x7fed46b43a6a (_queue.cpython-311-x86_64-linux-gnu.so) ← 0x7fed46b43c77 (_queue.cpython-311-x86_64-linux-gnu.so)
- **16.2 %** 0x7fed55287fe2 (libc.so.6) ← __internal_syscall_cancel (libc.so.6) ← __syscall_cancel (libc.so.6) ← wait4 (libc.so.6) ← _do_waitpid (unix_events.py) ← run (threading.py) ← _bootstrap_inner (threading.py)
- **8.1 %** 0x7fed55287fe2 (libc.so.6) ← __internal_syscall_cancel (libc.so.6) ← clock_nanosleep@GLIBC_2.2.5 (libc.so.6) ← save_periodic (refit_queue.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **8.0 %** 0x7fed55287fe2 (libc.so.6) ← __internal_syscall_cancel (libc.so.6) ← __futex_abstimed_wait_common (libc.so.6) ← __new_sem_wait_slow64 (libc.so.6) ← PyThread_acquire_lock_timed (libpython3.11.so.1.0) ← wait (threading.py) ← wait (threading.py)
- **7.7 %** 0x7fed55287fe2 (libc.so.6) ← __internal_syscall_cancel (libc.so.6) ← __futex_abstimed_wait_common (libc.so.6) ← pthread_cond_timedwait@@GLIBC_2.3.2 (libc.so.6) ← 0x7fed55091cbd (_socket.cpython-311-x86_64-linux-gnu.so) ← 0x7fed55091ec3 (_socket.cpython-311-x86_64-linux-gnu.so) ← 0x7fed55092057 (_socket.cpython-311-x86_64-linux-gnu.so)
- **7.1 %** 0x7fed55287fe2 (libc.so.6) ← __internal_syscall_cancel (libc.so.6) ← __syscall_cancel (libc.so.6) ← epoll_pwait (libc.so.6) ← uv__io_poll (linux.c) ← uv_run (core.c) ← Loop__Loop__run (loop.c)
- **6.0 %** 0x7fed55287fe2 (libc.so.6) ← __internal_syscall_cancel (libc.so.6) ← __futex_abstimed_wait_common (libc.so.6) ← pthread_cond_timedwait@@GLIBC_2.3.2 (libc.so.6) ← 0x7fed55952249 (select.cpython-311-x86_64-linux-gnu.so) ← select (selectors.py) ← _run_once (nest_asyncio.py)
- **0.8 %** 0x7fed55287fe2 (libc.so.6) ← __internal_syscall_cancel (libc.so.6) ← __futex_abstimed_wait_common (libc.so.6) ← pthread_cond_timedwait@@GLIBC_2.3.2 (libc.so.6) ← loop___ensure_handle_data (loop.c) ← loop___uvtimer_callback (loop.c) ← uv__queue_empty (queue.h)
- **0.6 %** save_float (pickle.py) ← save (pickle.py) ← save (numpy_pickle.py) ← _batch_appends (pickle.py) ← save_list (pickle.py) ← save (pickle.py) ← save (numpy_pickle.py)
