# Rapport de profilage IDS/IPS — 2026-10-01 12:56:03

- Temps **actif** (hors attentes) : **157.8 s** cumulés sur 10 thread(s)/process pour **365 s** de fenêtre · attentes ignorées (wait/sleep/queue.get/epoll…) : 1416.3 s
- Les pourcentages sont relatifs au temps actif total. ⚠️ `--native` en mode bloquant ralentit fortement la cible : fie-toi aux PROPORTIONS, pas au débit absolu.

## 🎯 Verdict automatique

- Bibliothèque qui consomme le plus (feuille) : **capture** (99.8 %)
- Inférence (paquet + séquence) active **0 s sur 365 s** de fenêtre (0 %) → le consommateur n'est pas saturé.
- 💡 Pas de règle évidente déclenchée : regarde les tables ci-dessous et le flamegraph.

_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_

## 📈 Débit mesuré pendant la fenêtre

- Séquences évaluées : **0** → 0.00/s (≈ 0.00 paquets/s traités, stride=10)
- Anomalies paquet : 0 · blocages nft : 0

## 🧱 Étapes du pipeline (temps inclusif)

| Étape | % temps actif | secondes |
|---|---:|---:|
| detect() — boucle consommateur (total) |   0.1 % | 0.1 |

## 🔥 Où le CPU brûle (bibliothèque de la feuille)

| Bibliothèque | % | secondes |
|---|---:|---:|
| capture |  99.8 % | 157.4 |
| asyncio / threads / queue |   0.1 % | 0.2 |
| Python pur (ton code / autre) |   0.1 % | 0.1 |
| json / pickle / dill / joblib |   0.0 % | 0.0 |

## 🧵 Par thread / process

| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |
|---|---:|---:|---:|---|
| Process 79407 Thread 79546 "Capture-veth_rx" | 157.4 |  99.7 % | 0.0 | _socket_capture (capture.py) |
| Process 79407 Thread 79465 "Detection Thread" | 0.2 |   0.1 % | 157.2 | is_set (synchronize.py) |
| Process 79407 Thread 79463 "API Thread" | 0.1 |   0.1 % | 157.3 | __schedule_callbacks (futures.py) |
| Process 79407 Thread 79466 "Thread-2 (start_server)" | 0.0 |   0.0 % | 157.4 | __init__ (tasks.py) |
| Process 79407 Thread 79407 "MainThread" | 0.0 |   0.0 % | 157.4 | _wait_for_stop (orchestrator.py) |
| Process 79407 Thread 79547 "Capture-Reporter" | 0.0 |   0.0 % | 157.4 | _rss_mb (capture.py) |

## ⏱️ Top 20 fonctions — temps propre (self)

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  99.7 % | 157.4 |
| `__schedule_callbacks` (futures.py) |   0.0 % | 0.1 |
| `is_set` (synchronize.py) |   0.0 % | 0.1 |
| `__step` (tasks.py) |   0.0 % | 0.0 |
| `done` (futures.py) |   0.0 % | 0.0 |
| `__init__` (tasks.py) |   0.0 % | 0.0 |
| `_wait_for_stop` (orchestrator.py) |   0.0 % | 0.0 |
| `_format_timetuple_and_zone` (utils.py) |   0.0 % | 0.0 |
| `_get_loop` (futures.py) |   0.0 % | 0.0 |
| `serve` (server.py) |   0.0 % | 0.0 |
| `main_loop` (server.py) |   0.0 % | 0.0 |
| `_strptime_datetime` (_strptime.py) |   0.0 % | 0.0 |
| `_drain_entries` (detection_module.py) |   0.0 % | 0.0 |
| `cancelled` (futures.py) |   0.0 % | 0.0 |
| `__init__` (events.py) |   0.0 % | 0.0 |
| `__exit__` (threading.py) |   0.0 % | 0.0 |
| `_timer_handle_cancelled` (base_events.py) |   0.0 % | 0.0 |
| `raw_decode` (decoder.py) |   0.0 % | 0.0 |
| `_rss_mb` (capture.py) |   0.0 % | 0.0 |

## ⏱️ Top 20 fonctions — temps inclusif

| Fonction | % | s |
|---|---:|---:|
| `_bootstrap` (threading.py) | 100.0 % | 157.8 |
| `run` (threading.py) | 100.0 % | 157.8 |
| `_bootstrap_inner` (threading.py) | 100.0 % | 157.8 |
| `_socket_capture` (capture.py) |  99.7 % | 157.4 |
| `__step` (tasks.py) |   0.2 % | 0.3 |
| `__wakeup` (tasks.py) |   0.2 % | 0.3 |
| `_run` (events.py) |   0.2 % | 0.2 |
| `_run_once` (nest_asyncio.py) |   0.2 % | 0.2 |
| `run_until_complete` (nest_asyncio.py) |   0.1 % | 0.2 |
| `run` (nest_asyncio.py) |   0.1 % | 0.2 |
| `_run_async_detection` (orchestrator.py) |   0.1 % | 0.2 |
| `run` (runners.py) |   0.1 % | 0.1 |
| `asyncio_run` (_compat.py) |   0.1 % | 0.1 |
| `run` (server.py) |   0.1 % | 0.1 |
| `_detection_coroutine` (orchestrator.py) |   0.1 % | 0.1 |
| `detect` (detection_module.py) |   0.1 % | 0.1 |
| `_set_result_unless_cancelled` (futures.py) |   0.0 % | 0.1 |
| `set_result` (futures.py) |   0.0 % | 0.1 |
| `__schedule_callbacks` (futures.py) |   0.0 % | 0.1 |
| `serve` (server.py) |   0.0 % | 0.1 |

## 🧩 Fonctions de TON code (`ids_ips_ia`) — inclusif

| Fonction | % | s |
|---|---:|---:|
| `_socket_capture` (capture.py) |  99.7 % | 157.4 |
| `_run_async_detection` (orchestrator.py) |   0.1 % | 0.2 |
| `detect` (detection_module.py) |   0.1 % | 0.1 |
| `_detection_coroutine` (orchestrator.py) |   0.1 % | 0.1 |
| `monitor_suricata_alerts` (detection_module.py) |   0.0 % | 0.0 |
| `parse_eve_line` (suricata_integration.py) |   0.0 % | 0.0 |
| `_drain_entries` (detection_module.py) |   0.0 % | 0.0 |
| `start_server` (real_time_plot.py) |   0.0 % | 0.0 |
| `_wait_for_stop` (orchestrator.py) |   0.0 % | 0.0 |
| `<module>` (api.py) |   0.0 % | 0.0 |
| `main` (orchestrator.py) |   0.0 % | 0.0 |
| `_parse_eve_timestamp` (suricata_integration.py) |   0.0 % | 0.0 |
| `_rss_mb` (capture.py) |   0.0 % | 0.0 |
| `_status_line` (capture.py) |   0.0 % | 0.0 |
| `_reporter` (capture.py) |   0.0 % | 0.0 |

## 📍 Top 20 lignes chaudes

| Ligne | % |
|---|---:|
| `_socket_capture` — capture.py:967 |  99.7 % |
| `_socket_capture` — capture.py:1011 |   0.0 % |
| `__schedule_callbacks` — futures.py:173 |   0.0 % |
| `done` — futures.py:187 |   0.0 % |
| `__step` — tasks.py:300 |   0.0 % |
| `is_set` — synchronize.py:336 |   0.0 % |
| `is_set` — synchronize.py:335 |   0.0 % |
| `_wait_for_stop` — orchestrator.py:587 |   0.0 % |
| `_format_timetuple_and_zone` — utils.py:234 |   0.0 % |
| `_get_loop` — futures.py:307 |   0.0 % |
| `serve` — server.py:71 |   0.0 % |
| `main_loop` — server.py:231 |   0.0 % |
| `__schedule_callbacks` — futures.py:172 |   0.0 % |
| `_strptime_datetime` — _strptime.py:569 |   0.0 % |
| `_drain_entries` — detection_module.py:620 |   0.0 % |
| `cancelled` — futures.py:177 |   0.0 % |
| `__init__` — events.py:108 |   0.0 % |
| `__step` — tasks.py:277 |   0.0 % |
| `__exit__` — threading.py:275 |   0.0 % |
| `_timer_handle_cancelled` — base_events.py:1856 |   0.0 % |

## 🥞 Piles les plus fréquentes (feuille ← appelants)

- **99.7 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **0.0 %** _socket_capture (capture.py) ← run (threading.py) ← _bootstrap_inner (threading.py) ← _bootstrap (threading.py)
- **0.0 %** __schedule_callbacks (futures.py) ← set_result (futures.py) ← _set_result_unless_cancelled (futures.py) ← run (runners.py) ← asyncio_run (_compat.py) ← run (server.py) ← run (threading.py)
- **0.0 %** is_set (synchronize.py) ← detect (detection_module.py) ← _detection_coroutine (orchestrator.py) ← __step (tasks.py) ← __wakeup (tasks.py) ← _run (events.py) ← _run_once (nest_asyncio.py)
- **0.0 %** is_set (synchronize.py) ← detect (detection_module.py) ← _detection_coroutine (orchestrator.py) ← __step (tasks.py) ← __wakeup (tasks.py) ← _run (events.py) ← _run_once (nest_asyncio.py)
- **0.0 %** _wait_for_stop (orchestrator.py) ← __step (tasks.py) ← __wakeup (tasks.py) ← _run (events.py) ← _run_once (nest_asyncio.py) ← run_until_complete (nest_asyncio.py) ← run (nest_asyncio.py)
- **0.0 %** _format_timetuple_and_zone (utils.py) ← format_datetime (utils.py) ← formatdate (utils.py) ← on_tick (server.py) ← main_loop (server.py) ← _serve (server.py) ← serve (server.py)
- **0.0 %** _get_loop (futures.py) ← __step (tasks.py) ← __wakeup (tasks.py) ← run (runners.py) ← asyncio_run (_compat.py) ← run (server.py) ← run (threading.py)
- **0.0 %** serve (server.py) ← __step (tasks.py) ← __wakeup (tasks.py) ← run (runners.py) ← asyncio_run (_compat.py) ← run (server.py) ← run (threading.py)
- **0.0 %** main_loop (server.py) ← _serve (server.py) ← serve (server.py) ← __step (tasks.py) ← __wakeup (tasks.py) ← run (runners.py) ← asyncio_run (_compat.py)
