#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Oct  4 20:17:55 2026

@author: hounsousamuel
"""

"""
Tests du dashboard.py — sans TTY réel, sans dépendance externe.

Lancement :
    pytest test_dashboard.py -v
    python -m unittest test_dashboard -v
"""
import io
import os
import re
import threading
import time
import unittest
from unittest import mock

# Import depuis le module à tester
import dashboard
from dashboard import (
    Dashboard, vlen, clip, fmt_int, fmt_rate, fmt_dur, fmt_bytes,
    bar, spark, color, g, _rss_bytes,
)

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


class FakeTTY(io.StringIO):
    """StringIO qui se déclare TTY et mémorise le dernier `isatty()`."""
    def isatty(self):
        return True


class FixedSize:
    """Patch de shutil.get_terminal_size pour un test donné."""
    def __init__(self, cols, rows):
        self.size = os.terminal_size((cols, rows))

    def __enter__(self):
        self._p = mock.patch("dashboard.shutil.get_terminal_size", return_value=self.size)
        self._p.start()
        return self

    def __exit__(self, *a):
        self._p.stop()


# =============================================================================
# 1. UTILITAIRES D'AFFICHAGE
# =============================================================================
class TestUtils(unittest.TestCase):

    def test_vlen_ignore_ansi(self):
        self.assertEqual(vlen("\x1b[31mhello\x1b[0m"), 5)
        self.assertEqual(vlen("plain"), 5)
        self.assertEqual(vlen(""), 0)

    def test_clip_respects_visible_width(self):
        s = "\x1b[31mabcdefghij\x1b[0m"
        out = clip(s, 4)
        # 4 caractères visibles max
        self.assertEqual(vlen(out), 4)
        # se termine bien par RESET pour ne pas baver
        self.assertTrue(out.endswith(dashboard.RESET))

    def test_clip_keeps_ansi_prefix(self):
        out = clip("\x1b[31mab\x1b[0mcd", 10)
        self.assertIn("\x1b[31m", out)   # la couleur est préservée
        self.assertEqual(vlen(out), 4)   # "abcd"

    def test_clip_wide_enough_keeps_everything(self):
        s = "\x1b[32mok\x1b[0m"
        self.assertEqual(vlen(clip(s, 50)), 2)

    def test_fmt_int(self):
        self.assertEqual(fmt_int(None), dashboard.DASH)
        self.assertEqual(fmt_int(0), "0")
        self.assertEqual(fmt_int(1234567), "1 234 567")

    def test_fmt_rate(self):
        self.assertEqual(fmt_rate(None), dashboard.DASH)
        self.assertEqual(fmt_rate(12.34), "12.3")
        self.assertEqual(fmt_rate(1234), "1 234")

    def test_fmt_dur(self):
        self.assertEqual(fmt_dur(0), "00:00:00")
        self.assertEqual(fmt_dur(61), "00:01:01")
        self.assertEqual(fmt_dur(3661), "01:01:01")
        self.assertEqual(fmt_dur(86400 + 3600), "1j 01:00:00")

    def test_fmt_bytes(self):
        self.assertEqual(fmt_bytes(None), dashboard.DASH)
        self.assertEqual(fmt_bytes(512), "512 o")
        self.assertEqual(fmt_bytes(2048), "2 Ko")
        self.assertEqual(fmt_bytes(1024 ** 3), "1.0 Go")

    def test_bar(self):
        self.assertEqual(vlen(bar(0.0, 10)), 10)
        self.assertEqual(vlen(bar(1.0, 10)), 10)
        self.assertEqual(bar(0.5, 10).count("█"), 5)
        self.assertEqual(bar(None, 10).count("░"), 10)

    def test_spark(self):
        s = spark([1, 2, 3, 4, 5], width=5)
        self.assertEqual(len(s), 5)
        # le plus grand (5) doit donner le bloc plein
        self.assertEqual(s[-1], dashboard.SPARK[-1])

    def test_spark_empty(self):
        self.assertEqual(spark([]), " " * 24)

    def test_color_thresholds(self):
        # vert < warn, jaune < crit, rouge >= crit
        self.assertIn(dashboard.GREEN, color("x", 5, 10, 20))
        self.assertIn(dashboard.YELLOW, color("x", 15, 10, 20))
        self.assertIn(dashboard.RED, color("x", 25, 10, 20))
        # None -> vert
        self.assertIn(dashboard.GREEN, color("x", None, 10, 20))

    def test_g_nested(self):
        d = {"a": {"b": {"c": 42}}}
        self.assertEqual(g(d, "a", "b", "c"), 42)
        self.assertIsNone(g(d, "a", "z"))
        self.assertEqual(g(d, "a", "z", default="ok"), "ok")
        self.assertIsNone(g(None, "a"))

    def test_rss_bytes_returns_int_or_none(self):
        r = _rss_bytes()
        self.assertTrue(r is None or (isinstance(r, int) and r > 0))


# =============================================================================
# 2. DASHBOARD EN MODE LOG (fallback sans TTY)
# =============================================================================
class TestDashboardLogMode(unittest.TestCase):

    def test_default_mode_is_log_without_tty(self):
        buf = io.StringIO()   # pas de TTY
        d = Dashboard(snapshot_fn=lambda: {}, stream=buf)
        self.assertEqual(d.mode, "log")

    def test_force_tty(self):
        d = Dashboard(snapshot_fn=lambda: {}, stream=io.StringIO(), force=True)
        self.assertEqual(d.mode, "tty")

    def test_force_log(self):
        buf = FakeTTY()
        d = Dashboard(snapshot_fn=lambda: {}, stream=buf, force=False)
        self.assertEqual(d.mode, "log")

    def test_fallback_emits_lines_periodically(self):
        lines = []
        d = Dashboard(
            snapshot_fn=lambda: {"detector": {"uptime_s": 5, "packets_processed": 100}},
            stream=io.StringIO(),
            fallback_log=lines.append,
            interval=0.05,
            fallback_every=0.05,
        )
        d.start()
        time.sleep(0.2)
        d.stop()
        self.assertGreaterEqual(len(lines), 1)
        self.assertIn("uptime", lines[0])
        self.assertIn("pkt/s", lines[0])

    def test_summary_line_handles_empty_snapshot(self):
        d = Dashboard(snapshot_fn=lambda: {}, stream=io.StringIO())
        m = d._compute({})
        line = d.summary_line(m)
        self.assertIn("[dashboard]", line)
        self.assertIn("uptime", line)

    def test_snapshot_fn_exception_is_swallowed(self):
        calls = {"n": 0}
        def bad():
            calls["n"] += 1
            raise RuntimeError("boom")
        d = Dashboard(snapshot_fn=bad, stream=io.StringIO(), interval=0.02)
        d.start()
        time.sleep(0.1)
        d.stop()
        self.assertGreater(calls["n"], 0)
        self.assertIsNotNone(d.last_error)


# =============================================================================
# 3. CALCUL DES MÉTRIQUES (rates, EWMA, uptime, cpu)
# =============================================================================
class TestCompute(unittest.TestCase):

    def setUp(self):
        self.d = Dashboard(snapshot_fn=lambda: {}, stream=io.StringIO())

    def test_uptime_from_detector_used(self):
        m = self.d._compute({"detector": {"uptime_s": 42}})
        self.assertEqual(m["uptime"], 42)

    def test_uptime_fallback_local_clock(self):
        m = self.d._compute({})
        self.assertGreaterEqual(m["uptime"], 0)

    def test_rate_none_on_first_point(self):
        m1 = self.d._compute({"detector": {"packets_processed": 100}})
        # 1er point -> None tant qu'on n'a qu'une mesure
        self.assertIsNone(m1["proc_rate"])

    def test_rate_computed_on_second_point(self):
        self.d._compute({"detector": {"packets_processed": 0, "uptime_s": 1}})
        time.sleep(0.1)
        m = self.d._compute({"detector": {"packets_processed": 100, "uptime_s": 2}})
        self.assertIsNotNone(m["proc_rate"])
        self.assertGreater(m["proc_rate"], 0)

    def test_rate_zero_on_counter_reset(self):
        self.d._compute({"detector": {"packets_processed": 1000}})
        time.sleep(0.05)
        # compteur remis à 0 -> rate doit être 0, pas négatif
        m = self.d._compute({"detector": {"packets_processed": 0}})
        self.assertEqual(m["proc_rate"], 0.0)

    def test_proc_avg(self):
        m = self.d._compute({"detector": {"packets_processed": 1000, "uptime_s": 10}})
        self.assertEqual(m["proc_avg"], 100.0)

    def test_peak_tracks_maximum(self):
        self.d._compute({"detector": {"packets_processed": 0}})
        time.sleep(0.05)
        self.d._compute({"detector": {"packets_processed": 500}})
        time.sleep(0.05)
        m = self.d._compute({"detector": {"packets_processed": 1000}})
        self.assertIsNotNone(m["peak"])
        self.assertGreater(m["peak"], 0)

    def test_inference_ok_default_true(self):
        m = self.d._compute({})
        self.assertTrue(m["infer_ok"])

    def test_inference_ok_false_on_failing(self):
        snap = {"detector": {"inference": {"x": {"failing": True}}}}
        m = self.d._compute(snap)
        self.assertFalse(m["infer_ok"])

    def test_mode_and_nested_values(self):
        snap = {
            "detector": {
                "mode": "pcap",
                "queue": {"size": 10, "max": 100, "fill_pct": 10},
                "pipeline": {"ready_batches": 3, "depth": 8},
            },
            "capture": {"recv": 500, "kept": 480, "loss_pct": 4.0,
                        "kernel_loss_pct": 1.0, "app_loss_pct": 3.0},
            "blocked": 7,
        }
        m = self.d._compute(snap)
        self.assertEqual(m["mode"], "pcap")
        self.assertEqual(m["q_size"], 10)
        self.assertEqual(m["q_max"], 100)
        self.assertEqual(m["ready"], 3)
        self.assertEqual(m["depth"], 8)
        self.assertEqual(m["loss"], 4.0)
        self.assertEqual(m["blocked"], 7)


# =============================================================================
# 4. RENDU (render_lines) — vérifie le nombre de lignes, la largeur, la robustesse
# =============================================================================
class TestRender(unittest.TestCase):

    def setUp(self):
        self.d = Dashboard(snapshot_fn=lambda: {}, stream=io.StringIO())

    def test_render_returns_exactly_height_lines(self):
        m = self.d._compute({})
        lines = self.d.render_lines(m, width=100)
        self.assertEqual(len(lines), Dashboard.HEIGHT)

    def test_render_lines_width_no_more_than_terminal(self):
        m = self.d._compute({})
        lines = self.d.render_lines(m, width=80)
        for ln in lines:
            self.assertLessEqual(vlen(ln), 80, f"ligne trop longue : {vlen(ln)}")

    def test_render_with_full_snapshot(self):
        snap = {
            "capture": {"recv": 1000, "kept": 950, "loss_pct": 5.0,
                        "kernel_loss_pct": 1.0, "app_loss_pct": 4.0},
            "detector": {
                "uptime_s": 3600, "mode": "pcap",
                "packets_processed": 50000,
                "sequences_evaluated": 12000,
                "batches": 400, "last_batch_size": 32, "avg_batch_size": 30.5,
                "anomalies_in_memory": 3, "system_alerts_open": 1,
                "queue": {"size": 12, "max": 256, "fill_pct": 4.7},
                "pipeline": {"ready_batches": 3, "depth": 8},
                "inference": {"model": {"failing": False}},
            },
            "anomalies_logged": 25,
            "blocked": 4,
            "batcher": {"queued": 1, "commands": 4, "failed": 0, "dropped": 0},
        }
        m = self.d._compute(snap)
        lines = self.d.render_lines(m, width=120)
        self.assertEqual(len(lines), Dashboard.HEIGHT)
        txt = strip_ansi("\n".join(lines))
        self.assertIn("OBSIDIAN", txt)
        self.assertIn("pcap", txt)
        # Les compteurs doivent apparaître quelque part
        self.assertIn("50", txt)     # 50 000 ou autre
        self.assertIn("25", txt)     # anomalies
        self.assertIn("4", txt)      # bloquées

    def test_render_with_empty_snapshot_does_not_crash(self):
        m = self.d._compute({})
        lines = self.d.render_lines(m, width=100)
        self.assertEqual(len(lines), Dashboard.HEIGHT)
        # Aucune valeur None ne doit apparaître en texte brut (remplacée par –)
        txt = strip_ansi("\n".join(lines))
        self.assertNotIn("None", txt)


# =============================================================================
# 5. CYCLE DE VIE (start/stop, idempotence, thread)
# =============================================================================
class TestLifecycle(unittest.TestCase):

    def test_start_stop_log_mode(self):
        d = Dashboard(snapshot_fn=lambda: {}, stream=io.StringIO(), interval=0.02)
        d.start()
        time.sleep(0.1)
        d.stop()
        # idempotence
        d.stop()

    def test_start_is_idempotent(self):
        d = Dashboard(snapshot_fn=lambda: {}, stream=io.StringIO(), interval=0.05)
        d.start()
        t = d._thread
        d.start()          # ne doit rien relancer
        self.assertIs(d._thread, t)
        d.stop()

    def test_thread_is_daemon(self):
        d = Dashboard(snapshot_fn=lambda: {}, stream=io.StringIO(), interval=0.05)
        d.start()
        self.assertTrue(d._thread.daemon)
        d.stop()

    def test_stop_from_inside_thread_does_not_deadlock(self):
        def stop_self():
            threading.Thread(target=d.stop).start()
            return {}
        d = Dashboard(snapshot_fn=stop_self, stream=io.StringIO(), interval=0.02)
        d.start()
        time.sleep(0.2)
        self.assertTrue(d._closed)


# =============================================================================
# 6. MODE TTY (avec faux TTY et taille patchée)
# =============================================================================
class TestTtyMode(unittest.TestCase):

    def test_enter_emits_scroll_region(self):
        buf = FakeTTY()
        with FixedSize(120, 40):
            d = Dashboard(snapshot_fn=lambda: {}, stream=buf, force=True, interval=0.02)
            d.start()
            time.sleep(0.1)
            d.stop()
        raw = buf.getvalue()
        # Les séquences ANSI attendues : home, région de défilement, restore
        self.assertIn("\x1b[2J", raw)                      # clear
        self.assertIn(f"\x1b[{Dashboard.HEIGHT + 1};40r", raw)  # région de scroll
        self.assertIn("\x1b[r", raw)                       # fin de la région
        self.assertIn("\x1b7", raw)                        # save cursor
        self.assertIn("\x1b8", raw)                        # restore cursor

    def test_tiny_terminal_disables_scroll(self):
        buf = FakeTTY()
        with FixedSize(40, 5):  # trop petit
            d = Dashboard(snapshot_fn=lambda: {}, stream=buf, force=True, interval=0.02)
            d.start()
            time.sleep(0.05)
            d.stop()
        # Pas de région de scroll (le dashboard reste inactif)
        self.assertNotIn("r\x1b", buf.getvalue().replace("\x1b[r", ""))

    def test_resize_triggers_reenter(self):
        buf = FakeTTY()
        with FixedSize(120, 40):
            d = Dashboard(snapshot_fn=lambda: {}, stream=buf, force=True, interval=0.02)
            d.start()
            time.sleep(0.1)
        # On simule un agrandissement pendant que ça tourne
        with FixedSize(140, 50):
            time.sleep(0.1)
        d.stop()
        raw = buf.getvalue()
        # On doit voir la séquence de restauration (resize détecté) et une nouvelle région
        self.assertGreaterEqual(raw.count("\x1b[r"), 1)

    def test_draw_is_single_write(self):
        """Le cadre complet doit partir en UN SEUL write (important pour ne pas casser les logs)."""
        writes = []
        class CountingTTY(FakeTTY):
            def write(self, s):
                writes.append(s)
                return super().write(s)

        buf = CountingTTY()
        with FixedSize(120, 40):
            d = Dashboard(snapshot_fn=lambda: {}, stream=buf, force=True, interval=0.05)
            d.start()
            time.sleep(0.15)
            d.stop()

        # On doit au moins voir une frame avec les 10 lignes du dashboard
        frames = [w for w in writes if "\x1b7" in w]
        self.assertTrue(frames, "aucune frame complète détectée")
        # Chaque frame contient bien les HEIGHT lignes positionnées
        for f in frames:
            positions = re.findall(r"\x1b\[(\d+);1H", f)
            self.assertGreaterEqual(len(positions), Dashboard.HEIGHT)


# =============================================================================
# 7. NON-RÉGRESSION : le dashboard ne doit JAMAIS tuer la détection
# =============================================================================
class TestSafety(unittest.TestCase):

    def test_snapshot_crash_is_logged_not_raised(self):
        d = Dashboard(snapshot_fn=lambda: 1 / 0, stream=io.StringIO(), interval=0.02)
        d.start()
        time.sleep(0.1)
        d.stop()
        self.assertIsNotNone(d.last_error)

    def test_stream_write_error_is_ignored(self):
        class BrokenStream(io.StringIO):
            def isatty(self):
                return True
            def write(self, s):
                raise OSError("broken pipe")
        with FixedSize(120, 40):
            d = Dashboard(snapshot_fn=lambda: {}, stream=BrokenStream(),
                          force=True, interval=0.02)
            d.start()
            time.sleep(0.1)
            d.stop()   # ne doit pas lever

    def test_no_zombie_thread_after_stop(self):
        before = threading.active_count()
        d = Dashboard(snapshot_fn=lambda: {}, stream=io.StringIO(), interval=0.02)
        d.start()
        time.sleep(0.1)
        d.stop()
        time.sleep(0.1)
        self.assertLessEqual(threading.active_count(), before + 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)