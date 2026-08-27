#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed May 27 02:57:40 2026

@author: hounsousamuel

MockLogger — dispatch vers plusieurs scans simultanés.

Chaque scan enregistre son WSTextIO via register(scan_id, output).
Le logger préfixe chaque message avec le scan_id pour permettre le filtrage.
"""

import threading


class MockLogger:
    def __init__(self, logger=None):
        self._outputs: dict = {}  # {scan_id: WSTextIO}
        self._lock = threading.Lock()
        self.logger = logger

    def register(self, scan_id: str, output) -> None:
        """Enregistre un output WSTextIO pour un scan."""
        with self._lock:
            self._outputs[scan_id] = output

    def unregister(self, scan_id: str) -> None:
        """Désenregistre l'output d'un scan terminé."""
        with self._lock:
            self._outputs.pop(scan_id, None)

    def _write(self, msg: str) -> None:
        """
        Dispatch le message vers tous les outputs enregistrés.
        Chaque message est préfixé par le scan_id :
            [scan_id] [LEVEL] message
        Côté client/test, filtrer avec : msg.startswith(scan_id)
        """
        with self._lock:
            outputs = dict(self._outputs)  # snapshot thread-safe

        if outputs:
            for scan_id, output in outputs.items():
                try:
                    output.write(f"[{scan_id}] {msg}\n")
                except Exception:
                    pass  # output fermé ou invalide — on ignore
        else:
            print(msg)

        try:
            level = msg.split("]")[0][1:].lower()
            getattr(self.logger, level, lambda x: x)(msg)
        except Exception:
            pass

    def info(self, msg, *args, **kwargs):
        self._write(f"[INFO] {msg}")

    def debug(self, msg, *args, **kwargs):
        self._write(f"[DEBUG] {msg}")

    def warning(self, msg, *args, **kwargs):
        self._write(f"[WARNING] {msg}")

    def error(self, msg, *args, **kwargs):
        self._write(f"[ERROR] {msg}")

    def critical(self, msg, *args, **kwargs):
        self._write(f"[CRITICAL] {msg}")

    def success(self, msg, *args, **kwargs):
        self._write(f"[SUCCESS] {msg}")

    def trace(self, msg, *args, **kwargs):
        self._write(f"[TRACE] {msg}")

    def exception(self, msg, *args, **kwargs):
        self._write(f"[EXCEPTION] {msg}")

    def bind(self, **kwargs):
        return self

    def opt(self, *args, **kwargs):
        return self

    def print(self, *args, **kwargs):
        self._write(" ".join(str(a) for a in args))


class MockLogger2:
    def __init__(self, *args, **kwargs):
        pass

    def _write(self, *args, **kwargs):
        pass

    def info(self, msg, *args, **kwargs):
        self._write(f"[INFO] {msg}")

    def debug(self, msg, *args, **kwargs):
        self._write(f"[DEBUG] {msg}")

    def warning(self, msg, *args, **kwargs):
        self._write(f"[WARNING] {msg}")

    def error(self, msg, *args, **kwargs):
        self._write(f"[ERROR] {msg}")

    def critical(self, msg, *args, **kwargs):
        self._write(f"[CRITICAL] {msg}")

    def success(self, msg, *args, **kwargs):
        self._write(f"[SUCCESS] {msg}")

    def trace(self, msg, *args, **kwargs):
        self._write(f"[TRACE] {msg}")

    def exception(self, msg, *args, **kwargs):
        self._write(f"[EXCEPTION] {msg}")

    def bind(self, **kwargs):
        return self

    def opt(self, *args, **kwargs):
        return self


# Singleton global — un seul MockLogger pour toute l'API
_logger = None


def get_mock_logger(logger=None) -> MockLogger:
    """Retourne le MockLogger singleton."""
    global _logger
    if _logger is None:
        _logger = MockLogger(logger=logger)
    return _logger


def get_mock_logger2() -> MockLogger2:
    return MockLogger2()
