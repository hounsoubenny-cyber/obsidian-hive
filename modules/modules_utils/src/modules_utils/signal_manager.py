#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 21 08:34:38 2026

@author: hounsousamuel
"""

import os, sys, signal, threading


def ignore_termination_signals():
    """À appeler au tout début d'un process enfant (mp.Process) qui ne doit
    PAS réagir lui-même à Ctrl+C / kill : c'est le process parent qui pilote
    l'arrêt (ex: via un multiprocessing.Event). Un seul endroit à mettre à
    jour si la liste des signaux à ignorer change un jour."""
    # SIGINT et SIGTERM existent sur toutes les plateformes, pas besoin de check
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    # SIGQUIT (Ctrl+\) n'existe pas sur Windows, lui a besoin du check
    if sys.platform != "win32":
        signal.signal(signal.SIGQUIT, signal.SIG_IGN)

        
def signal_manager(func, *args, **kwargs):
    def function(sig, frame):
        func(sig, frame, *args, **kwargs)
        # os.kill(os.getpid(), 9)
        # os._exit(0)
        sys.exit(0)

    def make_chained(ancien):
        # "ancien" est capturé ici, une fois pour toutes, AVANT le remplacement
        def chained(sig, frame):
            # 1. on exécute l'ancien handler s'il existe et si c'est callable
            #    (signal.SIG_DFL et signal.SIG_IGN ne sont pas "callable")
            #    ⚠️ le handler par défaut de Python lève KeyboardInterrupt,
            #    donc on protège l'appel pour ne pas casser la chaîne
            if callable(ancien):
                try:
                    ancien(sig, frame)
                except BaseException as e:
                    print(f"(ancien handler a levé {e!r}, on continue quand même)")

            # 2. puis on exécute le nouveau
            function(sig, frame)

        return chained

    if threading.current_thread() is threading.main_thread():
        for sig in (
            [signal.SIGINT, signal.SIGTERM]
            + ([signal.SIGQUIT] if sys.platform != "win32" else [])
        ):
            ancien = signal.getsignal(sig)   # on lit l'ancien AVANT
            signal.signal(sig, make_chained(ancien))  # puis on remplace