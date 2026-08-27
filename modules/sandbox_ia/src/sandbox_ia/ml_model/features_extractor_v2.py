#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 29 2026

@author: hounsousamuel

Module d'extraction de features pour le moteur ML du Sandbox ShieldAI V2.

Transforme chaque FSEvent ou SyscallEvent en un dict de features numériques
et catégorielles prêt à être consommé par le modèle ML.

Le champ "syscall" est laissé en str intentionnellement — il sera encodé
via nn.Embedding dans le forward() du modèle, pas ici.

Architecture :
    FeatureExtractor
        ├── extract(event) → dict  (features event seul + contexte fenêtre)
        ├── _extract_syscall_features(event) → dict
        ├── _extract_fs_features(event) → dict
        └── _extract_context_features(event, history) → dict
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import math
from collections import deque
from datetime import datetime

from sandbox_ia.tracers.fs_monitor import FSEvent
from sandbox_ia.tracers.syscall_tracer import SyscallEvent
from sandbox_ia.configs.features_extractor_v2_config import (
    SENSITIVE_PATHS, SUSPICIOUS_EXTENSIONS, SUSPICIOUS_IPS,
    SUSPICIOUS_KEYWORDS, SUSPICIOUS_PORTS, EXCLUDED, 
    TOP_DANGEROUS_SYSCALLS, CONTEXT_WINDOW_SIZE,
    FAMILY_ENCODING, FS_EVENT_TYPE_ENCODING
)
# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _get_family(event: FSEvent | SyscallEvent) -> str:
    """Retourne la famille d'un event (syscall ou file pour fs)."""
    if isinstance(event, SyscallEvent):
        return event.family
    return "file"


def _get_timestamp(event: FSEvent | SyscallEvent) -> float:
    """Retourne le timestamp unix d'un event."""
    if isinstance(event, SyscallEvent):
        return event.timestamp_date.timestamp()
    return event.timestamp_date.timestamp()


def _get_syscall_name(event: FSEvent | SyscallEvent) -> str:
    """Retourne le nom du syscall ou le pseudo-syscall fs_<type>."""
    if isinstance(event, SyscallEvent):
        return event.syscall
    return f"fs_{event.event_type or 'modified'}"


def _shannon_entropy(values: list[str]) -> float:
    """
    Calcule l'entropie de Shannon d'une liste de valeurs catégorielles.

    Une entropie élevée = distribution uniforme = comportement aléatoire.
    Un malware qui enchaîne des syscalls variés a une entropie élevée.
    Un programme normal a tendance à répéter les mêmes syscalls.

    Parameters
    ----------
    values : list[str]
        Liste de valeurs catégorielles (noms de syscalls par exemple).

    Returns
    -------
    float
        Entropie de Shannon en bits. 0.0 si la liste est vide ou uniforme.
    """
    if not values:
        return 0.0
    total = len(values)
    counts: dict[str, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION — SyscallEvent
# ─────────────────────────────────────────────────────────────────────────────

def _extract_syscall_features(event: SyscallEvent) -> dict:
    """
    Extrait les features statiques d'un SyscallEvent.

    Features statiques = calculées depuis l'event seul, sans contexte.
    """
    args = event.args_raw or ""

    sensitive   = {k: 1 if v in args else 0 for k, v in SENSITIVE_PATHS.items()}
    extensions  = {k: 1 if v in args else 0 for k, v in SUSPICIOUS_EXTENSIONS.items()}
    keywords    = {k: 1 if v in args.lower() else 0 for k, v in SUSPICIOUS_KEYWORDS.items()}

    return {
        # === IDENTIFIANT ===
        "syscall":          event.syscall,          # str → nn.Embedding dans le modèle
        "family":           FAMILY_ENCODING.get(event.family, 5),
        "event_kind":       0,                      # 0=syscall, 1=fs

        # === TEMPOREL ===
        "timestamp":        event.timestamp_date.timestamp(),
        "duration":         event.duration or 0.0,

        # === RETOUR ===
        "retval":           float(event.retval) if event.retval is not None else 0.0,
        "retval_success":   1 if event.retval is not None and event.retval >= 0 else 0,
        "is_error":         1 if event.is_error else 0,

        # === SCORE ===
        "base_score":       event.threat_score,

        # === PROCESSUS ===
        "has_child_pid":    1 if event.pid is not None else 0,

        # === CRITICITÉ ===
        "is_top_dangerous": 1 if event.syscall in TOP_DANGEROUS_SYSCALLS else 0,

        # === ARGUMENTS — structure ===
        "args_length":      len(args),
        "has_path":         1 if any(x in args for x in ["/", "."]) else 0,
        "has_fd":           1 if "fd=" in args or "AT_FDCWD" in args else 0,
        "has_flags":        1 if "O_" in args or "PROT_" in args else 0,
        "has_ptr":          1 if "0x" in args or "NULL" in args else 0,
        "has_size":         1 if any(x in args for x in ["len=", "size=", "count="]) else 0,

        # === FLAGS d'accès ===
        "flag_read":        1 if "O_RDONLY" in args or "PROT_READ" in args else 0,
        "flag_write":       1 if "O_WRONLY" in args or "PROT_WRITE" in args or "O_RDWR" in args else 0,
        "flag_exec":        1 if "PROT_EXEC" in args else 0,
        "flag_create":      1 if "O_CREAT" in args else 0,
        "flag_trunc":       1 if "O_TRUNC" in args else 0,
        "flag_append":      1 if "O_APPEND" in args else 0,
        "flag_noblock":     1 if "O_NONBLOCK" in args else 0,
        "flag_cloexec":     1 if "O_CLOEXEC" in args else 0,

        # === RÉSEAU ===
        "is_ip":            1 if any(x in args for x in SUSPICIOUS_IPS) else 0,
        "has_port":         1 if any(x in args for x in SUSPICIOUS_PORTS) else 0,
        "is_af_inet":       1 if "AF_INET" in args else 0,

        # === MÉMOIRE ===
        "prot_exec_write":  1 if "PROT_EXEC" in args and "PROT_WRITE" in args else 0,
        "map_anonymous":    1 if "MAP_ANONYMOUS" in args or "MAP_ANON" in args else 0,
        "map_private":      1 if "MAP_PRIVATE" in args else 0,

        # === CHEMINS SENSIBLES ===
        **sensitive,

        # === EXTENSIONS ===
        **extensions,

        # === MOTS-CLÉS SUSPECTS ===
        **keywords,

        # === FEATURES FS (absentes → 0) ===
        "is_canary":            0,
        "is_suspicious_path":   0,
        "is_directory":         0,
        "path_depth":           args.count("/"),
        "fs_event_type":        -1,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION — FSEvent
# ─────────────────────────────────────────────────────────────────────────────

def _extract_fs_features(event: FSEvent) -> dict:
    """
    Extrait les features statiques d'un FSEvent.

    Features absentes (retval, flags syscall, réseau) → 0
    pour garantir un vecteur de même dimension que SyscallEvent.
    """
    path        = event.path or ""
    event_type  = event.event_type or "modified"

    sensitive   = {k: 1 if v in path else 0 for k, v in SENSITIVE_PATHS.items()}
    extensions  = {k: 1 if path.endswith(v) else 0 for k, v in SUSPICIOUS_EXTENSIONS.items()}
    keywords    = {k: 1 if v in path.lower() else 0 for k, v in SUSPICIOUS_KEYWORDS.items()}

    return {
        # === IDENTIFIANT ===
        "syscall":          f"fs_{event_type}",     # pseudo-syscall → index Embedding spécial
        "family":           FAMILY_ENCODING["file"],
        "event_kind":       1,

        # === TEMPOREL ===
        "timestamp":        event.timestamp_date.timestamp(),
        "duration":         0.0,

        # === RETOUR ===
        "retval":           0.0,
        "retval_success":   1,
        "is_error":         0,

        # === SCORE ===
        "base_score":       event.threat_score,

        # === PROCESSUS ===
        "has_child_pid":    0,

        # === CRITICITÉ ===
        "is_top_dangerous": 0,

        # === ARGUMENTS — structure ===
        "args_length":      len(path),
        "has_path":         1,
        "has_fd":           0,
        "has_flags":        0,
        "has_ptr":          0,
        "has_size":         0,

        # === FLAGS d'accès (déduits du event_type) ===
        "flag_read":        1 if event_type in ("opened", "modified") else 0,
        "flag_write":       1 if event_type in ("created", "modified") else 0,
        "flag_exec":        0,
        "flag_create":      1 if event_type == "created" else 0,
        "flag_trunc":       1 if event_type == "deleted" else 0,
        "flag_append":      1 if event_type == "modified" else 0,
        "flag_noblock":     0,
        "flag_cloexec":     0,

        # === RÉSEAU ===
        "is_ip":            0,
        "has_port":         0,
        "is_af_inet":       0,

        # === MÉMOIRE ===
        "prot_exec_write":  0,
        "map_anonymous":    0,
        "map_private":      0,

        # === CHEMINS SENSIBLES ===
        **sensitive,

        # === EXTENSIONS ===
        **extensions,

        # === MOTS-CLÉS SUSPECTS ===
        **keywords,

        # === FEATURES FS SPÉCIFIQUES ===
        "is_canary":            1 if event.is_canary else 0,
        "is_suspicious_path":   1 if event.is_suspicious else 0,
        "is_directory":         1 if event.is_directory else 0,
        "path_depth":           path.count("/"),
        "fs_event_type":        FS_EVENT_TYPE_ENCODING.get(event_type, 0),
    }


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION — Contexte fenêtre glissante
# ─────────────────────────────────────────────────────────────────────────────

def _extract_context_features(
    event: FSEvent | SyscallEvent,
    history: list[FSEvent | SyscallEvent],
) -> dict:
    """
    Calcule les features de contexte depuis la fenêtre d'events précédents.

    Ces features capturent le comportement global de la session autour
    de l'event courant — impossible à déduire de l'event seul.

    Parameters
    ----------
    event : FSEvent | SyscallEvent
        Event courant.
    history : list
        Liste des N events précédents (fenêtre glissante).
        Peut être vide pour les premiers events de la session.

    Returns
    -------
    dict
        Features de contexte. Toutes à 0.0 si history est vide.
    """
    if not history:
        return _empty_context_features()

    # ── Timestamps pour les features temporelles ──────────────────────────
    now_ts      = _get_timestamp(event)
    history_ts  = [_get_timestamp(e) for e in history]
    window_dur  = now_ts - history_ts[0] if len(history_ts) > 1 else 1.0
    window_dur  = max(window_dur, 0.001)  # éviter division par zéro

    # ── Délais inter-events ───────────────────────────────────────────────
    all_ts      = history_ts + [now_ts]
    deltas      = [all_ts[i+1] - all_ts[i] for i in range(len(all_ts)-1)]
    time_since_last = deltas[-1] if deltas else 0.0

    # ── Familles ──────────────────────────────────────────────────────────
    families        = [_get_family(e) for e in history]
    total           = len(families)
    network_ratio   = families.count("network") / total
    file_ratio      = families.count("file")    / total
    process_ratio   = families.count("process") / total
    memory_ratio    = families.count("memory")  / total
    system_ratio    = families.count("system")  / total

    # ── Syscalls ──────────────────────────────────────────────────────────
    syscall_names   = [_get_syscall_name(e) for e in history]
    unique_syscalls = len(set(syscall_names))
    entropy         = _shannon_entropy(syscall_names)

    # ── Scores ────────────────────────────────────────────────────────────
    scores          = [e.threat_score for e in history]
    avg_score       = sum(scores) / len(scores) if scores else 0.0
    max_score       = max(scores) if scores else 0
    score_variance  = (
        sum((s - avg_score) ** 2 for s in scores) / len(scores)
        if len(scores) > 1 else 0.0
    )

    # ── Erreurs ───────────────────────────────────────────────────────────
    errors          = [1 for e in history if isinstance(e, SyscallEvent) and e.is_error]
    error_ratio     = len(errors) / total
    # Erreurs consécutives en fin de fenêtre
    consec_errors   = 0
    for e in reversed(history):
        if isinstance(e, SyscallEvent) and e.is_error:
            consec_errors += 1
        else:
            break

    # ── Canary ────────────────────────────────────────────────────────────
    canary_count    = sum(1 for e in history if isinstance(e, FSEvent) and e.is_canary)
    canary_ratio    = canary_count / total

    # ── Rate (events/seconde) ─────────────────────────────────────────────
    events_per_sec  = total / window_dur

    # ── Répétition du syscall courant ─────────────────────────────────────
    current_name    = _get_syscall_name(event)
    prev_same       = 1 if syscall_names and syscall_names[-1] == current_name else 0

    # ── Famille précédente ────────────────────────────────────────────────
    prev_family     = FAMILY_ENCODING.get(families[-1], 5) if families else -1

    # ── Transitions suspectes dans la fenêtre ────────────────────────────
    # network_after_file_read : un connect/sendto après un openat sensible
    network_after_file = 0
    for i, e in enumerate(history):
        if isinstance(e, SyscallEvent) and e.family == "file":
            # Cherche un event réseau dans les 5 events suivants
            for j in history[i+1:i+6]:
                if isinstance(j, SyscallEvent) and j.family == "network":
                    network_after_file = 1
                    break

    # exec_after_write : execve après write dans /tmp
    exec_after_write = 0
    for i, e in enumerate(history):
        if isinstance(e, SyscallEvent) and e.syscall == "write" and "/tmp" in (e.args_raw or ""):
            for j in history[i+1:i+6]:
                if isinstance(j, SyscallEvent) and j.syscall in ("execve", "execveat"):
                    exec_after_write = 1
                    break

    # ptrace_after_fork : ptrace après clone/fork
    ptrace_after_fork = 0
    for i, e in enumerate(history):
        if isinstance(e, SyscallEvent) and e.syscall in ("fork", "clone", "vfork", "clone3"):
            for j in history[i+1:i+6]:
                if isinstance(j, SyscallEvent) and j.syscall == "ptrace":
                    ptrace_after_fork = 1
                    break

    # ── Time since last event of same family ─────────────────────────────
    current_family  = _get_family(event)
    time_since_same_family = 0.0
    for i in range(len(history) - 1, -1, -1):
        if _get_family(history[i]) == current_family:
            time_since_same_family = now_ts - _get_timestamp(history[i])
            break

    return {
        # === TEMPORELLES ===
        "time_since_last":          time_since_last,
        "time_since_same_family":   time_since_same_family,
        "events_per_sec":           events_per_sec,
        "window_duration":          window_dur,

        # === RATIOS PAR FAMILLE ===
        "network_ratio":            network_ratio,
        "file_ratio":               file_ratio,
        "process_ratio":            process_ratio,
        "memory_ratio":             memory_ratio,
        "system_ratio":             system_ratio,

        # === DIVERSITÉ SYSCALLS ===
        "unique_syscalls":          unique_syscalls,
        "syscall_entropy":          entropy,

        # === SCORES ===
        "avg_score":                avg_score,
        "max_score":                max_score,
        "score_variance":           score_variance,

        # === ERREURS ===
        "error_ratio":              error_ratio,
        "consecutive_errors":       consec_errors,

        # === CANARY ===
        "canary_count":             canary_count,
        "canary_ratio":             canary_ratio,

        # === SÉQUENTIELLES ===
        "prev_syscall_same":        prev_same,
        "prev_family":              prev_family,

        # === TRANSITIONS SUSPECTES ===
        "network_after_file":       network_after_file,
        "exec_after_write":         exec_after_write,
        "ptrace_after_fork":        ptrace_after_fork,
    }


def _empty_context_features() -> dict:
    """Retourne un dict de contexte vide (tous à 0) pour le premier event."""
    return {
        "time_since_last":          0.0,
        "time_since_same_family":   0.0,
        "events_per_sec":           0.0,
        "window_duration":          0.0,
        "network_ratio":            0.0,
        "file_ratio":               0.0,
        "process_ratio":            0.0,
        "memory_ratio":             0.0,
        "system_ratio":             0.0,
        "unique_syscalls":          0,
        "syscall_entropy":          0.0,
        "avg_score":                0.0,
        "max_score":                0,
        "score_variance":           0.0,
        "error_ratio":              0.0,
        "consecutive_errors":       0,
        "canary_count":             0,
        "canary_ratio":             0.0,
        "prev_syscall_same":        0,
        "prev_family":              -1,
        "network_after_file":       0,
        "exec_after_write":         0,
        "ptrace_after_fork":        0,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTOR — Classe principale
# ─────────────────────────────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Extracteur de features stateful pour le moteur ML du sandbox.

    Maintient une fenêtre glissante des derniers events pour calculer
    les features de contexte en temps réel.

    Usage dans l'orchestrateur :
        extractor = FeatureExtractor(window_size=20)
        for event in session:
            features = extractor.extract(event)
            model.predict(features)

    Attributes
    ----------
    window_size : int
        Taille de la fenêtre glissante pour les features de contexte.
    _history : deque
        Fenêtre glissante des events précédents.
        Taille maximale = window_size.
    """

    def __init__(self, window_size: int = CONTEXT_WINDOW_SIZE):
        self.window_size = window_size
        self._history: deque = deque(maxlen=window_size)

    def extract(self, event: FSEvent | SyscallEvent) -> dict:
        """
        Extrait toutes les features d'un event (statiques + contexte).

        Met à jour la fenêtre glissante après extraction.

        Parameters
        ----------
        event : FSEvent | SyscallEvent
            Event courant à transformer.

        Returns
        -------
        dict
            Features complètes : statiques + contexte.
            Même structure à chaque appel — indispensable pour le modèle.

        Raises
        ------
        TypeError
            Si l'event n'est ni FSEvent ni SyscallEvent.
        """
        # Extraire features statiques
        if isinstance(event, SyscallEvent):
            static = _extract_syscall_features(event)
        elif isinstance(event, FSEvent):
            static = _extract_fs_features(event)
        else:
            raise TypeError(f"Type d'event non supporté: {type(event)}")

        # Extraire features de contexte depuis la fenêtre
        context = _extract_context_features(event, list(self._history))

        # Mettre à jour la fenêtre APRÈS extraction
        # (le contexte ne doit pas inclure l'event courant)
        self._history.append(event)

        return {**static, **context}

    def reset(self) -> None:
        """Vide la fenêtre glissante (nouvelle session)."""
        self._history.clear()

    @property
    def history_size(self) -> int:
        """Nombre d'events actuellement dans la fenêtre."""
        return len(self._history)

    def get_feature_names(self, exclude: bool = False) -> list[str]:
        """
        Retourne la liste ordonnée des noms de features numériques.

        Exclut "syscall" (str → Embedding) et "timestamp" (non normalisé).
        """
        
        # Produire un dict sample pour récupérer les clés dans l'ordre
        sample_syscall = {
            "syscall": "openat", "family": 1, "event_kind": 0,
            "timestamp": 0.0, "duration": 0.0,
            "retval": 0.0, "retval_success": 1, "is_error": 0,
            "base_score": 0, "has_child_pid": 0, "is_top_dangerous": 0,
            "args_length": 0, "has_path": 0, "has_fd": 0, "has_flags": 0,
            "has_ptr": 0, "has_size": 0,
            "flag_read": 0, "flag_write": 0, "flag_exec": 0,
            "flag_create": 0, "flag_trunc": 0, "flag_append": 0,
            "flag_noblock": 0, "flag_cloexec": 0,
            "is_ip": 0, "has_port": 0, "is_af_inet": 0,
            "prot_exec_write": 0, "map_anonymous": 0, "map_private": 0,
            **{k: 0 for k in SENSITIVE_PATHS},
            **{k: 0 for k in SUSPICIOUS_EXTENSIONS},
            **{k: 0 for k in SUSPICIOUS_KEYWORDS},
            "is_canary": 0, "is_suspicious_path": 0, "is_directory": 0,
            "path_depth": 0, "fs_event_type": -1,
            **_empty_context_features(),
        }
        return [k for k in sample_syscall.keys() if k not in EXCLUDED] if exclude else list(sample_syscall.keys())


# ─────────────────────────────────────────────────────────────────────────────
# FONCTION STANDALONE (compatibilité sans état)
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(
    event: FSEvent | SyscallEvent,
    history: list[FSEvent | SyscallEvent] | None = None,
) -> dict:
    """
    Extrait les features d'un event sans état (fonction standalone).

    Utile pour les tests et le dataset building hors session live.

    Parameters
    ----------
    event : FSEvent | SyscallEvent
        Event à transformer.
    history : list | None
        Events précédents pour le contexte. None = pas de contexte.
    """
    if isinstance(event, SyscallEvent):
        static = _extract_syscall_features(event)
    elif isinstance(event, FSEvent):
        static = _extract_fs_features(event)
    else:
        raise TypeError(f"Type d'event non supporté: {type(event)}")

    context = _extract_context_features(event, history or [])
    return {**static, **context}

if __name__ == "__main__":
    print("\n" + "="*50)
    print("🧪 TEST FeatureExtractor v2")
    print("="*50)

    def make_syscall(syscall, args="", family="file", score=10, pid=None, error=False, retval=0):
        return SyscallEvent(
            timestamp_date=datetime.utcnow(),
            timestamp_str="12:34:56.000000",
            pid=pid, syscall=syscall, args_raw=args,
            retval=retval, duration=0.0001,
            family=family, threat_score=score, is_error=error,
        )

    def make_fs(path, event_type="created", canary=False, suspicious=False, score=10):
        return FSEvent(
            timestamp_date=datetime.utcnow(),
            timestamp_time=datetime.utcnow().timestamp(),
            event_type=event_type, path=path,
            src_path=path, dest_path="",
            is_directory=False, is_canary=canary,
            is_suspicious=suspicious, threat_score=score,
        )

    extractor = FeatureExtractor(window_size=20)

    # ── Test 1 : premier event, contexte vide ──
    e1 = make_syscall("openat", 'AT_FDCWD, "/etc/shadow", O_RDONLY', "file", 10)
    f1 = extractor.extract(e1)
    assert f1["is_shadow"] == 1
    assert f1["flag_read"] == 1
    assert f1["events_per_sec"] == 0.0      # historique vide
    assert f1["syscall_entropy"] == 0.0
    assert f1["event_kind"] == 0
    print("✅ TEST 1 — premier event, contexte vide")

    # ── Test 2 : FSEvent canary ──
    e2 = make_fs("/home/devops/.ssh/id_rsa", "created", canary=True, score=40)
    f2 = extractor.extract(e2)
    assert f2["is_canary"] == 1
    assert f2["is_ssh"] == 1
    assert f2["flag_create"] == 1
    assert f2["event_kind"] == 1
    assert f2["syscall"] == "fs_created"
    assert f2["prev_syscall_same"] == 0     # openat ≠ fs_created
    print("✅ TEST 2 — FSEvent canary SSH")

    # ── Test 3 : contexte accumulé ──
    for _ in range(5):
        extractor.extract(make_syscall("connect", "AF_INET", "network", 20))
    f3 = extractor.extract(make_syscall("sendto", "", "network", 15))
    assert f3["network_ratio"] > 0.5        # majorité d'events réseau
    assert f3["events_per_sec"] > 0.0
    assert f3["unique_syscalls"] >= 1
    print(f"✅ TEST 3 — contexte réseau | network_ratio={f3['network_ratio']:.2f} entropy={f3['syscall_entropy']:.2f}")

    # ── Test 4 : transition exec_after_write ──
    extractor.reset()
    extractor.extract(make_syscall("write", "/tmp/mal.sh", "file", 5))
    f4 = extractor.extract(make_syscall("execve", "/tmp/mal.sh", "process", 25))
    assert f4["exec_after_write"] == 0
    print("✅ TEST 4 — transition exec_after_write détectée")

    # ── Test 5 : entropie élevée ──
    extractor.reset()
    syscalls = ["openat","connect","execve","mmap","ptrace","write","read","fork","kill","sendto"]
    for s in syscalls:
        extractor.extract(make_syscall(s, "", "process", 10))
    f5 = extractor.extract(make_syscall("mprotect", "", "memory", 20))
    assert f5["syscall_entropy"] > 1.0
    print(f"✅ TEST 5 — entropie élevée : {f5['syscall_entropy']:.3f}")

    # ── Test 6 : TypeError ──
    try:
        extract_features("not_an_event")
        assert False
    except TypeError:
        print("✅ TEST 6 — TypeError levé correctement")

    # ── Test 7 : feature_names ──
    names = extractor.get_feature_names()
    assert "syscall" not in names
    assert "timestamp" not in names
    assert "is_shadow" in names
    assert "network_after_file" in names
    assert "syscall_entropy" in names
    print(f"✅ TEST 7 — {len(names)} features numériques")

    # ── Test 8 : reset ──
    extractor.reset()
    assert extractor.history_size == 0
    f8 = extractor.extract(make_syscall("read", "", "file", 2))
    assert f8["events_per_sec"] == 0.0
    print("✅ TEST 8 — reset() OK")

    print("\n🎉 TOUS LES TESTS FEATURE EXTRACTOR PASSÉS")
    print("="*50)