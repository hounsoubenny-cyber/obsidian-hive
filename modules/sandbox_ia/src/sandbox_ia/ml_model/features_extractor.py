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
    extract_features(event)
        ├── _extract_syscall_features(event: SyscallEvent) → dict
        └── _extract_fs_features(event: FSEvent) → dict
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from sandbox_ia.tracers.fs_monitor import FSEvent
from sandbox_ia.tracers.syscall_tracer import SyscallEvent
from sandbox_ia.configs.features_extractor_config import (
    SENSITIVE_PATHS, SUSPICIOUS_EXTENSIONS, SUSPICIOUS_IPS,
    SUSPICIOUS_KEYWORDS, SUSPICIOUS_PORTS, FAMILY_ENCODING,
    FS_EVENT_TYPE_ENCODING, TOP_DANGEROUS_SYSCALLS,
    EXCLUDED
)


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION — SyscallEvent
# ─────────────────────────────────────────────────────────────────────────────

def _extract_syscall_features(event: SyscallEvent) -> dict:
    """
    Extrait les features d'un SyscallEvent.

    Parameters
    ----------
    event : SyscallEvent
        Event syscall intercepté par strace.

    Returns
    -------
    dict
        Dictionnaire de features. Le champ "syscall" est laissé en str
        pour être encodé via nn.Embedding dans le forward() du modèle.
    """
    args = event.args_raw or ""

    # Chemins sensibles
    sensitive = {k: 1 if v in args else 0 for k, v in SENSITIVE_PATHS.items()}

    # Extensions suspectes
    extensions = {k: 1 if v in args else 0 for k, v in SUSPICIOUS_EXTENSIONS.items()}

    # Mots-clés suspects
    keywords = {k: 1 if v in args.lower() else 0 for k, v in SUSPICIOUS_KEYWORDS.items()}

    return {
        # == IDENTIFIANT ==
        # syscall laissé en str pour nn.Embedding dans le modèle
        "syscall":        event.syscall,
        "family":         FAMILY_ENCODING.get(event.family, 5),
        "event_kind":     0,  # 0 = syscall, 1 = fs_event

        # === TEMPOREL ===
        "timestamp":      event.timestamp_date.timestamp(),
        "duration":       event.duration or 0.0,

        # === RETOUR ===
        "retval":         float(event.retval) if event.retval is not None else 0.0,
        "retval_success": 1 if event.retval is not None and event.retval >= 0 else 0,
        "is_error":       1 if event.is_error else 0,

        # === SCORE ===
        "base_score":     event.threat_score,

        # === PROCESSUS ===
        "has_child_pid":  1 if event.pid is not None else 0,

        # === CRITICITÉ ===
        "is_top_dangerous": 1 if event.syscall in TOP_DANGEROUS_SYSCALLS else 0,

        # === ARGUMENTS — structure ===
        "args_length":    len(args),
        "has_path":       1 if any(x in args for x in ["/", "."]) else 0,
        "has_fd":         1 if "fd=" in args or "AT_FDCWD" in args else 0,
        "has_flags":      1 if "O_" in args or "PROT_" in args else 0,
        "has_ptr":        1 if "0x" in args or "NULL" in args else 0,
        "has_size":       1 if any(x in args for x in ["len=", "size=", "count="]) else 0,

        # === FLAGS d'accès ===
        "flag_read":      1 if "O_RDONLY" in args or "PROT_READ" in args else 0,
        "flag_write":     1 if "O_WRONLY" in args or "PROT_WRITE" in args or "O_RDWR" in args else 0,
        "flag_exec":      1 if "PROT_EXEC" in args else 0,
        "flag_create":    1 if "O_CREAT" in args else 0,
        "flag_trunc":     1 if "O_TRUNC" in args else 0,
        "flag_append":    1 if "O_APPEND" in args else 0,
        "flag_noblock":   1 if "O_NONBLOCK" in args else 0,
        "flag_cloexec":   1 if "O_CLOEXEC" in args else 0,

        # === RÉSEAU ===
        "is_ip":          1 if any(x in args for x in SUSPICIOUS_IPS) else 0,
        "has_port":       1 if any(x in args for x in SUSPICIOUS_PORTS) else 0,
        "is_af_inet":     1 if "AF_INET" in args else 0,

        # === MÉMOIRE ===
        "prot_exec_write": 1 if "PROT_EXEC" in args and "PROT_WRITE" in args else 0,
        "map_anonymous":  1 if "MAP_ANONYMOUS" in args or "MAP_ANON" in args else 0,
        "map_private":    1 if "MAP_PRIVATE" in args else 0,

        # === CHEMINS SENSIBLES ===
        **sensitive,

        # === EXTENSIONS ===
        **extensions,

        # === MOTS-CLÉS SUSPECTS ===
        **keywords,

        # === FEATURES ABSENTES (fs uniquement) → 0 ===
        "is_canary":      0,
        "is_suspicious_path": 0,
        "is_directory":   0,
        "path_depth":     args.count("/"),
        "fs_event_type":  -1,  # pas un fs_event
    }


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION — FSEvent
# ─────────────────────────────────────────────────────────────────────────────

def _extract_fs_features(event: FSEvent) -> dict:
    """
    Extrait les features d'un FSEvent.

    Les features absentes dans FSEvent (retval, flags syscall, réseau...)
    sont mises à 0 pour garantir un vecteur de même dimension que SyscallEvent.

    Parameters
    ----------
    event : FSEvent
        Event filesystem détecté par watchdog/inotify.

    Returns
    -------
    dict
        Dictionnaire de features de même structure que _extract_syscall_features.
        Le champ "syscall" est un pseudo-syscall "fs_<event_type>" pour
        l'Embedding (index spécial réservé dans le vocabulaire).
    """
    path = event.path or ""

    # Chemins sensibles 
    sensitive = {k: 1 if v in path else 0 for k, v in SENSITIVE_PATHS.items()}

    # Extensions suspectes (depuis le path)
    extensions = {k: 1 if path.endswith(v) else 0 for k, v in SUSPICIOUS_EXTENSIONS.items()}

    # Mots-clés suspects (depuis le path)
    keywords = {k: 1 if v in path.lower() else 0 for k, v in SUSPICIOUS_KEYWORDS.items()}

    event_type = event.event_type or "modified"

    return {
        # === IDENTIFIANT ===
        # pseudo-syscall pour l'Embedding → index spécial "fs_created" etc.
        "syscall":        f"fs_{event_type}",
        "family":         FAMILY_ENCODING["file"],
        "event_kind":     1,  # 1 = fs_event

        # === TEMPOREL ===
        "timestamp":      event.timestamp_date.timestamp(),
        "duration":       0.0,

        # === RETOUR ===
        "retval":         0.0,
        "retval_success": 1,
        "is_error":       0,

        # === SCORE ===
        "base_score":     event.threat_score,

        # === PROCESSUS ===
        "has_child_pid":  0,

        # === CRITICITÉ ===
        "is_top_dangerous": 0,

        # === ARGUMENTS — structure ===
        "args_length":    len(path),
        "has_path":       1,
        "has_fd":         0,
        "has_flags":      0,
        "has_ptr":        0,
        "has_size":       0,

        # === FLAGS d'accès ===
        "flag_read":      1 if event_type in ("opened", "modified") else 0,
        "flag_write":     1 if event_type in ("created", "modified") else 0,
        "flag_exec":      0,
        "flag_create":    1 if event_type == "created" else 0,
        "flag_trunc":     1 if event_type == "deleted" else 0,
        "flag_append":    1 if event_type == "modified" else 0,
        "flag_noblock":   0,
        "flag_cloexec":   0,

        # === RÉSEAU ===
        "is_ip":          0,
        "has_port":       0,
        "is_af_inet":     0,

        # === MÉMOIRE ===
        "prot_exec_write": 0,
        "map_anonymous":  0,
        "map_private":    0,

        # === CHEMINS SENSIBLES ===
        **sensitive,

        # === EXTENSIONS ===
        **extensions,

        # === MOTS-CLÉS SUSPECTS ===
        **keywords,

        # === FEATURES FS SPÉCIFIQUES ===
        "is_canary":          1 if event.is_canary else 0,
        "is_suspicious_path": 1 if event.is_suspicious else 0,
        "is_directory":       1 if event.is_directory else 0,
        "path_depth":         path.count("/"),
        "fs_event_type":      FS_EVENT_TYPE_ENCODING.get(event_type, 0),
    }


# ─────────────────────────────────────────────────────────────────────────────
# POINT D'ENTRÉE PUBLIC
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(event: FSEvent | SyscallEvent) -> dict:
    """
    Extrait les features d'un event sandbox (FSEvent ou SyscallEvent).

    Dispatche vers _extract_syscall_features ou _extract_fs_features
    selon le type de l'event via isinstance().

    Le vecteur produit est toujours de même structure quelle que soit
    la source de l'event — indispensable pour le modèle ML.

    Parameters
    ----------
    event : FSEvent | SyscallEvent
        Event sandbox à transformer en features.

    Returns
    -------
    dict
        Dictionnaire de features avec les champs :
        - "syscall" : str (à encoder via nn.Embedding dans le modèle)
        - "family"  : int (0-5, label encoding)
        - tous les autres : float ou int

    Raises
    ------
    TypeError
        Si l'event n'est ni un FSEvent ni un SyscallEvent.
    """
    if isinstance(event, SyscallEvent):
        return _extract_syscall_features(event)
    elif isinstance(event, FSEvent):
        return _extract_fs_features(event)
    else:
        raise TypeError(f"Type d'event non supporté: {type(event)}")


def get_feature_names() -> list[str]:
    """
    Retourne la liste ordonnée des noms de features numériques.

    Exclut "syscall" (str, géré par Embedding) et "timestamp"
    (non normalisé, utilisé uniquement pour le contexte fenêtre).

    Returns
    -------
    list[str]
        Noms des features dans l'ordre du vecteur numérique.
    """
    # On instancie un event fictif pour récupérer les clés dans l'ordre
    from dataclasses import dataclass
    from datetime import datetime

    @dataclass
    class SyscallEvent:
        syscall = "openat"
        family = "file"
        args_raw = ""
        retval = 0
        duration = 0.0
        is_error = False
        threat_score = 0
        pid = None
        timestamp_date = datetime.utcnow()

    sample = _extract_syscall_features(SyscallEvent())
    return [k for k in sample.keys() if k not in EXCLUDED]

if __name__ == "__main__":
    from datetime import datetime
    
    print("\n" + "="*60)
    print("🧪 TEST FeatureExtractor")
    print("="*60)

    # ── SyscallEvent — openat sur fichier canary ──────────────────────
    syscall_event = SyscallEvent(
        timestamp_date=datetime.utcnow(),
        timestamp_str="12:34:56.123456",
        pid=None,
        syscall="openat",
        args_raw='AT_FDCWD, "/etc/shadow", O_RDONLY',
        retval=3,
        duration=0.000042,
        family="file",
        threat_score=10,
        is_error=False,
    )

    features_syscall = extract_features(syscall_event)
    print("\n📌 SyscallEvent (openat /etc/shadow)")
    print(f"   syscall       : {features_syscall['syscall']}")
    print(f"   family        : {features_syscall['family']}")
    print(f"   is_shadow     : {features_syscall['is_shadow']}")
    print(f"   flag_read     : {features_syscall['flag_read']}")
    print(f"   has_path      : {features_syscall['has_path']}")
    print(f"   is_top_danger : {features_syscall['is_top_dangerous']}")
    print(f"   base_score    : {features_syscall['base_score']}")
    assert features_syscall["is_shadow"] == 1
    assert features_syscall["flag_read"] == 1
    assert features_syscall["is_error"] == 0
    assert features_syscall["event_kind"] == 0
    print("   ✅ assertions OK")

    # ── SyscallEvent — ptrace (top dangerous) ────────────────────────
    ptrace_event = SyscallEvent(
        timestamp_date=datetime.utcnow(),
        timestamp_str="12:34:57.000000",
        pid=1847,
        syscall="ptrace",
        args_raw="PTRACE_ATTACH, 1234, NULL, 0",
        retval=0,
        duration=0.0001,
        family="process",
        threat_score=50,
        is_error=False,
    )

    features_ptrace = extract_features(ptrace_event)
    print("\n📌 SyscallEvent (ptrace)")
    print(f"   syscall         : {features_ptrace['syscall']}")
    print(f"   is_top_dangerous: {features_ptrace['is_top_dangerous']}")
    print(f"   has_child_pid   : {features_ptrace['has_child_pid']}")
    print(f"   base_score      : {features_ptrace['base_score']}")
    assert features_ptrace["is_top_dangerous"] == 1
    assert features_ptrace["has_child_pid"] == 1
    assert features_ptrace["family"] == 2  # process
    print("   ✅ assertions OK")

    # ── SyscallEvent — mmap PROT_EXEC|PROT_WRITE (shellcode) ─────────
    mmap_event = SyscallEvent(
        timestamp_date=datetime.utcnow(),
        timestamp_str="12:34:58.000000",
        pid=None,
        syscall="mmap",
        args_raw="NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0",
        retval=140234567890,
        duration=0.00002,
        family="memory",
        threat_score=5,
        is_error=False,
    )

    features_mmap = extract_features(mmap_event)
    print("\n📌 SyscallEvent (mmap PROT_EXEC|PROT_WRITE → shellcode)")
    print(f"   prot_exec_write : {features_mmap['prot_exec_write']}")
    print(f"   flag_exec       : {features_mmap['flag_exec']}")
    print(f"   flag_write      : {features_mmap['flag_write']}")
    print(f"   map_anonymous   : {features_mmap['map_anonymous']}")
    assert features_mmap["prot_exec_write"] == 1
    assert features_mmap["flag_exec"] == 1
    assert features_mmap["map_anonymous"] == 1
    print("   ✅ assertions OK")

    # ── FSEvent — fichier canary créé ────────────────────────────────
    fs_event = FSEvent(
        timestamp_date=datetime.utcnow(),
        timestamp_time=datetime.utcnow().timestamp(),
        event_type="created",
        path="/home/devops/.ssh/id_rsa",
        src_path="/var/lib/docker/.../home/devops/.ssh/id_rsa",
        dest_path="",
        is_directory=False,
        is_canary=True,
        is_suspicious=True,
        threat_score=40,
    )

    features_fs = extract_features(fs_event)
    print("\n📌 FSEvent (created /home/devops/.ssh/id_rsa)")
    print(f"   syscall       : {features_fs['syscall']}")
    print(f"   is_canary     : {features_fs['is_canary']}")
    print(f"   is_ssh        : {features_fs['is_ssh']}")
    print(f"   is_home       : {features_fs['is_home']}")
    print(f"   flag_create   : {features_fs['flag_create']}")
    print(f"   path_depth    : {features_fs['path_depth']}")
    print(f"   event_kind    : {features_fs['event_kind']}")
    assert features_fs["is_canary"] == 1
    assert features_fs["is_ssh"] == 1
    assert features_fs["flag_create"] == 1
    assert features_fs["event_kind"] == 1
    assert features_fs["syscall"] == "fs_created"
    print("   ✅ assertions OK")

    # ── FSEvent — fichier .sh créé dans /tmp ─────────────────────────
    fs_sh = FSEvent(
        timestamp_date=datetime.utcnow(),
        timestamp_time=datetime.utcnow().timestamp(),
        event_type="created",
        path="/tmp/backdoor.sh",
        src_path="/var/lib/docker/.../tmp/backdoor.sh",
        dest_path="",
        is_directory=False,
        is_canary=False,
        is_suspicious=True,
        threat_score=25,
    )

    features_sh = extract_features(fs_sh)
    print("\n📌 FSEvent (created /tmp/backdoor.sh)")
    print(f"   ext_sh        : {features_sh['ext_sh']}")
    print(f"   is_tmp        : {features_sh['is_tmp']}")
    print(f"   has_backdoor  : {features_sh['has_backdoor']}")
    assert features_sh["ext_sh"] == 1
    assert features_sh["is_tmp"] == 1
    assert features_sh["has_backdoor"] == 1
    print("   ✅ assertions OK")

    # ── TypeError sur type inconnu ────────────────────────────────────
    print("\n📌 Test TypeError sur type inconnu")
    try:
        extract_features("not_an_event")
        assert False, "Aurait dû lever TypeError"
    except TypeError as e:
        print(f"   TypeError levé correctement : {e}")
        print("   ✅ assertion OK")

    # ── get_feature_names ─────────────────────────────────────────────
    names = get_feature_names()
    print(f"\n📌 get_feature_names() → {len(names)} features numériques")
    print(f"   {names[:8]}...")
    assert "syscall" not in names
    assert "timestamp" not in names
    assert "base_score" in names
    assert "is_shadow" in names
    print("   ✅ assertions OK")

    print("\n" + "="*60)
    print("🎉 TOUS LES TESTS PASSÉS")
    print("="*60)