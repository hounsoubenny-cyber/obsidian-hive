#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May 28 2026

@author: hounsousamuel

Module de traçage des syscalls pour le Sandbox ShieldAI V2.
Lit en temps réel la sortie de strace via le tail_process fourni par
ContainerManager.get_file_reader_process_async(), parse chaque ligne
en SyscallEvent structuré et l'envoie dans la SandBoxQueue vers
le behavior_scorer.

Pipeline :
    ContainerManager.attach_tracer_async()          → strace_process, log_file
    ContainerManager.get_file_reader_process_async() → tail_process
    SyscallTracer(tail_process, queue).run()         → SyscallEvent → queue
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import asyncio
from dataclasses import dataclass
from datetime import datetime
from sandbox_ia.tracers.fs_monitor import SandBoxQueue
from sandbox_ia.sandbox_utils.logger import get_logger
from sandbox_ia.configs.syscall_tracer_config import SYSCALL_BONUS, SYSCALL_FAMILIES, IGNORE_PATTERNS
from modules_utils.stop_process import kill_process_group_async as kill_process
logger = get_logger()


# =============================================================================
# DATACLASS — Événement syscall
# =============================================================================

@dataclass
class SyscallEvent:
    """
    Représente un syscall intercepté par strace dans le container sandbox.

    Attributes
    ----------
    timestamp_date : datetime
        Date et heure UTC de parsing de la ligne.
    timestamp_str : str
        Timestamp brut extrait de la ligne : "12:34:56.123456".
    pid : int | None
        PID du processus enfant si présent ([pid XXXX] dans strace -f).
    syscall : str
        Nom du syscall : "openat", "execve", "connect"...
    args_raw : str
        Arguments bruts du syscall.
        Exemple : 'AT_FDCWD, "/etc/shadow", O_RDONLY'
    retval : int | None
        Valeur de retour du syscall. Négatif = erreur.
    duration : float | None
        Durée d'exécution du syscall en secondes.
    family : str
        Famille du syscall : "network", "file", "process", "memory", "system".
    threat_score : int
        Score de menace de base (0-100) calculé depuis SYSCALL_FAMILIES + SYSCALL_BONUS.
    is_error : bool
        True si retval < 0.
    """
    timestamp_date: datetime
    timestamp_str: str
    pid: int | None
    syscall: str
    args_raw: str
    retval: int | None
    duration: float | None
    family: str
    threat_score: int
    is_error: bool
    
    def to_dict(self) -> dict:
        return {
            "timestamp_date": self.timestamp_date.isoformat(),
            "timestamp_str": self.timestamp_str,
            "pid": self.pid,
            "syscall": self.syscall,
            "args_raw": self.args_raw,
            "retval": self.retval,
            "duration": self.duration,
            "family": self.family,
            "threat_score": self.threat_score,
            "is_error": self.is_error,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "SyscallEvent":
        return cls(
            timestamp_date=datetime.fromisoformat(data["timestamp_date"]),
            timestamp_str=data["timestamp_str"],
            pid=data["pid"],
            syscall=data["syscall"],
            args_raw=data["args_raw"],
            retval=data["retval"],
            duration=data["duration"],
            family=data["family"],
            threat_score=data["threat_score"],
            is_error=data["is_error"],
        )
    


# =============================================================================
# PARSER
# =============================================================================

class SyscallParser:
    """
    Parse les lignes strace brutes en SyscallEvent structurés.

    Utilisé par SyscallTracer pour transformer chaque ligne lue depuis
    tail_process.stdout en un événement exploitable par le behavior_scorer.

    Gère les cas particuliers :
    - Lignes incomplètes (syscall interrompu par un signal)
    - Lignes de signal strace ("--- SIGTERM ---")
    - Lignes de sortie de processus ("+++ exited with 0 +++")
    - Args contenant des parenthèses imbriquées
    - Pattern matching contextuel MITRE ATT&CK via KNOWN_PATTERNS
    """
    
    def __init__(
        self, 
        syscall_families: dict | None = None,
        syscall_bonus: dict | None = None,
        ignore_patterns: dict | None = None,
    ):
        self.syscall_families = syscall_families or SYSCALL_FAMILIES
        self.syscall_bonus = syscall_bonus or SYSCALL_BONUS
        self.ignore_patterns = ignore_patterns or IGNORE_PATTERNS
        

    def _should_ignore(self, line: str) -> bool:
        """
        Détermine si une ligne doit être ignorée.

        Vérifie la présence de motifs dans IGNORE_PATTERNS qui indiquent
        qu'une ligne n'est pas un syscall valide (signaux, exit, interruptions).

        Parameters
        ----------
        line : str
            Ligne brute de strace.

        Returns
        -------
        bool
            True si la ligne doit être ignorée, False sinon.
        """
        return any(ignore_pattern in line for ignore_pattern in self.ignore_patterns)

    @staticmethod
    def _detect_base(s: str) -> tuple[int, str]:
        """
        Détecte la base numérique d'une chaîne en fonction de son préfixe.

        Returns:
            tuple[int, str]: (base, valeur_nettoyée)
            - base: 10, 16, 8, ou 0 pour auto-détection int()
            - valeur_nettoyée: chaîne sans le préfixe (sauf pour '0x' et '0X')

        Examples:
            >>> SyscallParser._detect_base("123")
            (10, "123")
            >>> SyscallParser._detect_base("0x7fff")
            (16, "0x7fff")
            >>> SyscallParser._detect_base("-0x555d14787000")
            (16, "-0x555d14787000")
            >>> SyscallParser._detect_base("0755")      # octal
            (8, "0755")
            >>> SyscallParser._detect_base("0b1010")    # binaire
            (2, "0b1010")
        """
        s = s.strip()

        if s.startswith(("-0x", "-0X")):
            return 16, s
        if s.startswith(("0x", "0X")):
            return 16, s
        if s.startswith(("-0o", "-0O")):
            return 8, s
        if s.startswith(("0o", "0O")):
            return 8, s
        if s.startswith(("-0b", "-0B")):
            return 2, s
        if s.startswith(("0b", "0B")):
            return 2, s
        if s.startswith("0") and len(s) > 1 and s[1].isdigit():
            return 8, s
        return 10, s

    def _score(self, syscall: str) -> tuple[str, int]:
        """
        Calcule la famille et le threat score de base d'un syscall.

        Combine le score de base de la famille avec le bonus individuel
        si défini dans SYSCALL_BONUS. Score plafonné à 100.
        Le bonus contextuel de KNOWN_PATTERNS est ajouté séparément
        dans _match_pattern() et combiné dans parse().

        Parameters
        ----------
        syscall : str
            Nom du syscall en minuscules.

        Returns
        -------
        tuple[str, int]
            - str : famille ("network", "file", "process", "memory", "system",
                    ou "unknown" si le syscall n'est pas référencé)
            - int : threat score entre 0 et 100
        """
        if syscall not in self.syscall_families:
            return "unknown", 0

        syscall_family = self.syscall_families[syscall]
        family, base_score = syscall_family["family"], syscall_family["score"]
        bonus = self.syscall_bonus.get(syscall, 0)
        return family, min(base_score + bonus, 100)

    def parse(self, line: str) -> "SyscallEvent | None":
        """
        Parse une ligne strace brute en SyscallEvent.

        Retourne None pour les lignes non parsables :
        - Lignes vides
        - Signaux strace ("--- SIGTERM {si_signo=...} ---")
        - Sorties de processus ("+++ exited with 0 +++")
        - Lignes incomplètes sans parenthèse ouvrante

        Après le parsing de base, appelle _match_pattern() pour enrichir
        l'event avec le pattern MITRE ATT&CK correspondant si trouvé.
        Le score final est : base_score + pattern_bonus, plafonné à 100.

        Parameters
        ----------
        line : str
            Ligne brute lue depuis tail_process.stdout.
            Déjà décodée en str (sans \\n final).

        Returns
        -------
        SyscallEvent | None
            Événement parsé, ou None si la ligne n'est pas un syscall valide.
        """
        # Format possibles
        # direct dans console, si pid
        # [pid 221369] 00:12:50.294856 rt_sigprocmask(SIG_BLOCK, [CHLD] <unfinished ...>
        # sinon
        # 00:12:50.294362 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f491155aa10) = 221370 <0.000193>
        # dans fichier, -o
        # 221084 00:11:29.958380 execve("/usr/bin/echo", ["echo", "test"], 0x7ffe6da10fd0 /* 80 vars */) = 0 <0.000600>
        line: str = line.strip()
        if not line or self._should_ignore(line):
            return None

        # Extraction du pid si présent ou timestamp
        pid = None
        start_by_pid = False
        timestamp_str_or_pid, line = line.split(" ", 1)
        line = line.strip()
        timestamp_str_or_pid = timestamp_str_or_pid.strip()
        if timestamp_str_or_pid.startswith("[pid"):   # cas dans console avec pid
            start_by_pid = True
            timestamp_str_or_pid = timestamp_str_or_pid.removeprefix("[pid").strip()
            if timestamp_str_or_pid:  # donc pid coller a pid, genre [pid123]
                    timestamp_str_or_pid = timestamp_str_or_pid[:-1]
            else:
                timestamp_str_or_pid, line = line.split(" ", 1)
                timestamp_str_or_pid = timestamp_str_or_pid.strip()[:-1]
                line = line.strip()
                try:
                    pid = int(timestamp_str_or_pid.strip())
                except ValueError:
                    pid = None

        elif timestamp_str_or_pid.isdigit():   # cas fichier, pid au début
            start_by_pid = True
            try:
                pid = int(timestamp_str_or_pid.strip())
            except ValueError:
                pid = None

        else:  # cas normal, pas pid, donc timestamp
            timestamp_str = timestamp_str_or_pid

        if start_by_pid:
            timestamp_str, line = line.split(" ", 1)
            timestamp_str = timestamp_str.strip()
            line = line.strip()

        # Extraction du syscall
        syscall, line = line.split("(", 1)
        syscall = syscall.strip()
        line = line.strip()

        # Extraction du args du syscall, de la valeur de retour et de la durée
        if not "=" in line:
            duration = None
            retval = None
            args_raw = line.rsplit(")", 1)[0].strip()
        else:
            pre_args, line = line.rsplit("=", 1)
            line = line.strip()
            pre_args = pre_args.strip() + "  "

            args_raw, _ = pre_args.rsplit(")", 1)
            args_raw = args_raw.strip()

            # Extraction de la valeur de retour et de la durée
            retval, line = line.split(" ", 1)
            try:
                retval = int(retval.strip(), self._detect_base(retval.strip())[0])
            except ValueError:
                retval = None

            duration = line.split("<", 1)[-1][:-1].strip()
            try:
                duration = float(duration)
            except ValueError:
                duration = None

        family, threat_score = self._score(syscall)
        is_error = retval is not None and retval < 0
        return SyscallEvent(
            timestamp_date=datetime.utcnow(),
            timestamp_str=timestamp_str,
            pid=pid,
            syscall=syscall,
            args_raw=args_raw,
            retval=retval,
            duration=duration,
            family=family,
            threat_score=threat_score,
            is_error=is_error,
        )


# =============================================================================
# SYSCALL TRACER
# =============================================================================

class SyscallTracer:
    """
    Lit la sortie strace ligne par ligne et envoie des SyscallEvent dans la queue.
    """

    def __init__(
        self,
        tail_process: "asyncio.subprocess.Process",
        event_queue: SandBoxQueue,
        parser: SyscallParser | None = None,
        parser_kwargs: dict | None = None,
    ):
        self.tail_process = tail_process
        self.event_queue = event_queue
        if parser and isinstance(parser, SyscallParser):
            self.parser = parser
        else:
            try:
                self.parser = SyscallParser(**(parser_kwargs or {}))
            except Exception as e:
                raise ValueError(f"Erreur lors de la création du parser: {str(e)}") from e
                
        self._running = False
        self._total_lines = 0
        self._total_events = 0

    async def start(self) -> None:
        """Boucle principale de lecture de la sortie strace."""
        self._running = True
        logger.print("🔬 SyscallTracer démarré — lecture strace en cours...")

        try:
            async for raw_line in self.tail_process.stdout:
                if not self._running:
                    break

                self._total_lines += 1
                line = raw_line.decode("utf-8", errors="ignore")

                try:
                    event = self.parser.parse(line)
                    # print("[sycall_tracer]", event, "\n\n")
                    if event is not None:
                        self.event_queue.put(event)
                        self._total_events += 1

                        if event.threat_score >= 20:
                            logger.print(
                                f"⚡ syscall [{event.family}] {event.syscall}"
                                f"({event.args_raw[:60]})"
                                f" = {event.retval} | score +{event.threat_score}"
                            )

                except Exception:
                    pass

        except Exception as e:
            logger.print(f"❌ SyscallTracer erreur fatale: {e}")

        finally:
            self._running = False
            logger.print(
                f"🛑 SyscallTracer arrêté | "
                f"lignes lues: {self._total_lines} | "
                f"events produits: {self._total_events}"
            )

    async def stop(self) -> None:
        """Signale l'arrêt de la boucle."""
        self._running = False
        logger.print("🛑 SyscallTracer: arrêt demandé")
        if self.tail_process:
            await kill_process(self.tail_process, "tail")

    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict:
        rate = self._total_events / self._total_lines if self._total_lines > 0 else 0.0
        return {
            "total_lines": self._total_lines,
            "total_events": self._total_events,
            "parse_rate": round(rate, 3),
            "running": self._running,
        }


# =============================================================================
# TESTS
# =============================================================================

if __name__ == "__main__":
    parser = SyscallParser()
    passed = 0
    total_tests = 13

    print("\n" + "=" * 70)
    print("🧪 EXÉCUTION DES TESTS UNITAIRES - SyscallParser.parse()")
    print("=" * 70 + "\n")

    # TEST 1 : Syscall normal sans PID
    line1 = '20:33:12.729187 execve("/usr/bin/ls", ["ls"], 0x7fff /* 80 vars */) = 0 <0.000539>'
    event1 = parser.parse(line1)
    assert event1 is not None, "TEST 1 ❌ Event is None"
    assert event1.timestamp_str == "20:33:12.729187"
    assert event1.pid is None
    assert event1.syscall == "execve"
    assert event1.retval == 0
    assert event1.duration == 0.000539
    assert event1.family == "process"
    assert event1.threat_score == 25
    assert event1.is_error is False
    passed += 1
    print("✅ TEST 1 PASSÉ - Syscall normal sans PID")

    # TEST 2 : Format fichier -o
    line2 = '222846 20:33:12.730254 openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3 <0.000028>'
    event2 = parser.parse(line2)
    assert event2 is not None, "TEST 2 ❌ Event is None"
    assert event2.pid == 222846
    assert event2.timestamp_str == "20:33:12.730254"
    assert event2.syscall == "openat"
    assert event2.family == "file"
    assert event2.threat_score == 10
    passed += 1
    print("✅ TEST 2 PASSÉ - Format fichier -o")

    # TEST 3 : Retval négatif
    line3 = '20:33:12.730254 access("/etc/ld.so.preload", R_OK) = -1 ENOENT <0.000025>'
    event3 = parser.parse(line3)
    assert event3 is not None
    assert event3.retval == -1
    assert event3.is_error is True
    passed += 1
    print("✅ TEST 3 PASSÉ - Retval négatif")

    # TEST 4 : +++ exited ignorée
    line4 = '20:33:27.448120 +++ exited with 0 +++'
    assert parser.parse(line4) is None
    passed += 1
    print("✅ TEST 4 PASSÉ - Ignorer +++")

    # TEST 5 : --- SIGTERM ignorée
    line5 = '20:33:27.448120 --- SIGTERM ---'
    assert parser.parse(line5) is None
    passed += 1
    print("✅ TEST 5 PASSÉ - Ignorer ---")

    # TEST 6 : <unfinished ignorée
    line6 = '20:33:12.730254 <unfinished ...>'
    assert parser.parse(line6) is None
    passed += 1
    print("✅ TEST 6 PASSÉ - Ignorer <unfinished>")

    # TEST 7 : resumed> ignorée
    line7 = '20:33:12.730254 <... read resumed> "data", 4) = 4 <0.000015>'
    assert parser.parse(line7) is None
    passed += 1
    print("✅ TEST 7 PASSÉ - Ignorer resumed>")

    # TEST 8 : = ? ignorée
    line8 = '20:33:27.447972 exit_group(0) = ?'
    assert parser.parse(line8) is None
    passed += 1
    print("✅ TEST 8 PASSÉ - Ignorer = ?")

    # TEST 9 : Ligne vide
    assert parser.parse("") is None
    passed += 1
    print("✅ TEST 9 PASSÉ - Ignorer ligne vide")

    # TEST 10 : Args avec parenthèses imbriquées
    line10 = '20:33:12.730254 write(1, "data(test)", 10) = 10 <0.000015>'
    event10 = parser.parse(line10)
    assert event10 is not None
    assert event10.syscall == "write"
    assert '1, "data(test)", 10' in event10.args_raw
    assert event10.retval == 10
    passed += 1
    print("✅ TEST 10 PASSÉ - Args avec parenthèses imbriquées")

    # TEST 11 : ptrace avec bonus
    line11 = '20:33:12.730254 ptrace(PTRACE_ATTACH, 1234, NULL, 0) = 0 <0.000100>'
    event11 = parser.parse(line11)
    assert event11 is not None
    assert event11.syscall == "ptrace"
    assert event11.family == "process"
    assert event11.threat_score == 50
    passed += 1
    print("✅ TEST 11 PASSÉ - ptrace score 50")

    # TEST 12 : mmap avec retval hex
    line12 = '20:33:12.730254 mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f1234567000 <0.000012>'
    event12 = parser.parse(line12)
    assert event12 is not None
    assert event12.syscall == "mmap"
    assert event12.threat_score == 5
    assert event12.retval == 0x7f1234567000
    passed += 1
    print("✅ TEST 12 PASSÉ - mmap avec retval hex")

    # TEST 13 : Syscall inconnu
    line13 = '20:33:12.730254 brk(NULL) = 0x55555555a000 <0.000008>'
    event13 = parser.parse(line13)
    assert event13 is not None
    assert event13.syscall == "brk"
    assert event13.family == "unknown"
    assert event13.threat_score == 0
    passed += 1
    print("✅ TEST 13 PASSÉ - Syscall inconnu")

    print("\n" + "=" * 70)
    print(f"📊 RÉSUMÉ : {passed}/{total_tests} tests passés")
    if passed == total_tests:
        print("🎉 TOUS LES TESTS ONT RÉUSSI !")
    print("=" * 70)