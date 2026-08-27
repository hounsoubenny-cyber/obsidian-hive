#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May 28 21:31:06 2026

@author: hounsousamuel

Module de scoring comportemental pour le Sandbox ShieldAI V2.
Analyse les événements (syscalls + fichiers) en temps réel,
détecte les patterns d'attaque et calcule un score de menace.

Centralise toutes les logiques de détection :
- Patterns contextuels (analyse des arguments des syscalls)
- Patterns de séquences temporelles
- Patterns de sets (ordre non important)
- Scoring avec pondération temporelle
"""

import os
import sys
import math
import time
from typing import Any
from dataclasses import dataclass
from datetime import datetime
from collections import deque

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from sandbox_ia.tracers.fs_monitor import FSEvent
from sandbox_ia.tracers.syscall_tracer import SyscallEvent
from sandbox_ia.sandbox_utils.logger import get_logger
from sandbox_ia.configs.behavior_scorer_config import (
    THREAT_LEVELS, SEQUENCE_PATTERNS, SEQUENCE_TIMEOUT,
    SEQUENCE_WINDOW_SIZE, SET_PATTERNS, TIME_DECAY_HALF_LIFE,
    CONTEXT_PATTERNS, ALERT_THRESHOLD, DECAY_AMOUNT,
    DECAY_INTERVAL, PATTERN_MULTIPLIER
)
logger = get_logger()


# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

def get_threat_level(score: int) -> str:
    """Retourne le niveau de menace correspondant au score."""
    for level, (low, high) in THREAT_LEVELS.items():
        if low <= score <= high:
            return level
    return "CRITICAL"


def compute_time_weight(age_seconds: float, half_life: float = TIME_DECAY_HALF_LIFE) -> float:
    """Calcule le poids temporel d'un event selon son âge (décroissance exponentielle)."""
    return math.pow(2, -age_seconds / half_life)


def match_context_pattern(syscall: str, args_raw: str) -> tuple[str | None, int, str | None, str | None]:
    """
    Cherche un pattern contextuel MITRE ATT&CK pour ce syscall.

    Returns:
        tuple: (nom_pattern, score_bonus, mitre, description)
    """
    for pattern_name, pattern in CONTEXT_PATTERNS.items():
        if pattern["syscall"] != syscall:
            continue

        if pattern.get("args_contains") and pattern["args_contains"] not in args_raw:
            continue

        if pattern.get("args_contains_any") and not any(k in args_raw for k in pattern["args_contains_any"]):
            continue

        if pattern.get("flags_contains") and pattern["flags_contains"] not in args_raw:
            continue

        return (
            pattern_name,
            pattern["score"],
            pattern.get("mitre"),
            pattern.get("description"),
        )

    return None, 0, None, None


# =============================================================================
# THREAT REPORT
# =============================================================================

@dataclass
class ThreatReport:
    """Rapport d'alerte généré par le BehaviorScorer."""
    timestamp: datetime
    threat_score: int
    threat_level: str
    trigger_event: Any
    pattern_detected: str | None
    canary_triggered: bool
    session_duration: float
    mitre: str | None = None
    description: str | None = None

    def to_dict(self, max_output_length: int = 200) -> dict:
        """Convertit le rapport d'alerte en dictionnaire."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "threat_score": self.threat_score,
            "threat_level": self.threat_level,
            "trigger_event": str(self.trigger_event)[:max_output_length],
            "pattern_detected": self.pattern_detected,
            "canary_triggered": self.canary_triggered,
            "session_duration": round(self.session_duration, 3),
            "mitre": self.mitre,
            "description": self.description,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ThreatReport":
        """Reconstruit un ThreatReport depuis un dictionnaire."""
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            threat_score=data["threat_score"],
            threat_level=data["threat_level"],
            trigger_event=data["trigger_event"],
            pattern_detected=data["pattern_detected"],
            canary_triggered=data["canary_triggered"],
            session_duration=data["session_duration"],
            mitre=data.get("mitre"),
            description=data.get("description"),
        )
    
# =============================================================================
# BEHAVIOR SCORER
# =============================================================================

class BehaviorScorer:
    """
    Moteur de scoring comportemental.

    Centralise toutes les logiques de détection :
    - Patterns contextuels (analyse args_raw)
    - Patterns de séquences (ordre temporel)
    - Patterns de sets (ordre non important)
    - Scoring avec pondération temporelle
    """

    def __init__(
        self,
        alert_threshold: int | float | None = ALERT_THRESHOLD,
        decay_interval: int | float | None = DECAY_INTERVAL,
        decay_amount: int | float | None = DECAY_AMOUNT,
    ):
        self.threat_score = 0
        self.threat_level = "LOW"
        self.session_start_time = time.time()
        self.alerts: list[ThreatReport] = []
        self._last_pattern = None
        self.alert_threshold = alert_threshold if alert_threshold is not None else ALERT_THRESHOLD
        self.decay_interval = decay_interval if decay_interval is not None else DECAY_INTERVAL
        self.decay_amount = decay_amount if decay_amount is not None else DECAY_AMOUNT

        # Pour les patterns de sets
        self._seen_syscalls: set[str] = set()

        # Pour les séquences temporelles
        self._event_history: deque = deque(maxlen=SEQUENCE_WINDOW_SIZE)
        self._last_event: Any = None

        # Pour le scoring pondéré
        self._scored_events: list[tuple[float, int]] = []

    def _update_weighted_score(self) -> None:
        """Recalcule le score global avec pondération temporelle."""
        now = time.time()
        # Nettoyer les events trop vieux (> 30s)
        cutoff = now - 30.0
        self._scored_events = [(ts, s) for ts, s in self._scored_events if ts > cutoff]

        total_score = 0.0
        for ts, raw_score in self._scored_events:
            age = now - ts
            weight = compute_time_weight(age)
            total_score += raw_score * weight

        self.threat_score = min(int(total_score), 100)
        self.threat_level = get_threat_level(self.threat_score)

    def _detect_sequence_pattern(self) -> tuple[str | None, int | None, str | None, str | None]:
        """Détecte les patterns de séquences temporelles."""
        if len(self._event_history) < 2:
            return None, None, None, None

        for pattern_name, pattern in SEQUENCE_PATTERNS.items():
            required = pattern["sequence"]
            if len(self._event_history) < len(required):
                continue

            recent = list(self._event_history)[-len(required):]
            if recent == required:
                return (
                    pattern_name,
                    pattern["score"],
                    pattern.get("mitre"),
                    pattern.get("description"),
                )

        return None, None, None, None

    def _detect_set_pattern(self) -> tuple[str | None, int | None, str | None, str | None]:
        """Détecte les patterns basés sur des sets de syscalls."""
        for pattern_name, pattern in SET_PATTERNS.items():
            if pattern["syscalls"].issubset(self._seen_syscalls):
                return (
                    pattern_name,
                    pattern["score"],
                    pattern.get("mitre"),
                    pattern.get("description"),
                )
        return None, None, None, None

    def _check_alert(
        self, event: Any,
        pattern: str | None,
        canary_triggered: bool, 
        mitre: str | None = None,
        description: str | None = None
    ) -> None:
        """Crée un ThreatReport si le seuil d'alerte est dépassé."""
        if self.threat_score >= self.alert_threshold or canary_triggered:
            report = ThreatReport(
                timestamp=datetime.utcnow(),
                threat_score=self.threat_score,
                threat_level=self.threat_level,
                trigger_event=event,
                pattern_detected=pattern,
                canary_triggered=canary_triggered,
                session_duration=time.time() - self.session_start_time,
                mitre=mitre,
                description=description,
            )
            self.alerts.append(report)

            alert_msg = f"🚨 ALERTE [{self.threat_level}] score={self.threat_score}"
            if pattern:
                alert_msg += f" pattern={pattern}"
            if mitre:
                alert_msg += f" [{mitre}]"
            if canary_triggered:
                alert_msg += " 🍯 CANARY"
            logger.print(alert_msg)
    
    def _append_to_event_history(self, event:Any) -> None:
        if not isinstance(event, (SyscallEvent, FSEvent)):
            return
        
        sycall = event.syscall if isinstance(event, SyscallEvent) \
            else f"fs_{event.event_type}"
            
        if self._last_event is None:
            self._event_history.append(sycall)
            self._last_event = (time.time(), event)
            return
        
        ts, _ = self._last_event
        if time.time() - ts > SEQUENCE_TIMEOUT:
            self._event_history.clear()
            self._event_history.append(sycall)
            self._last_event = (time.time(), event)
            return
        
        self._event_history.append(sycall)
        self._last_event = (time.time(), event)
        
    def decay(self) -> None:
        """Réduit le score au fil du temps."""
        if self.threat_score > 0:
            self._update_weighted_score()
            if self.threat_score > 0:
                self.threat_score = max(self.threat_score - self.decay_amount, 0)
                self.threat_level = get_threat_level(self.threat_score)
                logger.print(f"⏱️ Decay | score={self.threat_score} | level={self.threat_level}")

    def process(
        self, event: FSEvent | SyscallEvent,
        score_function: callable = None,
        kwargs: dict = None,
    ) -> None:
        """Traite un événement et met à jour le score de menace."""
        # Ajouter à l'historique pour les séquences
        self._append_to_event_history(event)

        # Extraire le score brut
        raw_score = 0
        canary_triggered = False
        context_pattern = None
        mitre = None
        description = None

        if isinstance(event, SyscallEvent):
            raw_score = event.threat_score
            self._seen_syscalls.add(event.syscall)

            # Patterns contextuels
            ctx_pattern, ctx_score, ctx_mitre, ctx_desc = match_context_pattern(
                event.syscall, event.args_raw
            )
            if ctx_pattern:
                context_pattern = ctx_pattern
                raw_score = max(raw_score, ctx_score)
                mitre = ctx_mitre
                description = ctx_desc
                logger.print(f"🎯 Pattern contextuel: {ctx_pattern} [{ctx_mitre}] +{ctx_score}")

        elif isinstance(event, FSEvent):
            raw_score = event.threat_score
            if event.is_canary:
                canary_triggered = True

        # Ajouter au scoring pondéré
        self._scored_events.append((time.time(), raw_score))
        self._update_weighted_score()

        # Détection des séquences
        seq_pattern, seq_score, seq_mitre, seq_desc = self._detect_sequence_pattern()
        if seq_pattern and seq_score:
            context_pattern = seq_pattern
            mitre = seq_mitre or mitre
            description = seq_desc or description
            self.threat_score = min(self.threat_score + seq_score, 100)
            if score_function:
                # Le score bumped ci-dessus est passé en threat_score_manual à la fusion ML,
                # score_result est un score ABSOLU (pas un delta) → on remplace, pas on additionne
                score_result = score_function(event, **(kwargs or {}))
                self.threat_score = min(int(score_result), 100)
            logger.print(f"🎯 Séquence: {seq_pattern} [{seq_mitre}] +{seq_score}")

        # Détection des sets
        set_pattern, set_score, set_mitre, set_desc = self._detect_set_pattern()
        if set_pattern and set_score:
            context_pattern = set_pattern
            mitre = set_mitre or mitre
            description = set_desc or description
            self.threat_score = min(self.threat_score + set_score, 100)
            logger.print(f"🎯 Set pattern: {set_pattern} [{set_mitre}] +{set_score}")
        
        self._last_pattern = context_pattern
        # Mise à jour finale et alerte
        self.threat_level = get_threat_level(self.threat_score)
        self._check_alert(event, context_pattern, canary_triggered, mitre, description)

    def reset(self) -> None:
        """Réinitialise le scorer pour une nouvelle session."""
        self.threat_score = 0
        self.threat_level = "LOW"
        self.session_start_time = time.time()
        self.alerts.clear()
        self._seen_syscalls.clear()
        self._event_history.clear()
        self._scored_events.clear()
        self._last_pattern = None


# =============================================================================
# TESTS
# =============================================================================

if __name__ == "__main__":
    scorer = BehaviorScorer()

    class MockSyscall:
        def __init__(self, name, args, score=0):
            self.syscall = name
            self.args_raw = args
            self.threat_score = score
            self.event_type = ""

    # Test pattern contextuel
    print("\n🧪 Test pattern contextuel - shadow_read")
    event = MockSyscall("openat", 'AT_FDCWD, "/etc/shadow", O_RDONLY', 10)
    scorer.process(event)
    print(f"Score: {scorer.threat_score}")

    # Test reset
    scorer.reset()
    print(f"\n🧪 Reset - Score: {scorer.threat_score}")

    # Test séquence
    print("\n🧪 Test séquence - reverse_shell")
    events = [
        MockSyscall("socket", "", 5),
        MockSyscall("connect", "", 10),
        MockSyscall("dup2", "", 5),
        MockSyscall("execve", "", 15),
    ]
    for e in events:
        scorer.process(e)
    print(f"Score final: {scorer.threat_score}")
    print(f"Alertes: {len(scorer.alerts)}")