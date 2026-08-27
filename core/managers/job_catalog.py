#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 25 15:08:35 2026

@author: hounsousamuel
"""

"""
job_catalog.py

Catalogue des jobs planifiables par Coralie via add_job_core_tool.

Pourquoi un catalogue et pas une fonction arbitraire passée par le LLM :
APScheduler sérialise les jobs persistants comme un chemin d'import
('module:fonction'), pas comme un objet pickled -- la fonction doit donc
être définie au niveau module et déjà connue AVANT l'appel. Un LLM ne peut
ni créer ni référencer une fonction Python qui n'existe pas déjà dans ton
code. Coralie ne choisit donc qu'un NOM dans ce catalogue ; toi seul
contrôles le mapping nom -> vraie fonction + trigger par défaut + kwargs.

Pour ajouter un job planifiable :
    1. Écrire la fonction (sync ou async), au niveau module, importable.
    2. L'enregistrer ci-dessous avec un JobSpec.
    3. Coralie peut immédiatement la planifier via add_job(job_name=...).
"""

from dataclasses import dataclass, field
from typing import Callable, Any, Literal

@dataclass(frozen=True)
class JobSpec:
    func: Callable
    description: str
    default_trigger: dict[str, Any]
    default_kwargs: dict[str, Any] = field(default_factory=dict)
    risk: Literal["low", "medium", "high"] = "low"  # réservé si un jour je veux moduler le risque par job


# --------------------------------------------------------------------------- #
# Placeholders -- à remplacer par les vraies fonctions au fur et à mesure.
# Chaque placeholder lève NotImplementedError pour ne jamais s'exécuter
# silencieusement à moitié si un job est planifié trop tôt.
# --------------------------------------------------------------------------- #


def _placeholder_report_cleanup(older_than_days: int = 90):
    """Purge des rapports obsolètes -- pas encore implémenté."""
    raise NotImplementedError("report_cleanup : fonction réelle pas encore branchée")


def _placeholder_coralie_daily_digest():
    """Résumé quotidien envoyé par Coralie -- pas encore implémenté."""
    raise NotImplementedError("coralie_daily_digest : fonction réelle pas encore branchée")


# --------------------------------------------------------------------------- #
# Le catalogue -- seule source de vérité sur ce que Coralie peut planifier.
# --------------------------------------------------------------------------- #

JOB_CATALOG: dict[str, JobSpec] = {
    "report_cleanup": JobSpec(
        func=_placeholder_report_cleanup,
        description="Purge des rapports de plus de 90 jours",
        default_trigger={"type": "cron", "hour": 4, "minute": 30},
        default_kwargs={"older_than_days": 90},
        risk="low",
    ),
    "coralie_daily_digest": JobSpec(
        func=_placeholder_coralie_daily_digest,
        description="Résumé quotidien de l'état du système envoyé par Coralie",
        default_trigger={"type": "cron", "hour": 8, "minute": 0},
        risk="low",
    ),
}

def describe_catalog() -> list[dict[str, Any]]:
    """Utilisé par list_job_catalog_core_tool pour donner à Coralie la liste
    des jobs disponibles sans les coder en dur dans son prompt système."""
    return [
        {
            "job_name": name,
            "description": spec.description,
            "default_trigger": spec.default_trigger,
            "default_kwargs": spec.default_kwargs,
        }
        for name, spec in JOB_CATALOG.items()
    ]