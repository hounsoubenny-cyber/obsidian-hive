#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jul 13 18:57:14 2026

@author: hounsousamuel
"""

import inspect
import json
from apscheduler.job import Job
from datetime import datetime
from typing import Any
import asyncio


def job_to_dict(job: Job) -> dict[str, Any]:
    """
    Convertit un objet Job APScheduler en dictionnaire JSON-sérialisable.
    """
    func = job.func
    
    return {
        "id": job.id,
        "name": getattr(job, "name", None),
        "func": _func_to_dict(func),
        "args": getattr(job, "args", None),
        "kwargs": getattr(job, "kwargs", None),
        "trigger": _trigger_to_dict(job.trigger),
        "executor": getattr(job, "executor", None),
        "misfire_grace_time":getattr(job, "misfire_grace_time", None),
        "coalesce": getattr(job, "coalesce", None),
        "max_instances": getattr(job, "max_instances", None),
        "next_run_time": job.next_run_time.isoformat() if getattr(job, "next_run_time", None) else None,
        "pending": getattr(job, "pending", None),
        "jobstore": getattr(job, "jobstore", None),
        "repr": str(job)
    }


def _func_to_dict(func: callable) -> dict[str, Any]:
    """
    Convertit une fonction/méthode en dictionnaire descriptif.
    """
    result = {
        "name": func.__name__,
        "module": func.__module__,
        "qualname": func.__qualname__,
        "type": _get_callable_type(func),
    }
    result["is_async"] = asyncio.iscoroutinefunction(func)
    
    if func.__doc__:
        result["doc"] = func.__doc__.strip().split("\n\n")[0]
    
    return result


def _get_callable_type(func: callable) -> str:
    """Détermine le type d'appelable."""
    if inspect.ismethod(func):
        return "method"
    elif inspect.isfunction(func):
        return "function"
    elif inspect.isclass(func):
        return "class"
    elif inspect.isbuiltin(func):
        return "builtin"
    elif isinstance(func, type(lambda: None)):
        return "lambda"
    else:
        return "unknown"


def _trigger_to_dict(trigger) -> dict[str, Any]:
    """Convertit un trigger en dictionnaire."""
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    from apscheduler.triggers.date import DateTrigger
    from apscheduler.triggers.calendarinterval import CalendarIntervalTrigger
    
    if isinstance(trigger, CronTrigger):
        return {
            "type": "cron",
            "fields": {
                "year": trigger.fields[0].__dict__ if trigger.fields else None,
                "month": trigger.fields[1].__dict__ if len(trigger.fields) > 1 else None,
                "day": trigger.fields[2].__dict__ if len(trigger.fields) > 2 else None,
                "week": trigger.fields[3].__dict__ if len(trigger.fields) > 3 else None,
                "day_of_week": trigger.fields[4].__dict__ if len(trigger.fields) > 4 else None,
                "hour": trigger.fields[5].__dict__ if len(trigger.fields) > 5 else None,
                "minute": trigger.fields[6].__dict__ if len(trigger.fields) > 6 else None,
                "second": trigger.fields[7].__dict__ if len(trigger.fields) > 7 else None,
            },
            "repr": str(trigger)
        }
    
    elif isinstance(trigger, IntervalTrigger):
        # IntervalTrigger ne stocke PAS weeks/days/hours/minutes/seconds
        # séparément (contrairement à CalendarIntervalTrigger) — seulement
        # un .interval (timedelta) et .interval_length (secondes, float).
        # On décompose nous-mêmes pour garder le même format de sortie.
        total_seconds = int(trigger.interval.total_seconds())
        weeks, remainder = divmod(total_seconds, 7 * 24 * 3600)
        days, remainder = divmod(remainder, 24 * 3600)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        return {
            "type": "interval",
            "interval": {
                "weeks": weeks,
                "days": days,
                "hours": hours,
                "minutes": minutes,
                "seconds": seconds,
            },
            "total_seconds": total_seconds,
            "start_date": trigger.start_date.isoformat() if trigger.start_date else None,
            "end_date": trigger.end_date.isoformat() if trigger.end_date else None,
            "repr": str(trigger)
        }
    
    elif isinstance(trigger, DateTrigger):
        return {
            "type": "date",
            "run_date": trigger.run_date.isoformat() if trigger.run_date else None,
            "repr": str(trigger)
        }
    
    elif isinstance(trigger, CalendarIntervalTrigger):
        return {
            "type": "calendar_interval",
            "interval": {
                "years": trigger.years,
                "months": trigger.months,
                "weeks": trigger.weeks,
                "days": trigger.days,
            },
            "start_date": trigger.start_date.isoformat() if trigger.start_date else None,
            "end_date": trigger.end_date.isoformat() if trigger.end_date else None,
            "repr": str(trigger)
        }
    
    else:
        return {"type": "unknown", "repr": str(trigger)}

if __name__ == "__main__":
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger

    # Exemple de fonction async
    async def coralie_report():
        """Génère le rapport quotidien de Coralie."""
        print("📊 Coralie — Rapport quotidien")
        await asyncio.sleep(1)

    # Exemple de fonction sync
    def cleanup():
        """Nettoyage des logs."""
        print("🧹 Nettoyage des logs")

    scheduler = BackgroundScheduler()

    # Ajouter quelques jobs
    scheduler.add_job(
        func=coralie_report,
        trigger=CronTrigger(hour=8, minute=0),
        id='coralie_daily',
        name='Rapport quotidien Coralie',
        max_instances=2,
    )

    scheduler.add_job(
        func=cleanup,
        trigger=CronTrigger(hour=2, minute=0),
        id='cleanup_logs',
        name='Nettoyage des logs',
        coalesce=True
    )

    print("=" * 60)
    print("📋 JOBS ENREGISTRÉS")
    print("=" * 60)

    for job in scheduler.get_jobs():
        print(f"\n🔹 Job: {job.id}")
        data = job_to_dict(job)
        print(data)
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        print("-" * 40)

    # Tester la sérialisation JSON
    print("\n" + "=" * 60)
    print("🧪 TEST SÉRIALISATION JSON")
    print("=" * 60)

    job = scheduler.get_job('coralie_daily')
    data = job_to_dict(job)
    json_str = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    print(json_str)

    # Vérifier que le JSON est valide
    try:
        parsed = json.loads(json_str)
        print("\n✅ JSON valide")
    except json.JSONDecodeError as e:
        print(f"\n❌ Erreur JSON: {e}")
