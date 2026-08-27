#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 25 08:13:02 2026

@author: hounsousamuel
"""

"""
test_job_manager.py

Tests fonctionnels de JobManager, avec des `assert` bruts (pas de framework),
dans l'esprit du bloc de démo/test déjà présent dans job_to_dict.py.

Point important : AsyncIOScheduler.start() exige d'être appelé depuis une
event loop asyncio déjà en cours d'exécution (RuntimeError sinon). Tous les
tests qui ont besoin de next_run_time correctement calculé (pause/resume,
modify_job sur le trigger...) tournent donc dans une coroutine, avec le
scheduler démarré via manager.start(paused=False) avant toute opération.

Chaque fonction test_* est indépendante : elle crée son propre JobManager
sur une DB SQLite temporaire, fait ses vérifications, puis nettoie.

Lancement : python3 test_job_manager.py
"""

import asyncio
import os
import tempfile

from obsidian_hive.core.managers.job_manager import JobManager, TriggerKind
from obsidian_hive.core.managers._test_funcs import noop, async_noop

def _make_manager(start: bool = True) -> tuple[JobManager, str]:
    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    # path = "/home/hounsousamuel/PROJET/obsidian_hive/api/shieldai.db"
    manager = JobManager(db_url=f"sqlite+aiosqlite:///{path}")
    if start:
        manager.start(paused=False)
    return manager, path


def _cleanup(manager: JobManager, path: str):
    manager.stop(wait=False)
    if os.path.exists(path):
        os.remove(path)


async def test_db_url_strips_async_driver():
    manager, path = _make_manager()
    try:
        assert "+aiosqlite" not in manager.db_url
        assert manager.db_url.startswith("sqlite:///")
    finally:
        _cleanup(manager, path)
    print("[OK] test_db_url_strips_async_driver")


async def test_add_and_get_job():
    manager, path = _make_manager()
    try:
        job = manager.add_job(
            func=noop, job_id="job-1", name="Job de test",
            trigger={"type": "cron", "hour": 3},
        )
        assert job.id == "job-1"
        assert manager.job_exists("job-1") is True
        assert manager.job_exists("job-inexistant") is False

        fetched = manager.get_job("job-1")
        assert fetched is not None
        assert fetched.name == "Job de test"
        assert "job-1" in manager.list_jobs_id()
    finally:
        _cleanup(manager, path)
    print("[OK] test_add_and_get_job")


async def test_add_job_picks_correct_executor():
    manager, path = _make_manager()
    try:
        async_job = manager.add_job(
            func=async_noop, job_id="job-async", name="Async",
            trigger={"type": "interval", "minutes": 5},
        )
        sync_job = manager.add_job(
            func=noop, job_id="job-sync", name="Sync",
            trigger={"type": "interval", "minutes": 5},
        )
        assert async_job.executor == manager._async_executor_name
        assert sync_job.executor == manager._threadpool_executor_name
    finally:
        _cleanup(manager, path)
    print("[OK] test_add_job_picks_correct_executor")


async def test_in_memory_job_isolation():
    manager, path = _make_manager()
    try:
        manager.add_job(
            func=noop, job_id="job-mem", name="En mémoire",
            trigger={"type": "interval", "minutes": 1}, in_memory=True,
        )
        manager.add_job(
            func=noop, job_id="job-persist", name="Persistant",
            trigger={"type": "interval", "minutes": 1}, in_memory=False,
        )

        mem_ids = manager.list_jobs_id(in_memory=True)
        assert "job-mem" in mem_ids
        assert "job-persist" not in mem_ids

        persist_ids = manager.list_jobs_id(in_memory=False)
        assert "job-persist" in persist_ids
        assert "job-mem" not in persist_ids

        all_ids = manager.list_jobs_id()
        assert "job-mem" in all_ids
        assert "job-persist" in all_ids
    finally:
        _cleanup(manager, path)
    print("[OK] test_in_memory_job_isolation")


async def test_pause_and_resume_job():
    manager, path = _make_manager()
    try:
        manager.add_job(
            func=noop, job_id="job-pause", name="Pausable",
            trigger={"type": "interval", "minutes": 1},
        )

        assert manager.is_job_paused("job-pause") is False
        assert manager.get_job_state("job-pause") in ("running", "pending")

        result = manager.pause_job("job-pause")
        assert result["success"] is True
        assert manager.is_job_paused("job-pause") is True
        assert manager.get_job_state("job-pause") == "paused"

        result = manager.resume_job("job-pause")
        assert result["success"] is True
        assert manager.is_job_paused("job-pause") is False
    finally:
        _cleanup(manager, path)
    print("[OK] test_pause_and_resume_job")


async def test_is_job_paused_false_positive_before_scheduler_start():
    """
    Piège d'usage réel (pas un bug à corriger dans l'immédiat) : si un job
    est ajouté AVANT que le scheduler soit démarré, next_run_time n'est pas
    juste None mais carrément absent de l'objet Job -> is_job_paused()
    (qui teste `getattr(job, "next_run_time", None) is None`) le confond
    avec un job explicitement mis en pause. Toujours démarrer le scheduler
    AVANT d'ajouter des jobs si tu veux interroger cet état juste après.
    """
    manager, path = _make_manager(start=False)  # scheduler PAS démarré
    try:
        manager.add_job(
            func=noop, job_id="job-pending", name="Job ajouté avant start()",
            trigger={"type": "interval", "minutes": 1},
        )
        assert manager.is_job_paused("job-pending") is True  # faux positif documenté
    finally:
        _cleanup(manager, path)
    print("[OK] test_is_job_paused_false_positive_before_scheduler_start (comportement documenté)")


async def test_pause_unknown_job_fails_gracefully():
    manager, path = _make_manager()
    try:
        result = manager.pause_job("job-inexistant")
        assert result["success"] is False
        assert result["error"] is not None
    finally:
        _cleanup(manager, path)
    print("[OK] test_pause_unknown_job_fails_gracefully")


async def test_remove_job_and_remove_all_jobs():
    manager, path = _make_manager()
    try:
        for i in range(3):
            manager.add_job(
                func=noop, job_id=f"job-{i}", name=f"Job {i}",
                trigger={"type": "interval", "minutes": 1},
            )
        assert len(manager.list_jobs_id()) == 3

        result = manager.remove_job("job-0")
        assert result["success"] is True
        assert manager.job_exists("job-0") is False
        assert len(manager.list_jobs_id()) == 2

        result = manager.remove_all_jobs()
        assert result["success"] is True
        assert manager.list_jobs_id() == []
    finally:
        _cleanup(manager, path)
    print("[OK] test_remove_job_and_remove_all_jobs")


async def test_pause_all_and_resume_all_jobs():
    manager, path = _make_manager()
    try:
        for i in range(3):
            manager.add_job(
                func=noop, job_id=f"job-{i}", name=f"Job {i}",
                trigger={"type": "interval", "minutes": 1},
            )

        result = manager.pause_all_jobs()
        assert result["success"] is True
        assert result["affected"] == 3
        for i in range(3):
            assert manager.is_job_paused(f"job-{i}") is True

        result = manager.resume_all_jobs()
        assert result["success"] is True
        assert result["affected"] == 3
        for i in range(3):
            assert manager.is_job_paused(f"job-{i}") is False
    finally:
        _cleanup(manager, path)
    print("[OK] test_pause_all_and_resume_all_jobs")


async def test_modify_job_trigger_recomputes_next_run_time():
    manager, path = _make_manager()
    try:
        manager.add_job(
            func=noop, job_id="job-modif", name="A modifier",
            trigger={"type": "cron", "hour": 3},
        )
        before = manager.get_job("job-modif").next_run_time

        result = manager.modify_job("job-modif", trigger={"type": "cron", "hour": 4})
        assert result["success"] is True

        after = manager.get_job("job-modif").next_run_time
        assert after != before
    finally:
        _cleanup(manager, path)
    print("[OK] test_modify_job_trigger_recomputes_next_run_time")


async def test_modify_job_preserves_pause_state():
    manager, path = _make_manager()
    try:
        manager.add_job(
            func=noop, job_id="job-modif-pause", name="A modifier en pause",
            trigger={"type": "cron", "hour": 3},
        )
        manager.pause_job("job-modif-pause")
        assert manager.is_job_paused("job-modif-pause") is True

        result = manager.modify_job("job-modif-pause", trigger={"type": "cron", "hour": 5})
        assert result["success"] is True
        assert manager.is_job_paused("job-modif-pause") is True
    finally:
        _cleanup(manager, path)
    print("[OK] test_modify_job_preserves_pause_state")


async def test_modify_job_rejects_invalid_attribute():
    manager, path = _make_manager()
    try:
        manager.add_job(
            func=noop, job_id="job-invalid-attr", name="Test",
            trigger={"type": "cron", "hour": 3},
        )
        result = manager.modify_job("job-invalid-attr", not_a_real_attr="oops")
        assert result["success"] is False
        assert "not_a_real_attr" in result["error"]
    finally:
        _cleanup(manager, path)
    print("[OK] test_modify_job_rejects_invalid_attribute")


async def test_modify_job_unknown_job_fails_gracefully():
    manager, path = _make_manager()
    try:
        result = manager.modify_job("job-inexistant", name="Nouveau nom")
        assert result["success"] is False
        assert "introuvable" in result["error"]
    finally:
        _cleanup(manager, path)
    print("[OK] test_modify_job_unknown_job_fails_gracefully")


async def test_build_trigger_validations():
    try:
        JobManager.build_trigger("cron")
        assert False, "aurait dû lever ValueError (cron vide)"
    except ValueError:
        pass

    try:
        JobManager.build_trigger("interval", weeks=0, days=0)
        assert False, "aurait dû lever ValueError (interval vide)"
    except ValueError:
        pass

    try:
        JobManager.build_trigger("date")
        assert False, "aurait dû lever ValueError (date sans run_date)"
    except ValueError:
        pass

    try:
        JobManager.build_trigger("cron", not_a_real_param=1)
        assert False, "aurait dû lever ValueError (paramètre inconnu)"
    except ValueError:
        pass

    try:
        JobManager.build_trigger("not_a_real_type")
        assert False, "aurait dû lever ValueError (type invalide)"
    except ValueError:
        pass

    from apscheduler.triggers.date import DateTrigger
    from apscheduler.triggers.cron import CronTrigger
    trig = JobManager.build_trigger("once", run_date="2026-08-01 12:00:00")
    assert isinstance(trig, DateTrigger)

    trig = JobManager.build_trigger(TriggerKind.CRON, hour=9)
    assert isinstance(trig, CronTrigger)

    print("[OK] test_build_trigger_validations")


async def test_add_job_with_trigger_instance():
    from apscheduler.triggers.interval import IntervalTrigger

    manager, path = _make_manager()
    try:
        job = manager.add_job(
            func=noop, job_id="job-trigger-instance", name="Trigger direct",
            trigger=IntervalTrigger(minutes=10),
        )
        assert job.id == "job-trigger-instance"
    finally:
        _cleanup(manager, path)
    print("[OK] test_add_job_with_trigger_instance")


async def test_start_and_stop_scheduler():
    """
    Note : AsyncIOScheduler.shutdown() diffère l'effet réel (changement
    d'état interne) via un call_soon() sur l'event loop, plutôt que de
    l'appliquer de façon synchrone comme BaseScheduler. Concrètement :
    si stop() est appelé deux fois de suite SANS laisser l'event loop
    respirer entre les deux (pas d'await entre les deux appels), le
    try/except SchedulerNotRunningError de JobManager.stop() ne peut pas
    intercepter l'erreur -> elle remonte plus tard comme exception non
    gérée dans une callback asyncio (visible dans les logs, pas bloquant,
    mais indésirable). D'où le petit `await asyncio.sleep(0)` ci-dessous,
    qui laisse le call_soon() du premier stop() s'exécuter avant le second.
    """
    manager, path = _make_manager(start=False)
    try:
        result = manager.start(paused=True)
        assert result["state"] == "running"

        result = manager.start(paused=True)
        assert result["state"] == "already_running"

        result = manager.stop(wait=False)
        assert result["state"] == "stopped"

        await asyncio.sleep(0)  # laisse le call_soon du 1er stop() s'exécuter

    finally:
        if os.path.exists(path):
            os.remove(path)
    print("[OK] test_start_and_stop_scheduler")


async def main():
    tests = [
        test_db_url_strips_async_driver,
        test_add_and_get_job,
        test_add_job_picks_correct_executor,
        test_in_memory_job_isolation,
        test_pause_and_resume_job,
        test_is_job_paused_false_positive_before_scheduler_start,
        test_pause_unknown_job_fails_gracefully,
        test_remove_job_and_remove_all_jobs,
        test_pause_all_and_resume_all_jobs,
        test_modify_job_trigger_recomputes_next_run_time,
        test_modify_job_preserves_pause_state,
        test_modify_job_rejects_invalid_attribute,
        test_modify_job_unknown_job_fails_gracefully,
        test_build_trigger_validations,
        test_add_job_with_trigger_instance,
        test_start_and_stop_scheduler,
    ]
    for t in tests:
        await t()
    print(f"\n{len(tests)}/{len(tests)} tests passés ✅")


if __name__ == "__main__":
    asyncio.run(main())