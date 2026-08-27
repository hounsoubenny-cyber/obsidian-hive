#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 12 11:33:21 2026

@author: hounsousamuel
"""

import re
import json
import asyncio
import functools
import traceback
import sqlalchemy
from uuid import uuid4
from enum import Enum
from datetime import datetime
from typing import Union, Callable, List, Tuple, Dict, Optional, Any
from apscheduler.job import Job
from apscheduler.jobstores.base import ConflictingIdError
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.executors.asyncio import AsyncIOExecutor
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.calendarinterval import CalendarIntervalTrigger
from apscheduler.schedulers import SchedulerAlreadyRunningError, SchedulerNotRunningError
from obsidian_hive.core.managers.job_to_dict import job_to_dict

TRIGGER_TYPES = Union[CronTrigger, DateTrigger, IntervalTrigger, CalendarIntervalTrigger]
_ASYNC_DRIVER_RE = re.compile(r"^(\w+)\+\w+://")


class TriggerKind(str, Enum):
    """
    Types de triggers supportés par JobManager.build_trigger().

    Hérite de str, donc utilisable indifféremment comme membre d'enum
    (TriggerKind.CRON) ou comme chaîne brute ("cron") — build_trigger()
    accepte les deux.
    """
    CRON = "cron"
    DATE = "date"
    INTERVAL = "interval"
    CALENDAR_INTERVAL = "calendarinterval"


def job_to_dict_wrapper(func):
    """Wrapper qui convertit les Job en dict JSON-sérialisable.
    
    Args:
        func (Callable): La fonction à wrapper.

    Returns:
        Callable: La fonction wrapper.
    """
    
    if asyncio.iscoroutinefunction(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            if not result:
                return result
            
            if isinstance(result, Job):
                return job_to_dict(result)
            
            if isinstance(result, list):
                return [
                    job_to_dict(job) if isinstance(job, Job) else job
                    for job in result
                ]
            return result
    
    else:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            if not result:
                return result
            
            if isinstance(result, Job):
                return job_to_dict(result)
            
            if isinstance(result, list):
                return [
                    job_to_dict(job) if isinstance(job, Job) else job
                    for job in result
                ]
            return result
    
    return wrapper


def job_id(name: str = None):
    """Génère un identifiant unique pour un job.

    Args:
        name (str, optional): Nom du job pour le préfixe. Par défaut "job".

    Returns:
        str: Un ID unique au format "{name}-job_ob-{uuid4}".
    """
    from uuid import uuid4
    job_id = str(uuid4())
    name = name or "job"
    return f"{name}-job_ob-{job_id}"


class JobManager:
    """Gestionnaire de jobs APScheduler avec persistance et mémoire.
    
    Fournit une interface unifiée pour la gestion des jobs planifiés,
    avec support de deux jobstores (persistant SQLite et mémoire),
    exécution asynchrone et synchronisée, et gestion des triggers.
    
    Attributes:
        db_url (str): URL de connexion à la base de données.
        scheduler (AsyncIOScheduler): L'instance du scheduler APScheduler.
        _stopping (bool): Flag indiquant si le scheduler est en cours d'arrêt.
    """
    
    def __init__(
        self,
        db_url: str,
    ):
        """Initialise le gestionnaire de jobs.

        Args:
            db_url (str): URL de connexion à la base de données pour la persistance.
                Ex: "sqlite+aiosqlite:///jobs.db"

        Raises:
            RuntimeError: Si db_url n'est pas fournie.
        """
        if not db_url:
            raise RuntimeError("DB url is required for JobManager")
        self.db_url = _ASYNC_DRIVER_RE.sub(r"\1://", db_url)
        self._jobstore_table_name = "obsidian_apscheduler_jobs"
        self._jobstore_memory = "memory"
        self._jobstore_default = "default"
        self._jobstores = {
            self._jobstore_memory: MemoryJobStore(),
            self._jobstore_default: SQLAlchemyJobStore(url=self.db_url, tablename=self._jobstore_table_name,)
        }
        self._async_executor_name = "default"
        self._threadpool_executor_name = "threadpool"
        self._executors = {
            self._async_executor_name: AsyncIOExecutor(),
            self._threadpool_executor_name: ThreadPoolExecutor()
        }
        
        self.scheduler: AsyncIOScheduler = AsyncIOScheduler(
            executors=self._executors,
            jobstores=self._jobstores,
        )
        self._stopping = False
    
    def start(self, paused: bool = False):
        """Démarre le scheduler.

        Args:
            paused (bool, optional): Si True, démarre en pause. Par défaut False.

        Returns:
            dict: État du scheduler ('running' ou 'already_running').
        """
        try:
            self.scheduler.start(paused=paused)
            return {
                "state": "running"
            }
        except SchedulerAlreadyRunningError:
            return {
                "state": "already_running"
            }
        
    def stop(self, wait: bool = True):
        """Arrête le scheduler.

        Args:
            wait (bool, optional): Si True, attend la fin des jobs en cours.
                Par défaut True.

        Returns:
            dict: État du scheduler ('stopped' ou 'not_running').
        """
        if self._stopping:
            return {
                "state": "stopped"
            }
        try:
            self._stopping = True
            self.scheduler.shutdown(wait=wait)
            return {
                "state": "stopped"
            }
        except SchedulerNotRunningError:
            return {
                "state": "not_running"
            }
    
    def _get_jobstore(self, in_memory: Optional[bool] = None):
        """Retourne le nom du jobstore en fonction du paramètre.

        Args:
            in_memory (Optional[bool], optional): Si True, retourne le jobstore mémoire.
                Si False, retourne le jobstore persistant. Si None, retourne None.

        Returns:
            str | None: Le nom du jobstore ou None.
        """
        jobstore = (
            None if in_memory is None
            else (self._jobstore_memory if in_memory else self._jobstore_default)
        )
        return jobstore
    
    def list_jobs(self, in_memory: Optional[bool] = None) -> List[Job]:
        """Liste tous les jobs.

        Args:
            in_memory (Optional[bool], optional): Si True, liste les jobs en mémoire.
                Si False, liste les jobs persistants. Si None, liste tous les jobs.
                Par défaut None.

        Returns:
            List[Job]: La liste des jobs.
        """
        return self.scheduler.get_jobs(jobstore=self._get_jobstore(in_memory))
    
    @job_to_dict_wrapper
    def list_jobs_wrapped(self, *args, **kwargs):
        """Liste tous les jobs avec conversion en dict JSON-sérialisable.

        Returns:
            list: La liste des jobs convertis en dict.
        """
        return self.list_jobs(*args, **kwargs)
    
    def list_jobs_id(self, in_memory: Optional[bool] = None) -> List[str]:
        """Liste les IDs de tous les jobs.

        Args:
            in_memory (Optional[bool], optional): Si True, liste les jobs en mémoire.
                Si False, liste les jobs persistants. Si None, liste tous les jobs.
                Par défaut None.

        Returns:
            List[str]: La liste des IDs des jobs.
        """
        jobs = self.list_jobs(in_memory=in_memory)
        return [job.id for job in jobs]
    
    def get_job(self, job_id: str, in_memory: Optional[bool] = None) -> Job | None:
        """Récupère un job par son ID.

        Args:
            job_id (str): L'ID du job.
            in_memory (Optional[bool], optional): Si True, cherche dans le jobstore mémoire.
                Si False, cherche dans le jobstore persistant. Si None, cherche dans les deux.
                Par défaut None.

        Returns:
            Job | None: Le job trouvé ou None.
        """
        return self.scheduler.get_job(job_id=job_id, jobstore=self._get_jobstore(in_memory))
    
    @job_to_dict_wrapper
    def get_job_wrapped(self, *args, **kwargs):
        """Récupère un job par son ID avec conversion en dict JSON-sérialisable.

        Returns:
            dict | None: Le job converti en dict ou None.
        """
        return self.get_job(*args, **kwargs)
    
    def _resolve_trigger(self, trigger: Union[TRIGGER_TYPES, Dict]) -> TRIGGER_TYPES:
        """
        Résout un trigger fourni tel quel (instance CronTrigger/DateTrigger/...)
        ou sous forme de dict {"type": "cron"/"date"/"interval"/"calendarinterval",
        ...params} en instance de trigger, via build_trigger().

        Utilisé par add_job() et modify_job() pour accepter les deux formats
        sans dupliquer la logique.

        Args:
            trigger: instance de trigger déjà construite, ou dict de spec.

        Returns:
            Instance de TRIGGER_TYPES.

        Raises:
            ValueError: dict sans clé 'type', ou valeur qui n'est ni un dict
                        ni une instance de trigger valide.
        """
        if isinstance(trigger, dict):
            trigger_spec = dict(trigger)
            trigger_kind = trigger_spec.pop('type', None)
            if trigger_kind is None:
                raise ValueError("Un trigger fourni en dict doit contenir la clé 'type'")
            return self.build_trigger(trigger_kind, **trigger_spec)

        if not isinstance(trigger, TRIGGER_TYPES):
            raise ValueError(
                f"trigger doit être un dict {{'type': ...}} ou une instance de "
                f"{TRIGGER_TYPES}, reçu {type(trigger).__name__}"
            )
        return trigger

    def add_job(
        self,
        func: Callable,
        job_id: str,
        name: str,
        trigger: Union[TRIGGER_TYPES, Dict],
        args: Optional[Union[List, Tuple]] = None,
        kwargs: Optional[Dict] = None,
        replace_existing: bool = False,
        in_memory: bool = False
    ) -> Job:
        """
        Ajoute un job au scheduler.

        Args:
            func (Callable): fonction (sync ou async) à exécuter.
            job_id (str): identifiant unique du job.
            name (str): nom lisible du job.
            trigger (Union[TRIGGER_TYPES, Dict]): instance de trigger (CronTrigger, DateTrigger, ...) OU
                dict {"type": "cron"/"date"/"interval"/"calendarinterval", ...params}
                — construit automatiquement via build_trigger() dans ce cas.
            args (Optional[Union[List, Tuple]], optional): arguments positionnels passés à func.
            kwargs (Optional[Dict], optional): arguments nommés passés à func.
            replace_existing (bool, optional): si True, remplace un job existant avec le même id.
                Par défaut False.
            in_memory (bool, optional): si True, stocke dans le jobstore mémoire (non persistant).
                Par défaut False.

        Returns:
            Job: L'instance Job créée.

        Example:
            >>> job_manager.add_job(
            ...     func=my_scan,
            ...     job_id="scan_daily",
            ...     name="Scan quotidien",
            ...     trigger={"type": "cron", "hour": 3},
            ... )
        """
        trigger = self._resolve_trigger(trigger)
        _kwargs = {
            "func": func,
            "name": name,
            "id": job_id,
            "trigger": trigger,
            "replace_existing": replace_existing,
            "jobstore": self._jobstore_memory if in_memory else self._jobstore_default,
            "executor": self._async_executor_name if asyncio.iscoroutinefunction(func) else self._threadpool_executor_name
        }
        if kwargs:
            _kwargs["kwargs"] = dict(kwargs)
        
        if args:
            _kwargs["args"] = tuple(args)
        
        try:            
            job = self.scheduler.add_job(**_kwargs)
        
        except (sqlalchemy.exc.IntegrityError, ConflictingIdError):
            _kwargs["id"] = f"{job_id}-{str(uuid4())}"
            job = self.scheduler.add_job(**_kwargs)
            
        return job
    
    @job_to_dict_wrapper
    def add_job_wrapped(self, *args, **kwargs):
        """Ajoute un job avec conversion en dict JSON-sérialisable.

        Returns:
            dict: Le job ajouté converti en dict.
        """
        return self.add_job(*args, **kwargs)
    
    def pause_job(self, job_id: str, in_memory: Optional[bool] = None) -> dict:
        """
        Met un job en pause.
        
        Args:
            job_id (str): ID du job à mettre en pause.
            in_memory (Optional[bool], optional): Si True, cherche dans le jobstore mémoire.
                Si False, cherche dans le jobstore persistant. Si None, cherche dans les deux.
                Par défaut None.
        
        Returns:
            dict: Résultat de l'opération avec success, error et traceback.
        """
        jobstore = self._get_jobstore(in_memory)
        
        try:
            self.scheduler.pause_job(job_id=job_id, jobstore=jobstore)
            return {
                "success": True,
                "error": None,
                "traceback": None
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            }

    def resume_job(self, job_id: str, in_memory: Optional[bool] = None) -> dict:
        """
        Reprend un job en pause.
        
        Args:
            job_id (str): ID du job à reprendre.
            in_memory (Optional[bool], optional): Si True, cherche dans le jobstore mémoire.
                Si False, cherche dans le jobstore persistant. Si None, cherche dans les deux.
                Par défaut None.
        
        Returns:
            dict: Résultat de l'opération avec success, error et traceback.
        """
        jobstore = self._get_jobstore(in_memory)
        
        try:
            self.scheduler.resume_job(job_id=job_id, jobstore=jobstore)
            return {
                "success": True,
                "error": None,
                "traceback": None
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            }
    
    @staticmethod
    def build_trigger(trigger_type: Union[str, "TriggerKind"], **params: Any) -> TRIGGER_TYPES:
        """
        Construit un trigger APScheduler valide à partir d'un type et de paramètres simples.

        À utiliser partout où un trigger est nécessaire (add_job, modify_job, agents...)
        pour éviter d'importer/instancier CronTrigger/DateTrigger/IntervalTrigger/
        CalendarIntervalTrigger à la main, et pour être protégé contre les triggers
        "vides" qui se déclencheraient n'importe comment (ex: cron sans aucun champ
        = toutes les minutes).

        Args:
            trigger_type (Union[str, TriggerKind]): TriggerKind.CRON / .DATE / .INTERVAL / .CALENDAR_INTERVAL,
                ou l'équivalent en str ("cron", "date", "interval", "calendarinterval").
                Alias tolérés en str : "once" → date, "calendar_interval" → calendarinterval.
                Insensible à la casse, tirets/underscores ignorés.
            **params (Any): paramètres transmis au trigger correspondant.

                - cron: year, month, day, week, day_of_week, hour, minute, second,
                        start_date, end_date, timezone, jitter
                        (au moins un champ temporel requis)
                - date: run_date (obligatoire, datetime ou str ISO), timezone
                - interval: weeks, days, hours, minutes, seconds,
                            start_date, end_date, timezone, jitter
                            (au moins une unité doit être > 0)
                - calendarinterval: years, months, weeks, days, hour, minute,
                                    second, start_date, end_date, timezone, jitter
                                    (au moins years/months/weeks/days doit être > 0)

        Returns:
            TRIGGER_TYPES: Une instance de CronTrigger, DateTrigger, IntervalTrigger ou
                CalendarIntervalTrigger, prête à être passée à add_job/modify_job.

        Raises:
            TypeError: trigger_type n'est ni un TriggerKind ni une str.
            ValueError: type inconnu, paramètre inconnu pour ce type, ou
                paramètres insuffisants pour produire un déclenchement réel.

        Examples:
            >>> JobManager.build_trigger(TriggerKind.CRON, hour=9, minute=0)
            >>> JobManager.build_trigger("cron", day_of_week="mon-fri", hour=8, minute=30)
            >>> JobManager.build_trigger(TriggerKind.INTERVAL, hours=6)
            >>> JobManager.build_trigger("date", run_date="2026-08-01 12:00:00")
            >>> JobManager.build_trigger(TriggerKind.CALENDAR_INTERVAL, days=1, hour=3)
        """
        if isinstance(trigger_type, TriggerKind):
            kind = trigger_type
        else:
            if not isinstance(trigger_type, str):
                raise TypeError(
                    f"trigger_type doit être un TriggerKind ou un str, "
                    f"reçu {type(trigger_type).__name__}"
                )

            normalized = trigger_type.strip().lower().replace("-", "").replace("_", "")
            aliases = {
                "cron": TriggerKind.CRON,
                "date": TriggerKind.DATE,
                "once": TriggerKind.DATE,
                "interval": TriggerKind.INTERVAL,
                "calendarinterval": TriggerKind.CALENDAR_INTERVAL,
            }
            kind = aliases.get(normalized)
            if kind is None:
                raise ValueError(
                    f"trigger_type invalide: '{trigger_type}'. "
                    f"Valeurs acceptées: {', '.join(k.value for k in TriggerKind)}"
                )

        allowed_params = {
            TriggerKind.CRON: {"year", "month", "day", "week", "day_of_week", "hour", "minute",
                                "second", "start_date", "end_date", "timezone", "jitter"},
            TriggerKind.DATE: {"run_date", "timezone"},
            TriggerKind.INTERVAL: {"weeks", "days", "hours", "minutes", "seconds",
                                    "start_date", "end_date", "timezone", "jitter"},
            TriggerKind.CALENDAR_INTERVAL: {"years", "months", "weeks", "days", "hour",
                                             "minute", "second", "start_date", "end_date",
                                             "timezone", "jitter"},
        }

        unknown = set(params.keys()) - allowed_params[kind]
        if unknown:
            raise ValueError(
                f"Paramètres invalides pour un trigger '{kind.value}': {', '.join(sorted(unknown))}. "
                f"Paramètres acceptés: {', '.join(sorted(allowed_params[kind]))}"
            )

        if kind is TriggerKind.CRON:
            cron_fields = ("year", "month", "day", "week", "day_of_week", "hour", "minute", "second")
            if not any(params.get(f) is not None for f in cron_fields):
                raise ValueError(
                    "Un trigger 'cron' nécessite au moins un champ temporel "
                    "(year, month, day, week, day_of_week, hour, minute ou second) — "
                    "sinon il se déclencherait toutes les minutes par défaut."
                )
            return CronTrigger(**params)

        if kind is TriggerKind.DATE:
            if not params.get("run_date"):
                raise ValueError("Un trigger 'date' nécessite le paramètre 'run_date'.")
            return DateTrigger(**params)

        if kind is TriggerKind.INTERVAL:
            interval_units = ("weeks", "days", "hours", "minutes", "seconds")
            if not any(params.get(u, 0) for u in interval_units):
                raise ValueError(
                    "Un trigger 'interval' nécessite qu'au moins une unité "
                    "(weeks, days, hours, minutes, seconds) soit > 0."
                )
            return IntervalTrigger(**params)

        # kind is TriggerKind.CALENDAR_INTERVAL
        cal_units = ("years", "months", "weeks", "days")
        if not any(params.get(u, 0) for u in cal_units):
            raise ValueError(
                "Un trigger 'calendarinterval' nécessite qu'au moins une unité "
                "(years, months, weeks, days) soit > 0."
            )
        return CalendarIntervalTrigger(**params)

    def modify_job(
        self,
        job_id: str,
        in_memory: Optional[bool] = None,
        **changes: Any,
    ) -> Dict:
        """
        Modifie les attributs d'un job existant.

        Améliorations par rapport à un simple wrapper de scheduler.modify_job :
        - Le job est vérifié au préalable (retourne une erreur propre s'il n'existe pas,
          au lieu de laisser remonter une JobLookupError brute).
        - Si 'trigger' fait partie des changements, next_run_time est recalculé
          automatiquement à partir du nouveau trigger — SAUF si le job est
          actuellement en pause, auquel cas il reste en pause avec le nouveau
          trigger prêt pour la reprise.
        - 'trigger' peut être fourni directement comme instance de trigger, ou
          comme dict {"type": "cron"/"date"/"interval"/"calendarinterval", ...params},
          auquel cas il est construit via build_trigger().
        - Toutes les erreurs (attribut invalide, type invalide, job introuvable,
          erreur du scheduler) sont renvoyées dans le même format de dict, jamais
          levées — cohérent avec le reste de JobManager.

        Args:
            job_id (str): ID du job à modifier.
            in_memory (Optional[bool], optional): Si True, cherche dans le jobstore mémoire.
                Si False, cherche dans le jobstore persistant. Si None, cherche dans les deux.
                Par défaut None.
            **changes (Any): Attributs à modifier (args, kwargs, name, max_instances,
                coalesce, misfire_grace_time, executor, trigger)

        Returns:
            Dict: {"success": bool, "error": str | None, "traceback": str | None}

        Example:
            >>> job_manager.modify_job(
            ...     'coralie_daily',
            ...     args=("asset-001",),
            ...     max_instances=5,
            ... )
            >>> job_manager.modify_job(
            ...     'coralie_daily',
            ...     trigger={"type": "cron", "hour": 9, "minute": 0},
            ... )
        """
        try:
            jobstore = self._get_jobstore(in_memory)

            job = self.get_job(job_id, in_memory=in_memory)
            if job is None:
                return {
                    "success": False,
                    "error": f"Job '{job_id}' introuvable (in_memory={in_memory})",
                    "traceback": None
                }

            if not changes:
                raise ValueError("Aucun changement fourni à modify_job")

            VALID_JOB_ATTRS = {
                'args', 'kwargs', 'name', 'max_instances',
                'coalesce', 'misfire_grace_time', 'executor',
                'trigger'
            }

            invalid_attrs = set(changes.keys()) - VALID_JOB_ATTRS
            if invalid_attrs:
                raise ValueError(
                    f"Attributs invalides pour Job: {', '.join(sorted(invalid_attrs))}. "
                    f"Attributs valides: {', '.join(sorted(VALID_JOB_ATTRS))}"
                )

            if 'trigger' in changes:
                changes['trigger'] = self._resolve_trigger(changes['trigger'])

            # ✅ Vérifier les types des valeurs
            for key, value in changes.items():
                if key == 'max_instances' and not isinstance(value, int):
                    raise TypeError(f"max_instances doit être un int, reçu {type(value).__name__}")
                if key == 'coalesce' and not isinstance(value, bool):
                    raise TypeError(f"coalesce doit être un bool, reçu {type(value).__name__}")
                if key == 'args' and not isinstance(value, (list, tuple)):
                    raise TypeError(f"args doit être un list ou tuple, reçu {type(value).__name__}")
                if key == 'kwargs' and not isinstance(value, dict):
                    raise TypeError(f"kwargs doit être un dict, reçu {type(value).__name__}")
                if key == 'name' and not isinstance(value, str):
                    raise TypeError(f"name doit être un str, reçu {type(value).__name__}")
                if key == 'misfire_grace_time' and not isinstance(value, (int, type(None))):
                    raise TypeError(f"misfire_grace_time doit être un int ou None, reçu {type(value).__name__}")
                if key == 'executor' and value not in self._executors:
                    raise ValueError(f"executor doit être l'un de {sorted(self._executors)}, reçu '{value}'")
                if key == 'trigger' and not isinstance(value, TRIGGER_TYPES):
                    raise TypeError(f"trigger doit être un {TRIGGER_TYPES}, reçu {type(value).__name__}")

            # ✅ Si le trigger change, recalculer next_run_time (sauf job en pause,
            # et sauf si l'appelant a lui-même fourni next_run_time)
            if 'trigger' in changes and 'next_run_time' not in changes:
                was_paused = getattr(job, "next_run_time", None) is None
                if not was_paused:
                    tz = getattr(changes['trigger'], 'timezone', None) or self.scheduler.timezone
                    now = datetime.now(tz)
                    changes['next_run_time'] = changes['trigger'].get_next_fire_time(None, now)

            self.scheduler.modify_job(job_id=job_id, jobstore=jobstore, **changes)
            return {
                "success": True,
                "error": None,
                "traceback": None
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            }
    
    def remove_job(self, job_id: str, in_memory: Optional[bool] = None) -> dict:
        """
        Supprime un job.
        
        Args:
            job_id (str): ID du job à supprimer.
            in_memory (Optional[bool], optional): Si True, cherche dans le jobstore mémoire.
                Si False, cherche dans le jobstore persistant. Si None, cherche dans les deux.
                Par défaut None.
        
        Returns:
            dict: Résultat de l'opération avec success, error et traceback.
        """
        jobstore = self._get_jobstore(in_memory)
        
        try:
            self.scheduler.remove_job(job_id=job_id, jobstore=jobstore)
            return {
                "success": True,
                "error": None,
                "traceback": None
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            }
    
    def remove_all_jobs(self, in_memory: Optional[bool] = None) -> dict:
        """
        Supprime tous les jobs.
        
        Args:
            in_memory (Optional[bool], optional): Si True, supprime uniquement les jobs en mémoire.
                Si False, supprime uniquement les jobs persistants. Si None, supprime TOUS les jobs.
                Par défaut None.
        
        Returns:
            dict: Résultat de l'opération avec success, error et traceback.
        """
        try:
            if in_memory is None:
                # Supprimer les jobs des deux jobstores
                for jobstore in [self._jobstore_memory, self._jobstore_default]:
                    for job in self.scheduler.get_jobs(jobstore=jobstore):
                        self.scheduler.remove_job(job.id, jobstore=jobstore)
            else:
                jobstore = self._jobstore_memory if in_memory else self._jobstore_default
                self.scheduler.remove_all_jobs(jobstore=jobstore)
            return {
                "success": True,
                "error": None,
                "traceback": None
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            }
    
    def pause_all_jobs(self, in_memory: Optional[bool] = None) -> Dict:
        """
        Met en pause tous les jobs.

        Args:
            in_memory (Optional[bool], optional): Si True, pause uniquement les jobs en mémoire.
                Si False, pause uniquement les jobs persistants. Si None, pause TOUS les jobs.
                Par défaut None.

        Returns:
            Dict: {"success": bool, "affected": int, "error": str | None, "traceback": str | None}
                'affected' = nombre de jobs effectivement mis en pause.
        """
        try:
            affected = 0
            jobstores = (
                [self._jobstore_memory, self._jobstore_default] if in_memory is None
                else [self._jobstore_memory if in_memory else self._jobstore_default]
            )
            for jobstore in jobstores:
                for job in self.scheduler.get_jobs(jobstore=jobstore):
                    self.scheduler.pause_job(job.id, jobstore=jobstore)
                    affected += 1
            return {"success": True, "affected": affected, "error": None, "traceback": None}
        except Exception as e:
            return {
                "success": False,
                "affected": 0,
                "error": str(e),
                "traceback": traceback.format_exc()
            }

    def resume_all_jobs(self, in_memory: Optional[bool] = None) -> Dict:
        """
        Reprend tous les jobs en pause.

        Args:
            in_memory (Optional[bool], optional): Si True, reprend uniquement les jobs en mémoire.
                Si False, reprend uniquement les jobs persistants. Si None, reprend TOUS les jobs.
                Par défaut None.

        Returns:
            Dict: {"success": bool, "affected": int, "error": str | None, "traceback": str | None}
                'affected' = nombre de jobs effectivement repris.
        """
        try:
            affected = 0
            jobstores = (
                [self._jobstore_memory, self._jobstore_default] if in_memory is None
                else [self._jobstore_memory if in_memory else self._jobstore_default]
            )
            for jobstore in jobstores:
                for job in self.scheduler.get_jobs(jobstore=jobstore):
                    self.scheduler.resume_job(job.id, jobstore=jobstore)
                    affected += 1
            return {"success": True, "affected": affected, "error": None, "traceback": None}
        except Exception as e:
            return {
                "success": False,
                "affected": 0,
                "error": str(e),
                "traceback": traceback.format_exc()
            }
    
    def is_job_paused(self, job_id: str, in_memory: Optional[bool] = None) -> bool | None:
        """
        Vérifie si un job est en pause.
        
        Args:
            job_id (str): ID du job.
            in_memory (Optional[bool], optional): Si True, cherche dans le jobstore mémoire.
                Si False, cherche dans le jobstore persistant. Si None, cherche dans les deux.
                Par défaut None.
        
        Returns:
            bool | None: True si le job est en pause, False s'il est actif, None si le job n'existe pas.
        """
        job = self.get_job(job_id, in_memory=in_memory)
        if job is None:
            return None
        return getattr(job, "next_run_time", None) is None
    
    def job_exists(self, job_id: str, in_memory: Optional[bool] = None) -> bool:
        """
        Vérifie si un job existe.
        
        Args:
            job_id (str): ID du job.
            in_memory (Optional[bool], optional): Si True, cherche dans le jobstore mémoire.
                Si False, cherche dans le jobstore persistant. Si None, cherche dans les deux.
                Par défaut None.
        
        Returns:
            bool: True si le job existe, False sinon.
        """
        return self.get_job(job_id, in_memory=in_memory) is not None
    
    def get_job_state(self, job_id: str, in_memory: Optional[bool] = None) -> str | None:
        """
        Retourne l'état d'un job.
        
        Args:
            job_id (str): ID du job.
            in_memory (Optional[bool], optional): Si True, cherche dans le jobstore mémoire.
                Si False, cherche dans le jobstore persistant. Si None, cherche dans les deux.
                Par défaut None.
        
        Returns:
            str | None: "running", "paused", "pending" ou None si le job n'existe pas.
        """
        job = self.get_job(job_id, in_memory=in_memory)
        if job is None:
            return None
        if getattr(job, "next_run_time", None) is None:
            return "paused"
        if job.pending:
            return "pending"
        return "running"