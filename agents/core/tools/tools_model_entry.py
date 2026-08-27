#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 12 12:03:05 2026

@author: hounsousamuel
"""

from datetime import datetime
from pydantic import BaseModel, Field, field_validator, model_validator
from modules_utils.agent_utils import (
    timer, _validate_confined, _validate_path,
)
from obsidian_hive.core.assets.asset_types import (
    AssetStatus, AssetType, Priority, Source, Severity
)
from typing import Literal, Union as _Union
from obsidian_hive.core.managers.job_catalog import JOB_CATALOG
from obsidian_hive.core.managers.job_manager import job_id

class GetAssetEntry(BaseModel):
    identifier: str = Field(
        description="Identifiant de l'asset recherché. Peut être l'ID interne (ex: 42), "
                    "l'item_id (ex: 'sh_as-4ae622a6-...'), ou le nom de l'asset si include_name=True. (casse sensible)"
    )
    include_name: bool = Field(
        default=False,
        description="Si True, permet également de rechercher par nom exact de l'asset. "
                    "Attention : plusieurs assets peuvent porter le même nom."
    )
    first: bool = Field(
        default=False,
        description="Si True, retourne uniquement le premier résultat trouvé (utile "
                    "quand plusieurs assets matchent l'identifiant)."
    )

class GetAssetByNameEntry(BaseModel):
    name: str = Field(
        description="Nom de l'asset à rechercher. Peut être un nom complet ou partiel selon `partial`."
    )
    case_sensitive: bool = Field(
        default=False,
        description="Si True, recherche exacte avec respect de la casse. "
                    "Si False (défaut), recherche insensible à la casse (tout en minuscules)."
    )
    partial: bool = Field(
        default=False,
        description="Si True, recherche partielle : le nom doit CONTENIR la chaîne fournie. "
                    "Si False (défaut), recherche exacte : le nom doit ÊTRE ÉGAL à la chaîne fournie."
    )
    first: bool = Field(
        default=True,
        description="Si True (défaut), retourne uniquement le premier résultat trouvé. "
                    "Si False, retourne la liste complète des résultats (limitée par `limit`)."
    )
    limit: int = Field(
        default=500,
        description="Nombre maximum de résultats retournés (ignoré si first=True). "
                    "Défaut: 500.",
        ge=1,
        le=10000
    )
    
class ListAssetEntry(BaseModel):
    status: AssetStatus | None = Field(
        default=None,
        description="Filtre par statut de l'asset. Valeurs possibles : 'active', 'inactive', 'suppressed'."
    )
    type_: AssetType | None = Field(
        default=None,
        description="Filtre par type d'asset."
    )
    priority: Priority | None = Field(
        default=None,
        description="Filtre par priorité."
    )
    tags: list | None = Field(
        default=None,
        description="Filtre par tags. Un asset est retourné s'il possède AU MOINS un des tags fournis "
                    "(correspondance OR). Exemple : ['prod', 'critique']."
    )
class ListAssetsByStatusEntry(BaseModel):
    """Liste les assets ayant un statut précis."""
    status: AssetStatus = Field(description="Statut recherché (active, inactive, suppressed)")

class GetFirstestReportEntry(BaseModel):
    """Récupère le tout premier rapport (le plus ancien) d'un asset."""
    asset_id: str = Field(description="item_id de l'asset concerné")
    
class ListAssetByTagsEntry(BaseModel):
    """Recherche d'assets par tags (correspondance OR : au moins un tag matché)."""
    tags: list[str] = Field(
        description="Liste de tags à rechercher, ex: ['prod', 'critique']"
    )

class PauseAssetEntry(BaseModel):
    """Met un asset en pause (INACTIVE) sans le supprimer."""
    asset_id: str = Field(description="item_id de l'asset à mettre en pause")

class ResumeAssetEntry(BaseModel):
    """Reprend un asset en pause (repasse en ACTIVE)."""
    asset_id: str = Field(description="item_id de l'asset à reprendre")

class PauseAssetsEntry(BaseModel):
    asset_type: AssetType | None = Field(default=None, description="Ne cibler que les assets de ce type. None = tous types confondus.")
    asset_ids: list[str] | None = Field(default=None, description="Ne cibler que ces assets précis (item_id). None = pas de filtre par id.")
    priority: Priority | None = Field(default=None, description="Ne cibler que les assets de cette priorité. None = toutes priorités.")
    tags: list[str] | None = Field(default=None, description="Ne cibler que les assets ayant au moins un de ces tags. None = pas de filtre par tag.")

class ResumeAssetsEntry(BaseModel):
    asset_type: AssetType | None = Field(default=None, description="Ne cibler que les assets de ce type. None = tous types confondus.")
    asset_ids: list[str] | None = Field(default=None, description="Ne cibler que ces assets précis (item_id). None = pas de filtre par id.")
    priority: Priority | None = Field(default=None, description="Ne cibler que les assets de cette priorité. None = toutes priorités.")
    tags: list[str] | None = Field(default=None, description="Ne cibler que les assets ayant au moins un de ces tags. None = pas de filtre par tag.")

class UpdateAssetEntry(BaseModel):
    """Met à jour les attributs d'un asset existant."""
    asset_id: str = Field(description="item_id de l'asset à mettre à jour")
    attrs: dict = Field(
        description="Attributs à modifier, ex: {'priority': 'high', 'tags': ['prod']}"
    )
    restart_workflow: bool = Field(
        default=False,
        description="Si True, redémarre le workflow avec la nouvelle config (utile si url/config_path/source_code_dir changent)"
    )

class RemoveAssetEntry(BaseModel):
    """Supprime définitivement un asset : annule ses tasks actives et le
    retire de la DB (config, historique). Si un source_code_dir existe
    (simple copie locale, remplaçable), il est aussi nettoyé sur disque
    sans conséquence en soi. Destructif et irréversible côté DB --
    contrairement à pause_asset (réversible), aucun retour en arrière."""
    asset_id: str = Field(description="item_id de l'asset à supprimer")



class GetEngineStatusEntry(BaseModel):
    """Aucun paramètre : retourne l'état global du moteur ShieldAI."""
    pass
 
class GetInfoAboutToolEntry(BaseModel):
    """Demande la documentation complète (usage, impact, args, avertissements) d'un tool précis."""
    tool_name: str = Field(
        description="Nom exact du tool à documenter (ex: 'pause_asset', 'get_report')"
    )


# =============================================================================
# Rapports (ReportManager)
# =============================================================================

class GetReportEntry(BaseModel):
    """Récupère un ou plusieurs rapports par ID de rapport ou asset_id."""
    identifier: str = Field(description="ID du rapport (ex: '42') ou asset_id concerné")
    first: bool = Field(
        default=False,
        description="Si True, retourne uniquement le rapport le plus récent trouvé"
    )
    limit: int = Field(
        default=50, ge=1, le=200,
        description="Nombre maximum de résultats si first=False"
    )

class GetLatestReportEntry(BaseModel):
    """Récupère le dernier rapport en date d'un asset."""
    asset_id: str = Field(description="item_id de l'asset concerné")

class ListReportsByFilterEntry(BaseModel):
    """Filtrage complet des rapports selon plusieurs critères combinables."""
    asset_id: str | None = Field(default=None, description="Filtrer sur un asset précis")
    source: Source | None = Field(default=None, description="Filtrer sur un module d'origine")
    severity: Severity | None = Field(default=None, description="Filtrer sur une sévérité exacte")
    min_severity: Severity | None = Field(
        default=None,
        description="Filtrer sur une sévérité minimale (ex: 'high' inclut high + critical)"
    )
    start_date: datetime | None = Field(default=None, description="Borne de date de début (incluse)")
    end_date: datetime | None = Field(default=None, description="Borne de date de fin (incluse)")
    limit: int = Field(default=100, ge=1, le=500)

class ListCriticalReportsEntry(BaseModel):
    """Liste les rapports de sévérité critique."""
    limit: int = Field(default=100, ge=1, le=500)

class ListRecentReportsEntry(BaseModel):
    """
    Liste tous les rapports récents (tous assets confondus) sur une fenêtre
    glissante — pensé pour la synthèse périodique cross-module de Coralie.
    """
    window_hours: float = Field(
        default=24, gt=0, le=24 * 30,
        description="Fenêtre temporelle en heures à considérer (défaut: 24h)"
    )
    limit: int = Field(default=200, ge=1, le=1000)

class GetReportStatsEntry(BaseModel):
    """Statistiques agrégées des rapports (globales si asset_id est None)."""
    asset_id: str | None = Field(
        default=None,
        description="Si fourni, restreint les stats à cet asset. Sinon, stats globales."
    )

class UpdateReportSeverityEntry(BaseModel):
    """Reclasse la sévérité d'un rapport existant (ex: requalifier un faux
    positif en 'low', ou escalader une découverte en 'critical'). Seuls
    severity et has_fix sont modifiables -- jamais content ou report_json,
    pour préserver l'intégrité du rapport d'origine d'Alex."""
    report_id: int = Field(description="ID du rapport à modifier")
    severity: Severity = Field(description="Nouvelle sévérité: critical, high, medium, low, info")
    has_fix: bool | None = Field(default=None, description="Si fourni, met aussi à jour le flag has_fix")

class DeleteReportEntry(BaseModel):
    """Supprime définitivement un rapport précis. Destructif, irréversible."""
    report_id: int = Field(description="ID du rapport à supprimer")

class DeleteOldReportsEntry(BaseModel):
    """Supprime définitivement TOUS les rapports (tous assets confondus)
    plus vieux que N jours. Destructif, irréversible, large impact."""
    days: int = Field(description="Âge en jours au-delà duquel les rapports sont supprimés", gt=0)

# =============================================================================
#  JobManager entry models
# =============================================================================

class CronTriggerSpec(BaseModel):
    """Trigger cron : se déclenche selon un calendrier (comme un crontab Unix).
    Chaque champ accepte soit un entier exact, soit une expression cron style
    Unix ('*' = toutes les valeurs, '*/3' = tous les 3, '1-5' = plage,
    '1,3,5' = liste). Au moins un champ doit être fourni."""
    type: Literal["cron"] = "cron"
    year: str | int | None = Field(
        default=None, description="Année(s) exacte(s). ex: 2026, '2026-2028'"
    )
    month: str | int | None = Field(
        default=None,
        description="Mois (1-12). ex: 6 (juin), '*/3' (tous les 3 mois), '1,4,7,10' (trimestriel)"
    )
    day: str | int | None = Field(
        default=None,
        description="Jour du mois (1-31, ou 'last' pour le dernier jour). ex: 1, 15, '*/2'"
    )
    week: str | int | None = Field(
        default=None, description="Numéro de semaine ISO (1-53). ex: 1, '10-20'"
    )
    day_of_week: str | int | None = Field(
        default=None,
        description="Jour de la semaine. ex: 'mon-fri' (lun-ven), '0-4' (0=lundi), 'sat,sun'"
    )
    hour: str | int | None = Field(
        default=None, description="Heure (0-23). ex: 9, '8-18' (heures ouvrées), '*/2'"
    )
    minute: str | int | None = Field(
        default=None, description="Minute (0-59). ex: 0, 30, '*/15'"
    )
    second: str | int | None = Field(
        default=None, description="Seconde (0-59). ex: 0. Rarement utile en pratique."
    )
    start_date: datetime | None = Field(
        default=None, description="Le trigger ne se déclenche pas avant cette date"
    )
    end_date: datetime | None = Field(
        default=None, description="Le trigger ne se déclenche plus après cette date"
    )
    timezone: str | None = Field(
        default=None, description="Fuseau horaire IANA. ex: 'Africa/Porto-Novo', 'UTC'"
    )
    jitter: int | None = Field(default=None, description="Délai aléatoire max ajouté (secondes)")

class DateTriggerSpec(BaseModel):
    """Trigger date : se déclenche une seule fois à une date précise."""
    type: Literal["date"] = "date"
    run_date: datetime = Field(description="Date/heure unique d'exécution. ex: '2026-08-01T12:00:00'")
    timezone: str | None = Field(default=None, description="Fuseau horaire IANA. ex: 'Africa/Porto-Novo', 'UTC'")

class IntervalTriggerSpec(BaseModel):
    """Trigger interval : se déclenche à intervalle fixe. Au moins une des
    unités (weeks/days/hours/minutes/seconds) doit être > 0."""
    type: Literal["interval"] = "interval"
    weeks: int = Field(default=0, description="Nombre de semaines entre 2 exécutions")
    days: int = Field(default=0, description="Nombre de jours entre 2 exécutions")
    hours: int = Field(default=0, description="Nombre d'heures entre 2 exécutions")
    minutes: int = Field(default=0, description="Nombre de minutes entre 2 exécutions")
    seconds: int = Field(default=0, description="Nombre de secondes entre 2 exécutions")
    start_date: datetime | None = Field(default=None, description="Première exécution possible")
    end_date: datetime | None = Field(default=None, description="Dernière exécution possible")
    timezone: str | None = Field(default=None, description="Fuseau horaire IANA. ex: 'Africa/Porto-Novo', 'UTC'")
    jitter: int | None = Field(default=None, description="Délai aléatoire max ajouté (secondes)")

class CalendarIntervalTriggerSpec(BaseModel):
    """Trigger calendarinterval : se déclenche tous les N années/mois/semaines/jours
    (préférable à interval pour des unités calendaires comme les mois, dont la
    durée varie — interval en jours serait imprécis). Au moins une des unités
    (years/months/weeks/days) doit être > 0."""
    type: Literal["calendarinterval"] = "calendarinterval"
    years: int = Field(default=0, description="Nombre d'années entre 2 exécutions")
    months: int = Field(default=0, description="Nombre de mois entre 2 exécutions. ex: 3 = tous les 3 mois")
    weeks: int = Field(default=0, description="Nombre de semaines entre 2 exécutions")
    days: int = Field(default=0, description="Nombre de jours entre 2 exécutions")
    hour: int = Field(default=0, description="Heure du jour (0-23) à laquelle exécuter")
    minute: int = Field(default=0, description="Minute (0-59) à laquelle exécuter")
    second: int = Field(default=0, description="Seconde (0-59) à laquelle exécuter")
    start_date: datetime | None = Field(default=None, description="Première exécution possible")
    end_date: datetime | None = Field(default=None, description="Dernière exécution possible")
    timezone: str | None = Field(default=None, description="Fuseau horaire IANA. ex: 'Africa/Porto-Novo', 'UTC'")
    jitter: int | None = Field(default=None, description="Délai aléatoire max ajouté (secondes)")

TriggerSpec = _Union[CronTriggerSpec, DateTriggerSpec, IntervalTriggerSpec, CalendarIntervalTriggerSpec]
IN_MEMORY_DESC = (
    "True: jobstore mémoire uniquement. False: jobstore persistant (SQL) "
    "uniquement. None (défaut): les deux combinés."
)

class ListJobsEntry(BaseModel):
    """Liste les jobs planifiés du scheduler."""
    in_memory: bool | None = Field(
        default=None,
        description=IN_MEMORY_DESC
    )

class GetJobEntry(BaseModel):
    """Récupère un job précis par son ID."""
    job_id: str = Field(description="ID du job (ex: 'scan_daily_asset-042')")
    in_memory: bool | None = Field(default=None, description=IN_MEMORY_DESC)

class GetJobStateEntry(BaseModel):
    """Récupère l'état d'un job (raccourci léger vs get_job)."""
    job_id: str = Field(description="ID du job")
    in_memory: bool | None = Field(default=None, description=IN_MEMORY_DESC)

class PauseJobEntry(BaseModel):
    """Met un job en pause (réversible, ne supprime rien)."""
    job_id: str = Field(description="ID du job à mettre en pause")
    in_memory: bool | None = Field(default=None, description=IN_MEMORY_DESC)

class ResumeJobEntry(BaseModel):
    """Reprend un job en pause."""
    job_id: str = Field(description="ID du job à reprendre")
    in_memory: bool | None = Field(default=None, description=IN_MEMORY_DESC)

class ModifyJobEntry(BaseModel):
    """
    Modifie un ou plusieurs attributs d'un job existant. Seuls les champs
    fournis (non None) sont appliqués — les autres restent inchangés.
    Si 'trigger' est fourni, la prochaine exécution est recalculée
    automatiquement (sauf si le job est en pause, auquel cas il reste en pause).
    """
    job_id: str = Field(description="ID du job à modifier")
    in_memory: bool | None = Field(default=None, description=IN_MEMORY_DESC)
    trigger: TriggerSpec | None = Field(
        default=None,
        description="Nouveau trigger. Fournir le sous-schéma correspondant au 'type' voulu."
    )
    args: list | None = Field(default=None, description="Nouveaux arguments positionnels de la fonction du job")
    kwargs: dict | None = Field(default=None, description="Nouveaux arguments nommés de la fonction du job")
    name: str | None = Field(default=None, description="Nouveau nom lisible du job")
    max_instances: int | None = Field(default=None, description="Nombre max d'exécutions concurrentes")
    coalesce: bool | None = Field(default=None, description="Fusionner les exécutions manquées en une seule")
    misfire_grace_time: int | None = Field(default=None, description="Tolérance (secondes) avant de considérer un run manqué")
    executor: str | None = Field(default=None, description="Nom de l'executor APScheduler à utiliser")

class RemoveJobEntry(BaseModel):
    """Supprime définitivement un job. Action destructive et irréversible."""
    job_id: str = Field(description="ID du job à supprimer")
    in_memory: bool | None = Field(default=None, description=IN_MEMORY_DESC)

class RemoveAllJobsEntry(BaseModel):
    """Supprime définitivement TOUS les jobs (d'un jobstore ou des deux). Action destructive et irréversible, large impact."""
    in_memory: bool | None = Field(
        default=None,
        description="True: supprime uniquement les jobs mémoire. False: uniquement les persistants. "
                    "None: supprime TOUS les jobs des deux jobstores — à utiliser avec une extrême prudence."
    )

class PauseAllJobsEntry(BaseModel):
    """Met TOUS les jobs en pause. Large impact (réversible via resume_all_jobs)."""
    in_memory: bool | None = Field(
        default=None, 
        description=(
                "True: supprime uniquement les jobs mémoire. False: uniquement les persistants. "
                "None: supprime TOUS les jobs des deux jobstores — à utiliser avec une extrême prudence."
            )
        )

class ResumeAllJobsEntry(BaseModel):
    """Reprend TOUS les jobs en pause. Large impact."""
    in_memory: bool | None = Field(
        default=None, 
        description=(
                "True: supprime uniquement les jobs mémoire. False: uniquement les persistants. "
                "None: supprime TOUS les jobs des deux jobstores — à utiliser avec une extrême prudence."
            )
    )

JobName = Literal[tuple(JOB_CATALOG)]

class AddJobEntry(BaseModel):
    """Planifie un nouveau job à partir du catalogue prédéfini. Jamais de
    fonction arbitraire -- job_name doit référencer une entrée du catalogue."""
    job_name: Literal[JobName] = Field(description=f"Nom du job dans le catalogue: {', '.join(JOB_CATALOG)}")
    job_id: str | None = Field(description="ID unique pour cette instance planifiée", default=None)
    trigger: TriggerSpec | None = Field(default=None, description="Trigger custom, sinon celui par défaut du catalogue")
    kwargs: dict | None = Field(default=None, description="Kwargs custom, fusionnés avec ceux par défaut du catalogue")
    in_memory: bool = Field(default=False, description=IN_MEMORY_DESC)

    @field_validator("job_name")
    @classmethod
    def job_name_must_exist(cls, v):
        if v not in JOB_CATALOG:
            raise ValueError(f"job_name inconnu: '{v}'. Disponibles: {', '.join(JOB_CATALOG)}")
        return v
    
    @model_validator(mode="after")
    def validate_model(self) -> "AddJobEntry":
        self.job_id = self.job_id or job_id(self.job_name)
        return self
    
class ListJobCatalogEntry(BaseModel):
    """Liste les jobs planifiables (aucun paramètre)."""
    