#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jun 23 14:39:30 2026

@author: hounsousamuel
"""
import abc
from uuid import uuid4
from typing import TYPE_CHECKING
import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", "..", ".."))))

if TYPE_CHECKING:
    from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager
    from obsidian_hive.core.managers.report_manager import ReportManager


class WorkflowBase(abc.ABC):
    """Classe de base abstraite pour tous les workflows de l'Obsidian Hive.
    
    Cette classe fournit l'infrastructure commune à tous les workflows :
    gestion des managers (LLM et rapport), génération d'IDs de tâches,
    et définition du contrat d'exécution.
    
    Attributes:
        _llm_manager (LLMManager | None): Gestionnaire LLM partagé au niveau de la classe.
        _report_manager (ReportManager | None): Gestionnaire de rapports partagé au niveau de la classe.
    """
    _llm_manager: "LLMManager" = None 
    _report_manager: "ReportManager" = None

    def __init__(self, llm_manager=None, report_manager=None):
        """Initialise un workflow avec des gestionnaires optionnels.

        Args:
            llm_manager (LLMManager | None, optional): Gestionnaire LLM à utiliser.
            report_manager (ReportManager | None, optional): Gestionnaire de rapports à utiliser.
        """
        self._llm_manager_override = llm_manager
        self._report_manager_override = report_manager

    @classmethod
    def set_report_manager(cls, manager: "ReportManager"):
        """Définit le gestionnaire de rapports partagé au niveau de la classe.

        Args:
            manager (ReportManager): Le gestionnaire de rapports à partager.
        """
        cls._report_manager = manager
        
    @classmethod
    def set_llm_manager(cls, manager: "LLMManager"):
        """Définit le gestionnaire LLM partagé au niveau de la classe.

        Args:
            manager (LLMManager): Le gestionnaire LLM à partager.
        """
        cls._llm_manager = manager

    @property
    def report_manager(self):
        """Retourne le gestionnaire de rapports utilisé par ce workflow.
        
        Priorité à l'override d'instance, sinon utilisation du partagé de classe.

        Returns:
            ReportManager | None: Le gestionnaire de rapports.
        """
        return self._report_manager_override or type(self)._report_manager
    
    @property
    def llm_manager(self):
        """Retourne le LLM Manager
        
        Priorité à l'override d'instance, sinon utilisation du partagé de classe.

        Returns:
            LLMManager | None.
        """
        return self._llm_manager_override or type(self)._llm_manager
    
    @staticmethod
    def task_id(tag: str = "sh_ta-"):
        """Génère un identifiant unique pour une tâche workflow.

        Args:
            tag (str, optional): Préfixe pour l'ID de la tâche. Par défaut "sh_ta-".

        Returns:
            str: Un ID unique combinant le préfixe et un UUID4.
        """
        return (tag or "sh_ta-") + str(uuid4())

    @abc.abstractmethod
    async def run_async(self, *args, **kwargs):
        """Exécute le workflow de manière asynchrone.
        
        Cette méthode doit être implémentée par toutes les sous-classes.
        Elle contient la logique principale du workflow.

        Args:
            *args: Arguments positionnels.
            **kwargs: Arguments nommés.

        Returns:
            Any: Le résultat du workflow.
        """
        pass

    @abc.abstractmethod
    def run(self, *args, **kwargs):
        """Exécute le workflow de manière synchrone.
        
        Cette méthode doit être implémentée par toutes les sous-classes.
        Elle sert d'interface synchrone vers l'exécution asynchrone.

        Args:
            *args: Arguments positionnels.
            **kwargs: Arguments nommés.

        Returns:
            Any: Le résultat du workflow.
        """
        pass