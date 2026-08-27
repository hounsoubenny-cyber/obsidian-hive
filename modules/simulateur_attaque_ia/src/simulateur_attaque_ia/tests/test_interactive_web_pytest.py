#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 14:00:38 2026

@author: hounsousamuel
"""

"""
Tests unitaires pour InteractiveWebOrchestrator.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from simulateur_attaque_ia.orchestrator.interactive_web_orchestrator import (
    InteractiveWebOrchestrator,
    _merge,
)


# ─────────────────────────────────────────────────────────────────────────────
# Tests du helper _merge
# ─────────────────────────────────────────────────────────────────────────────

class TestMerge:
    """Tests de la fonction _merge."""
    
    def test_keep(self):
        existing = [1, 2, 3]
        incoming = [4, 5, 6]
        result = _merge(existing, incoming, "keep")
        assert result == existing
        assert result is existing  # retourne la même liste
    
    def test_replace(self):
        existing = [1, 2, 3]
        incoming = [4, 5, 6]
        result = _merge(existing, incoming, "replace")
        assert result == incoming
    
    def test_replace_with_none(self):
        existing = [1, 2, 3]
        result = _merge(existing, None, "replace")
        assert result == existing
    
    def test_add(self):
        existing = [1, 2, 3]
        incoming = [3, 4, 5]
        result = _merge(existing, incoming, "add")
        assert result == [1, 2, 3, 4, 5]  # dédupliqué
    
    def test_add_with_none(self):
        existing = [1, 2, 3]
        result = _merge(existing, None, "add")
        assert result == existing
    
    def test_default_mode(self):
        existing = [1, 2, 3]
        incoming = [4, 5, 6]
        result = _merge(existing, incoming, "unknown")
        assert result == incoming  # fallback replace


# ─────────────────────────────────────────────────────────────────────────────
# Tests d'InteractiveWebOrchestrator
# ─────────────────────────────────────────────────────────────────────────────

class TestInteractiveWebOrchestrator:
    """Tests de la classe InteractiveWebOrchestrator."""
    
    @pytest.fixture
    def orchestrator(self):
        """Fixture pour créer un orchestrator avec des mocks."""
        mock_docker = MagicMock()
        mock_ws_send = AsyncMock()
        
        orch = InteractiveWebOrchestrator(
            docker_manager=mock_docker,
            ip="192.168.1.1",
            sim_config=None,
            use_llm=False,
            llm=None,
            ws_send=mock_ws_send,
            debug=True,
        )
        return orch
    
    # ─── Tests de base ────────────────────────────────────────────────────
    
    def test_init(self, orchestrator):
        """Test de l'initialisation."""
        assert orchestrator.ip == "192.168.1.1"
        assert orchestrator.use_llm is False
        assert orchestrator.llm is None
        assert orchestrator.debug is True
        assert orchestrator.done_steps == set()
        assert orchestrator.scan_data == {}
        assert orchestrator.cred_data == {}
        assert orchestrator.exec_data == {}
        assert orchestrator.ca_data == {}
    
    def test_get_set(self, orchestrator):
        """Test des helpers _get et _set."""
        # Test _get avec défaut
        assert orchestrator._get("inexistant", "default") == "default"
        
        # Test _set et _get
        orchestrator._set("test_key", "test_value")
        assert orchestrator._get("test_key") == "test_value"
    
    # ─── Tests available_actions ─────────────────────────────────────────
    
    def test_available_actions_empty(self, orchestrator):
        """Test available_actions quand rien n'est fait."""
        actions = orchestrator.available_actions()
        
        # Reconnaissance doit être disponible
        assert "reconnaissance" in actions
        
        # Les autres ne doivent pas être disponibles sans prérequis
        assert "initial_access" not in actions
        assert "execution" not in actions
        assert "report" not in actions
    
    def test_available_actions_after_recon(self, orchestrator):
        """Test available_actions après reconnaissance."""
        orchestrator.scan_data = {"continue": True, "open_ports": [22, 80]}
        orchestrator.done_steps.add("reconnaissance")
        
        actions = orchestrator.available_actions()
        
        assert "reconnaissance" not in actions
        assert "initial_access" in actions
        assert "execution" not in actions
    
    def test_available_actions_after_initial_access(self, orchestrator):
        """Test available_actions après initial_access."""
        orchestrator.scan_data = {"continue": True}
        orchestrator.done_steps.add("reconnaissance")
        orchestrator.done_steps.add("initial_access")
        
        orchestrator.cred_data = {
            "credentials": {
                "ssh": {
                    22: {"results": {"founds": [{"username": "root", "password": "toor"}]}}
                }
            }
        }
        
        actions = orchestrator.available_actions()
        
        assert "execution" in actions
        assert "initial_access" not in actions
    
    def test_available_actions_report(self, orchestrator):
        """Test que report est disponible après au moins une étape."""
        orchestrator.done_steps.add("reconnaissance")
        
        actions = orchestrator.available_actions()
        assert "report" in actions
    
    # ─── Tests available_actions_with_details ────────────────────────────
    
    def test_available_actions_with_details(self, orchestrator):
        """Test de available_actions_with_details."""
        details = orchestrator.available_actions_with_details()
        
        # Vérifier la structure
        assert "reconnaissance" in details
        assert "initial_access" in details
        assert "execution" in details
        
        # Vérifier que les champs sont présents
        for action, info in details.items():
            assert "available" in info
            assert "reason" in info
            assert "prereq" in info
            assert "prereq_met" in info
        
        # Vérifier que les raisons sont en français
        assert "🔍" in details["reconnaissance"]["reason"]
        assert "🔑" in details["initial_access"]["reason"]
    
    # ─── Tests execute_step ──────────────────────────────────────────────
    
    @pytest.mark.asyncio
    async def test_execute_step_action_not_available(self, orchestrator):
        """Test execute_step avec une action non disponible."""
        # Mock available_actions pour simuler une action non dispo
        with patch.object(orchestrator, 'available_actions', return_value=[]):
            result = await orchestrator.execute_step("execution", {})
            
            assert result["success"] is False
            assert "non disponible" in result["error"]
            assert result["error_type"] == "unavailable_action"
    
    @pytest.mark.asyncio
    async def test_execute_step_unknown_action(self, orchestrator):
        """Test execute_step avec une action inconnue."""
        # Simuler que l'action est disponible (pour passer la vérif)
        with patch.object(orchestrator, 'available_actions', return_value=["action_inexistante"]):
            result = await orchestrator.execute_step("action_inexistante", {})
            
            assert result["success"] is False
            assert "Action inconnue" in result["error"]
    
    @pytest.mark.asyncio
    async def test_execute_step_value_error(self, orchestrator):
        """Test execute_step avec une ValueError (prérequis manquant)."""
        # Simuler que l'action est disponible
        with patch.object(orchestrator, 'available_actions', return_value=["execution"]):
            # Mock le handler pour lever une ValueError
            with patch.object(orchestrator, '_step_execution', side_effect=ValueError("Lancez d'abord l'Initial Access.")):
                result = await orchestrator.execute_step("execution", {})
                
                assert result["success"] is False
                assert result["error_type"] == "prereq_error"
                assert "Lancez d'abord" in result["error"]
    
    @pytest.mark.asyncio
    async def test_execute_step_success(self, orchestrator):
        """Test execute_step avec succès."""
        # Simuler que l'action est disponible
        with patch.object(orchestrator, 'available_actions', return_value=["reconnaissance"]):
            # Mock le handler
            mock_result = {"open_ports": [22, 80]}
            with patch.object(orchestrator, '_step_reconnaissance', return_value=mock_result):
                result = await orchestrator.execute_step("reconnaissance", {})
                
                assert result["success"] is True
                assert result["step"] == "reconnaissance"
                assert result["result"] == mock_result
                assert "reconnaissance" in orchestrator.done_steps
    
    # ─── Tests get_state_summary ─────────────────────────────────────────
    
    def test_get_state_summary_empty(self, orchestrator):
        """Test get_state_summary quand tout est vide."""
        summary = orchestrator.get_state_summary()
        
        assert summary["ip"] == "192.168.1.1"
        assert summary["done_steps"] == []
        assert summary["open_ports"] == []
        assert summary["ssh_creds_found"] == {}
        assert summary["privesc_success"] is False
        assert summary["usable_keys_count"] == 0
    
    def test_get_state_summary_with_data(self, orchestrator):
        """Test get_state_summary avec des données."""
        orchestrator.scan_data = {"open_ports": [22, 80, 443]}
        orchestrator.done_steps.add("reconnaissance")
        orchestrator.steps_results["SSHBruteForce|InitialAccess"] = [
            {"port": 22, "result": {"results": {"founds": [{"username": "root"}]}}}
        ]
        
        summary = orchestrator.get_state_summary()
        
        assert summary["open_ports"] == [22, 80, 443]
        assert summary["done_steps"] == ["reconnaissance"]
        assert summary["ssh_creds_found"] == {"22": 1}
    
    # ─── Tests build_report ──────────────────────────────────────────────
    
    def test_build_report_empty(self, orchestrator):
        """Test build_report quand rien n'a été fait."""
        report = orchestrator.build_report()
        
        assert report["ip"] == "192.168.1.1"
        assert report["done_steps"] == []
        assert report["steps_results"] == {}
        assert "started_at" in report
        assert "ended_at" in report
    
    def test_build_report_with_data(self, orchestrator):
        """Test build_report avec des données."""
        orchestrator.done_steps.add("reconnaissance")
        orchestrator.steps_results["test"] = [{"result": "ok"}]
        
        report = orchestrator.build_report()
        
        assert report["done_steps"] == ["reconnaissance"]
        assert report["steps_results"]["test"] == [{"result": "ok"}]


# ─────────────────────────────────────────────────────────────────────────────
# Tests d'intégration (avec mocks)
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegration:
    """Tests d'intégration avec mocks des tactiques."""
    
    @pytest.fixture
    def orchestrator(self):
        mock_docker = MagicMock()
        mock_ws_send = AsyncMock()
        
        return InteractiveWebOrchestrator(
            docker_manager=mock_docker,
            ip="192.168.1.1",
            ws_send=mock_ws_send,
            debug=True,
        )
    
    @pytest.mark.asyncio
    async def test_full_workflow(self, orchestrator):
        """Test d'un workflow complet (recon → initial_access → execution)."""
        
        # ─── 1. Reconnaissance ──────────────────────────────────────────
        with patch('simulateur_attaque_ia.orchestrator.interactive_web_orchestrator.NetworkServiceDiscover') as MockDiscover:
            mock_instance = MockDiscover.return_value
            mock_instance.scan_async = AsyncMock(return_value={
                "results": {
                    "open_ports": [22, 80],
                    "scan_result": {
                        22: {"service": "ssh", "banner": "SSH-2.0"},
                        80: {"service": "http", "banner": "nginx"},
                    }
                }
            })
            
            result = await orchestrator.execute_step("reconnaissance", {
                "timeout_socket": 0.5,
                "port_range": [22, 80, 443],
            })
            
            assert result["success"] is True
            assert orchestrator.scan_data["open_ports"] == [22, 80]
            assert "reconnaissance" in orchestrator.done_steps
        
        # ─── 2. Initial Access ──────────────────────────────────────────
        with patch('simulateur_attaque_ia.orchestrator.interactive_web_orchestrator.SSHBruteForce') as MockSSH:
            mock_ssh = MockSSH.return_value
            mock_ssh.find_all_async = AsyncMock(return_value={
                "results": {
                    "founds": [{"username": "root", "password": "toor"}]
                }
            })
            
            result = await orchestrator.execute_step("initial_access", {
                "timeout": 5.0,
                "delay": 0.2,
                "max_attempts": 50,
                "ssh": {"enabled": True},
            })
            
            assert result["success"] is True
            assert orchestrator.cred_data["credentials"]["ssh"][22]["results"]["founds"] == [{"username": "root", "password": "toor"}]
            assert "initial_access" in orchestrator.done_steps
        
        # ─── 3. Execution ──────────────────────────────────────────────
        with patch('simulateur_attaque_ia.orchestrator.interactive_web_orchestrator.CommandExecution') as MockCmd:
            mock_cmd = MockCmd.return_value
            mock_cmd.exec_command_async = AsyncMock(return_value={
                "results": {
                    "commands": {
                        "whoami": {"returncode": 0, "stdout": "root\n"}
                    }
                }
            })
            
            result = await orchestrator.execute_step("execution", {
                "credential_index": 0,
                "commands": ["whoami", "id"],
            })
            
            assert result["success"] is True
            assert orchestrator.exec_data["selected_cred"]["username"] == "root"
            assert "execution" in orchestrator.done_steps