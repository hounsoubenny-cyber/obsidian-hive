#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 12:25:24 2026

@author: hounsousamuel
"""
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_all_routes.py — Smoke test complet de l'API Simulateur attaque.

Parcourt TOUTES les routes (auth, images, clone, services, sim, containers, network, ws).

Dépendances :
    pip install httpx websockets rich

Usage :
    python test_all_routes.py \
        --base-url http://127.0.0.1:8000/api \
        --username admin --password ********** \
        --image shieldai_sim_atk:v2
"""

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Awaitable, Tuple

import httpx
import websockets

# ─── Rich ────────────────────────────────────────────────────────────────────
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.rule import Rule

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# Types de résultats
# ─────────────────────────────────────────────────────────────────────────────

class TestStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class TestResult:
    name: str
    status: TestStatus
    message: str = ""
    duration: float = 0.0
    data: Any = None

    def __str__(self) -> str:
        icons = {
            TestStatus.PASSED: "✅",
            TestStatus.FAILED: "❌",
            TestStatus.SKIPPED: "⏭️",
            TestStatus.ERROR: "💥",
        }
        return f"{icons.get(self.status, '❓')} {self.name} — {self.message}"


@dataclass
class TestSuiteResult:
    results: List[TestResult] = field(default_factory=list)
    start_time: float = field(default_factory=time.monotonic)
    end_time: Optional[float] = None

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == TestStatus.PASSED)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == TestStatus.FAILED)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.status == TestStatus.SKIPPED)

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.status == TestStatus.ERROR)

    @property
    def success_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.passed / self.total) * 100

    @property
    def duration(self) -> float:
        end = self.end_time or time.monotonic()
        return end - self.start_time

    def add(self, result: TestResult) -> None:
        self.results.append(result)

    def get_failures(self) -> List[TestResult]:
        return [r for r in self.results if r.status in (TestStatus.FAILED, TestStatus.ERROR)]


# ─────────────────────────────────────────────────────────────────────────────
# Test Runner
# ─────────────────────────────────────────────────────────────────────────────

class TestRunner:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        image: str,
        with_clone: bool = False,
        clone_src: Optional[str] = None,
        interactive: bool = False,
        timeout: float = 30.0,
    ):
        self.base_url = base_url
        self.ws_base_url = base_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws"
        self.username = username
        self.password = password
        self.image = image
        self.with_clone = with_clone
        self.clone_src = clone_src
        self.interactive = interactive
        self.timeout = timeout

        self.results = TestSuiteResult()
        self._client: Optional[httpx.AsyncClient] = None
        self._token: Optional[str] = None
        self._headers: Optional[Dict[str, str]] = None
        self._container_name: Optional[str] = None
        self._network_name: Optional[str] = None

    async def _run_test(self, name: str, coro: Awaitable[Any], skip_msg: Optional[str] = None) -> Any:
        start = time.monotonic()

        if skip_msg:
            self.results.add(TestResult(name=name, status=TestStatus.SKIPPED, message=skip_msg))
            return None

        try:
            result = await coro
            duration = time.monotonic() - start
            self.results.add(TestResult(name=name, status=TestStatus.PASSED, message="OK", duration=duration, data=result))
            return result

        except AssertionError as e:
            duration = time.monotonic() - start
            self.results.add(TestResult(name=name, status=TestStatus.FAILED, message=str(e), duration=duration))
            return None

        except httpx.HTTPStatusError as e:
            duration = time.monotonic() - start
            self.results.add(TestResult(
                name=name,
                status=TestStatus.FAILED,
                message=f"HTTP {e.response.status_code}: {e.response.text[:150]}",
                duration=duration,
            ))
            return None

        except asyncio.TimeoutError:
            duration = time.monotonic() - start
            self.results.add(TestResult(name=name, status=TestStatus.ERROR, message=f"Timeout après {self.timeout}s", duration=duration))
            return None

        except Exception as e:
            duration = time.monotonic() - start
            self.results.add(TestResult(name=name, status=TestStatus.ERROR, message=f"{type(e).__name__}: {e}", duration=duration))
            return None

    # ─── Tests Auth ──────────────────────────────────────────────────────────

    async def test_login(self) -> str:
        r = await self._client.post("/auth/login", json={"username": self.username, "password": self.password})
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Login failed: {data}"
        assert data.get("token"), "No token in response"
        return data["token"]

    # ─── Tests Images ────────────────────────────────────────────────────────

    async def test_images_list(self) -> List[Dict]:
        r = await self._client.get("/images/list", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert "images" in data, f"No 'images' key in {data}"
        assert isinstance(data["images"], list), "Images should be a list"
        return data["images"]

    # ─── Tests Services ──────────────────────────────────────────────────────

    async def test_services_capture(self) -> Dict:
        r = await self._client.get("/services/capture", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert "services" in data, f"No 'services' key in {data}"
        assert isinstance(data["services"], dict), "Services should be a dict"
        return data["services"]

    async def test_services_validate(self, services: Dict) -> Dict:
        r = await self._client.post("/services/validate", headers=self._headers, json={"services": services})
        r.raise_for_status()
        data = r.json()
        assert "valid" in data, f"No 'valid' key in {data}"
        assert data["valid"] is True, f"Services invalid: {data.get('errors')}"
        return data

    # ─── Tests Clone ─────────────────────────────────────────────────────────

    async def test_clone_start(self, src: Optional[str] = None) -> str:
        payload = {"src": src} if src else {}
        r = await self._client.post("/clone/start", headers=self._headers, json=payload)
        r.raise_for_status()
        data = r.json()
        clone_id = data.get("clone_id")
        assert clone_id, f"No clone_id in {data}"
        return clone_id

    async def test_clone_status(self, clone_id: str) -> Dict:
        r = await self._client.get(f"/clone/{clone_id}/status", headers=self._headers)
        r.raise_for_status()
        return r.json()

    async def test_clone_stop(self, clone_id: str) -> Dict:
        r = await self._client.post(f"/clone/{clone_id}/stop", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert data.get("status") == "stopped", f"Expected stopped, got {data}"
        return data

    async def test_clone_flow(self, src: Optional[str] = None) -> Optional[str]:
        clone_id = await self.test_clone_start(src)
        deadline = time.monotonic() + 300
        last_status = "starting"

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(),
                      TimeElapsedColumn(), TimeRemainingColumn(), console=console, transient=True) as progress:
            task = progress.add_task("🔄 Clonage en cours...", total=300)

            while time.monotonic() < deadline:
                remaining = int(deadline - time.monotonic())
                progress.update(task, completed=300 - remaining)

                data = await self.test_clone_status(clone_id)
                status = data.get("status", "unknown")

                if status != last_status:
                    progress.update(task, description=f"🔄 Status: {status}")
                    last_status = status

                if status in ("completed", "failed", "stopped"):
                    if status == "completed":
                        return data.get("image")
                    raise AssertionError(f"Clone failed: {data.get('error')}")

                await asyncio.sleep(3)

            raise TimeoutError("Clone timeout after 5 minutes")

    # ─── Tests Containers ────────────────────────────────────────────────────

    async def test_containers_list(self) -> Dict:
        r = await self._client.get("/containers/list", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert "total" in data, f"No 'total' key in {data}"
        assert "containers" in data, f"No 'containers' key in {data}"
        return data

    async def test_container_create(self) -> str:
        payload = {
            "image": self.image,
            "name": f"test_container_{int(time.time())}",
            "network": "bridge",
            "cap_add": ["NET_RAW"],
            "labels": {"test": "true"},
        }
        r = await self._client.post("/containers/create", headers=self._headers, json=payload)
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create failed: {data}"
        assert data.get("container", {}).get("name"), f"No container name in {data}"
        self._container_name = data["container"]["name"]
        return self._container_name

    async def test_container_create_invalid_network(self) -> Dict:
        payload = {
            "image": self.image,
            "name": f"test_invalid_network_{int(time.time())}",
            "network": "reseau_inexistant",
        }
        r = await self._client.post("/containers/create", headers=self._headers, json=payload)
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is False, f"Should have failed, got {data}"
        assert "introuvable" in data.get("message", ""), f"Expected network error, got {data}"
        return data

    async def test_container_exec(self, name: str) -> Dict:
        payload = {"command": "whoami"}
        r = await self._client.post(f"/containers/{name}/exec", headers=self._headers, json=payload)
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Exec failed: {data}"
        assert data.get("exit_code") == 0, f"Command failed with exit code {data.get('exit_code')}"
        return data

    async def test_container_stop(self, name: str) -> Dict:
        r = await self._client.post(f"/containers/{name}/stop", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Stop failed: {data}"
        return data

    async def test_containers_cache(self) -> Dict:
        r = await self._client.get("/containers/cache", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert "total" in data, f"No 'total' key in {data}"
        assert "containers" in data, f"No 'containers' key in {data}"
        return data

    # ─── Tests Network ───────────────────────────────────────────────────────

    async def test_network_list(self) -> Dict:
        """Test GET /network/list."""
        r = await self._client.get("/network/list", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert "total" in data, f"No 'total' key in {data}"
        assert "networks" in data, f"No 'networks' key in {data}"
        return data

    async def test_network_create(self) -> str:
        """Test POST /network/create."""
        self._network_name = f"test_network_{int(time.time())}"
        payload = {
            "name": self._network_name,
            "driver": "bridge",
            "subnet": "172.30.0.0/24",
            "internal": True,
            "labels": {"test": "true"},
        }
        r = await self._client.post("/network/create", headers=self._headers, json=payload)
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create network failed: {data}"
        assert data.get("network", {}).get("name") == self._network_name, f"Network name mismatch: {data}"
        return self._network_name

    async def test_network_create_duplicate(self) -> Dict:
        """Test POST /network/create avec un nom existant."""
        payload = {
            "name": self._network_name,
            "driver": "bridge",
        }
        r = await self._client.post("/network/create", headers=self._headers, json=payload)
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is False, f"Should have failed, got {data}"
        assert "existe déjà" in data.get("message", ""), f"Expected duplicate error, got {data}"
        return data

    async def test_network_create_invalid_subnet(self) -> Dict:
        """Test POST /network/create avec subnet invalide."""
        payload = {
            "name": f"test_invalid_subnet_{int(time.time())}",
            "driver": "bridge",
            "subnet": "999.999.999.999/33",
        }
        r = await self._client.post("/network/create", headers=self._headers, json=payload)
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is False, f"Should have failed, got {data}"
        assert "subnet" in data.get("message", "").lower() or "invalide" in data.get("message", ""), f"Expected subnet error, got {data}"
        return data

    async def test_network_containers(self) -> Dict:
        """Test GET /network/{name}/containers."""
        r = await self._client.get(f"/network/{self._network_name}/containers", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert data.get("network") == self._network_name, f"Network name mismatch: {data}"
        assert "containers" in data, f"No 'containers' key in {data}"
        return data

    async def test_network_containers_not_found(self) -> Dict:
        """Test GET /network/{name}/containers avec réseau inexistant."""
        r = await self._client.get("/network/inexistant/containers", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        # La route retourne un JSON avec message d'erreur, pas un 404 HTTP
        assert data.get("total") == 0, f"Should be empty, got {data}"
        assert "introuvable" in data.get("message", ""), f"Expected not found message, got {data}"
        return data

    async def test_network_connect(self) -> Dict:
        """Test POST /network/{name}/connect."""
        # Créer un container sur bridge
        container_name = f"test_connect_{int(time.time())}"
        r = await self._client.post("/containers/create", headers=self._headers, json={
            "image": self.image,
            "name": container_name,
            "network": "bridge",
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create container failed: {data}"

        # Connecter au réseau
        r = await self._client.post(
            f"/network/{self._network_name}/connect",
            headers=self._headers,
            json={"container_name": container_name}
        )
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Connect failed: {data}"
        assert data.get("container") == container_name, f"Container name mismatch: {data}"
        return data

    async def test_network_connect_already(self) -> Dict:
        """Test POST /network/{name}/connect sur un container déjà connecté."""
        container_name = f"test_connect_already_{int(time.time())}"
        # Créer container directement sur le réseau
        r = await self._client.post("/containers/create", headers=self._headers, json={
            "image": self.image,
            "name": container_name,
            "network": self._network_name,
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create container failed: {data}"

        # Tentative de reconnexion
        r = await self._client.post(
            f"/network/{self._network_name}/connect",
            headers=self._headers,
            json={"container_name": container_name}
        )
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is False, f"Should have failed, got {data}"
        assert "déjà connecté" in data.get("message", ""), f"Expected already connected error, got {data}"
        return data

    async def test_network_disconnect_no_force(self) -> Dict:
        """Test POST /network/{name}/disconnect sans force (doit échouer)."""
        container_name = f"test_disconnect_{int(time.time())}"
        # Créer container sur le réseau
        r = await self._client.post("/containers/create", headers=self._headers, json={
            "image": self.image,
            "name": container_name,
            "network": self._network_name,
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create container failed: {data}"
        
        # Déconnecter sans force
        r = await self._client.post(
            f"/network/{self._network_name}/disconnect",
            headers=self._headers,
            json={"container_name": container_name, "force": False}
        )
        r.raise_for_status()
        data = r.json()
        # On attend une erreur (dernier réseau)
        assert data.get("success") is False, f"Should have failed, got {data}"
        assert "Dernier réseau" in data.get("message", ""), f"Expected 'Dernier réseau', got {data}"
        return data
     
    async def test_network_disconnect_force(self) -> Dict:
        """Test POST /network/{name}/disconnect avec force=true."""
        container_name = f"test_disconnect_force_{int(time.time())}"
        r = await self._client.post("/containers/create", headers=self._headers, json={
            "image": self.image,
            "name": container_name,
            "network": self._network_name,
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create container failed: {data}"
        
        r = await self._client.post(
            f"/network/{self._network_name}/disconnect",
            headers=self._headers,
            json={"container_name": container_name, "force": True}
        )
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Disconnect with force failed: {data}"
        assert data.get("container") == container_name, f"Container name mismatch: {data}"
        return data

    async def test_network_disconnect_not_connected(self) -> Dict:
        """Test POST /network/{name}/disconnect sur un container non connecté."""
        container_name = f"test_not_connected_{int(time.time())}"
        # Créer container sur bridge (pas sur le réseau)
        r = await self._client.post("/containers/create", headers=self._headers, json={
            "image": self.image,
            "name": container_name,
            "network": "bridge",
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create container failed: {data}"

        # Tentative de déconnexion
        r = await self._client.post(
            f"/network/{self._network_name}/disconnect",
            headers=self._headers,
            json={"container_name": container_name}
        )
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is False, f"Should have failed, got {data}"
        assert "non connecté" in data.get("message", ""), f"Expected not connected error, got {data}"
        return data

    async def test_network_move_no_force(self) -> Dict:
        """Test POST /network/move sans force (doit échouer)."""
        network2_name = f"test_network2_{int(time.time())}"
        r = await self._client.post("/network/create", headers=self._headers, json={
            "name": network2_name,
            "driver": "bridge",
            "subnet": "172.31.0.0/24",
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create network2 failed: {data}"
    
        container_name = f"test_move_{int(time.time())}"
        r = await self._client.post("/containers/create", headers=self._headers, json={
            "image": self.image,
            "name": container_name,
            "network": self._network_name,
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create container failed: {data}"
    
        r = await self._client.post(
            "/network/move",
            headers=self._headers,
            json={
                "container_name": container_name,
                "source_network": self._network_name,
                "destination_network": network2_name,
                "force": False,
            }
        )
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is False, f"Should have failed, got {data}"
        assert "Dernier réseau" in data.get("message", ""), f"Expected 'Dernier réseau', got {data}"
        return data
    
    async def test_network_move_force(self) -> Dict:
        """Test POST /network/move avec force=true."""
        network2_name = f"test_network2_force_{int(time.time())}"
        r = await self._client.post("/network/create", headers=self._headers, json={
            "name": network2_name,
            "driver": "bridge",
            "subnet": "172.31.0.0/24",
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create network2 failed: {data}"
    
        container_name = f"test_move_force_{int(time.time())}"
        r = await self._client.post("/containers/create", headers=self._headers, json={
            "image": self.image,
            "name": container_name,
            "network": self._network_name,
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create container failed: {data}"
    
        r = await self._client.post(
            "/network/move",
            headers=self._headers,
            json={
                "container_name": container_name,
                "source_network": self._network_name,
                "destination_network": network2_name,
                "force": True,
            }
        )
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Move with force failed: {data}"
        assert data.get("destination_network") == network2_name, f"Destination network mismatch: {data}"
        return data

    async def test_network_move_invalid_source(self) -> Dict:
        """Test POST /network/move avec source invalide."""
        container_name = f"test_move_invalid_{int(time.time())}"
        r = await self._client.post("/containers/create", headers=self._headers, json={
            "image": self.image,
            "name": container_name,
            "network": "bridge",
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create container failed: {data}"

        r = await self._client.post(
            "/network/move",
            headers=self._headers,
            json={
                "container_name": container_name,
                "source_network": "reseau_inexistant",
                "destination_network": self._network_name,
            }
        )
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is False, f"Should have failed, got {data}"
        assert "introuvable" in data.get("message", "") or "non connecté" in data.get("message", ""), f"Expected error, got {data}"
        return data

    async def test_network_remove(self) -> Dict:
        """Test POST /network/{name}/remove."""
        # Créer un réseau vide
        network_to_remove = f"test_remove_{int(time.time())}"
        r = await self._client.post("/network/create", headers=self._headers, json={
            "name": network_to_remove,
            "driver": "bridge",
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create network failed: {data}"

        # Supprimer
        r = await self._client.post(f"/network/{network_to_remove}/remove", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Remove failed: {data}"
        return data

    async def test_network_remove_with_containers_no_force(self) -> Dict:
        """Test POST /network/{name}/remove sans force avec containers."""
        network_with_containers = f"test_with_containers_{int(time.time())}"
        r = await self._client.post("/network/create", headers=self._headers, json={
            "name": network_with_containers,
            "driver": "bridge",
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create network failed: {data}"

        # Créer un container sur ce réseau
        r = await self._client.post("/containers/create", headers=self._headers, json={
            "image": self.image,
            "name": f"container_on_{network_with_containers}",
            "network": network_with_containers,
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create container failed: {data}"

        # Tentative de suppression sans force
        r = await self._client.post(f"/network/{network_with_containers}/remove", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is False, f"Should have failed, got {data}"
        assert "container" in data.get("message", "").lower(), f"Expected container error, got {data}"
        return data

    async def test_network_remove_with_containers_force(self) -> Dict:
        """Test POST /network/{name}/remove avec force=true."""
        network_with_containers = f"test_force_remove_{int(time.time())}"
        r = await self._client.post("/network/create", headers=self._headers, json={
            "name": network_with_containers,
            "driver": "bridge",
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create network failed: {data}"

        # Créer un container sur ce réseau
        r = await self._client.post("/containers/create", headers=self._headers, json={
            "image": self.image,
            "name": f"container_force_{network_with_containers}",
            "network": network_with_containers,
        })
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Create container failed: {data}"

        # Suppression avec force
        r = await self._client.post(f"/network/{network_with_containers}/remove?force=true", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert data.get("success") is True, f"Remove with force failed: {data}"
        return data

    # ─── Tests Simulation ────────────────────────────────────────────────────

    async def test_sim_start(self, mode: str = "auto") -> str:
        r = await self._client.post(
            "/sim/start",
            headers=self._headers,
            json={
                "image": self.image,
                "mode": mode,
                "use_llm": False,
                "authorize_network": False,
                "network_caps": False,
            },
        )
        r.raise_for_status()
        data = r.json()
        session_id = data.get("session_id")
        assert session_id, f"No session_id in {data}"
        return session_id

    async def test_sim_start_with_container(self, container_name: str) -> str:
        r = await self._client.post(
            "/sim/start",
            headers=self._headers,
            json={
                "image": self.image,
                "mode": "auto",
                "container_name": container_name,
                "use_llm": False,
            },
        )
        r.raise_for_status()
        data = r.json()
        session_id = data.get("session_id")
        assert session_id, f"No session_id in {data}"
        return session_id

    async def test_sim_status(self, session_id: str) -> Dict:
        r = await self._client.get(f"/sim/{session_id}/status", headers=self._headers)
        r.raise_for_status()
        return r.json()

    async def test_sim_list(self) -> List[Dict]:
        r = await self._client.get("/sim/list", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert "sims" in data, f"No 'sims' key in {data}"
        return data["sims"]

    async def test_sim_report(self, session_id: str) -> Dict:
        r = await self._client.get(f"/sim/{session_id}/report", headers=self._headers)
        r.raise_for_status()
        return r.json()

    async def test_sim_actions(self, session_id: str) -> Dict:
        r = await self._client.get(f"/sim/{session_id}/actions", headers=self._headers)
        if r.status_code == 409:
            raise AssertionError("Actions route only available in interactive mode")
        r.raise_for_status()
        return r.json()

    async def test_sim_stop(self, session_id: str) -> Dict:
        r = await self._client.post(f"/sim/{session_id}/stop", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert data.get("status") == "stopped", f"Expected stopped, got {data}"
        return data

    async def test_history_list(self) -> List[Dict]:
        r = await self._client.get("/sim/history", headers=self._headers)
        r.raise_for_status()
        data = r.json()
        assert "history" in data, f"No 'history' key in {data}"
        return data["history"]

    async def test_history_detail(self, session_id: str) -> Dict:
        r = await self._client.get(f"/sim/history/{session_id}", headers=self._headers)
        r.raise_for_status()
        return r.json()

    async def test_ws_follow_auto(self, session_id: str, timeout: float = 180.0) -> Dict:
        url = f"{self.ws_base_url}/{session_id}?token={self._token}"
        last_msg: Dict = {}

        try:
            async with websockets.connect(url) as ws:
                deadline = time.monotonic() + timeout
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
                    task = progress.add_task("📡 Suivi WS...", total=None)

                    while time.monotonic() < deadline:
                        try:
                            remaining = deadline - time.monotonic()
                            raw = await asyncio.wait_for(ws.recv(), timeout=min(remaining, 5.0))
                        except asyncio.TimeoutError:
                            continue

                        msg = json.loads(raw)
                        last_msg = msg
                        msg_type = msg.get("type", "?")

                        if msg_type == "step_start":
                            progress.update(task, description=f"📡 {msg.get('step')} — démarré")
                        elif msg_type == "step_progress":
                            progress.update(task, description=f"📡 {msg.get('step')} — {msg.get('message', '')}")
                        elif msg_type == "sim_finished":
                            progress.update(task, description="✅ Simulation terminée")
                            break
                        elif msg_type == "error":
                            progress.update(task, description=f"❌ Erreur: {msg.get('message', '')}")
                            break

        except websockets.exceptions.ConnectionClosed:
            pass

        assert last_msg, "Aucun message reçu sur le WS"
        return last_msg

    # ─── Run ──────────────────────────────────────────────────────────────────

    async def run(self) -> TestSuiteResult:
        self.results.start_time = time.monotonic()

        console.print()
        console.print(Panel.fit(
            Text("🛡  ShieldAI — Smoke Test", justify="center", style="bold cyan"),
            border_style="cyan",
            padding=(1, 4),
        ))
        console.print()

        async with httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout) as client:
            self._client = client

            # ─── Auth ──────────────────────────────────────────────────────────
            console.print("[bold cyan]── Auth ──────────────────────────────────────────────────[/bold cyan]")
            self._token = await self._run_test("POST /auth/login", self.test_login())
            if not self._token:
                console.print("\n[red]❌ Login échoué, impossible de continuer.[/red]")
                self.results.end_time = time.monotonic()
                return self.results

            self._headers = {"Authorization": f"Bearer {self._token}"}

            # ─── Images ────────────────────────────────────────────────────────
            console.print("\n[bold cyan]── Images ─────────────────────────────────────────────[/bold cyan]")
            images = await self._run_test("GET /images/list", self.test_images_list())
            if images:
                console.print(f"  [dim]Images trouvées: {len(images)}[/dim]")

            # ─── Services ──────────────────────────────────────────────────────
            console.print("\n[bold cyan]── Services ───────────────────────────────────────────[/bold cyan]")
            services = await self._run_test("GET /services/capture", self.test_services_capture())
            if services:
                await self._run_test("POST /services/validate", self.test_services_validate(services))

            # ─── Clone ─────────────────────────────────────────────────────────
            console.print("\n[bold cyan]── Clone ──────────────────────────────────────────────[/bold cyan]")
            if self.with_clone:
                await self._run_test("POST /clone/start (+ poll)", self.test_clone_flow(self.clone_src))
                clone_id = await self._run_test("POST /clone/start (pour stop)", self.test_clone_start(self.clone_src))
                if clone_id:
                    await asyncio.sleep(0.5)
                    await self._run_test("POST /clone/{id}/stop", self.test_clone_stop(clone_id))
            else:
                console.print("  [dim]⏭️  Clone skipped (--with-clone non fourni)[/dim]")

            # ─── Containers ─────────────────────────────────────────────────────
            console.print("\n[bold cyan]── Containers ─────────────────────────────────────────[/bold cyan]")
            await self._run_test("GET /containers/list", self.test_containers_list())

            container_name = await self._run_test("POST /containers/create", self.test_container_create())
            if container_name:
                await self._run_test("POST /containers/{name}/exec", self.test_container_exec(container_name))
                await self._run_test("POST /containers/{name}/stop", self.test_container_stop(container_name))

            await self._run_test("POST /containers/create (réseau invalide)", self.test_container_create_invalid_network())
            await self._run_test("GET /containers/cache", self.test_containers_cache())

            # ─── Network ───────────────────────────────────────────────────────
            console.print("\n[bold cyan]── Network ────────────────────────────────────────────[/bold cyan]")
            await self._run_test("GET /network/list", self.test_network_list())

            network_name = await self._run_test("POST /network/create", self.test_network_create())
            if network_name:
                await self._run_test("POST /network/create (duplicate)", self.test_network_create_duplicate())
                # await self._run_test("POST /network/create (subnet invalide)", self.test_network_create_invalid_subnet())
                await self._run_test("GET /network/{name}/containers", self.test_network_containers())
                await self._run_test("GET /network/inexistant/containers", self.test_network_containers_not_found())

                # Connect / Disconnect / Move
                await self._run_test("POST /network/{name}/connect", self.test_network_connect())
                await self._run_test("POST /network/{name}/connect (already)", self.test_network_connect_already())
                await self._run_test("POST /network/{name}/disconnect (force)", self.test_network_disconnect_force())
                await self._run_test("POST /network/{name}/disconnect (no force)", self.test_network_disconnect_no_force())
                await self._run_test("POST /network/{name}/disconnect (not connected)", self.test_network_disconnect_not_connected())
                await self._run_test("POST /network/move (force)", self.test_network_move_force())
                await self._run_test("POST /network/move (no force)", self.test_network_move_no_force())
                await self._run_test("POST /network/move (invalid source)", self.test_network_move_invalid_source())

                # Remove
                await self._run_test("POST /network/{name}/remove", self.test_network_remove())
                await self._run_test("POST /network/{name}/remove (with containers, no force)", self.test_network_remove_with_containers_no_force())
                await self._run_test("POST /network/{name}/remove (with containers, force)", self.test_network_remove_with_containers_force())

            # ─── Simulation AUTO ──────────────────────────────────────────────
            console.print("\n[bold cyan]── Simulation (mode auto) ────────────────────────────[/bold cyan]")
            session_id = await self._run_test("POST /sim/start (auto)", self.test_sim_start(mode="auto"))

            if session_id:
                await self._run_test("GET /sim/{id}/status", self.test_sim_status(session_id))
                await self._run_test("GET /sim/list", self.test_sim_list())

                console.print("  [dim]📡 Connexion WS en cours (peut prendre du temps)...[/dim]")
                await self._run_test("WS /ws/{id} (suivi auto)", self.test_ws_follow_auto(session_id))

                await self._run_test("GET /sim/{id}/report", self.test_sim_report(session_id))
                await self._run_test("GET /sim/history", self.test_history_list())
                await self._run_test("GET /sim/history/{id}", self.test_history_detail(session_id))

                await self._run_test("GET /sim/{id}/actions (auto)", self.test_sim_actions(session_id))

            # ─── Simulation avec container existant ──────────────────────────
            if container_name:
                console.print("\n[bold cyan]── Simulation avec container existant ───────────────[/bold cyan]")
                session_id_container = await self._run_test(
                    "POST /sim/start (container existant)",
                    self.test_sim_start_with_container(container_name),
                )
                if session_id_container:
                    await self._run_test(
                        "POST /sim/{id}/stop (container)",
                        self.test_sim_stop(session_id_container),
                    )

            # ─── Simulation STOP ──────────────────────────────────────────────
            console.print("\n[bold cyan]── Simulation (stop en plein vol) ────────────────────[/bold cyan]")
            session_id_2 = await self._run_test("POST /sim/start (pour stop)", self.test_sim_start(mode="auto"))
            if session_id_2:
                await asyncio.sleep(2)
                await self._run_test("POST /sim/{id}/stop", self.test_sim_stop(session_id_2))

            # ─── Simulation INTERACTIVE ──────────────────────────────────────
            if self.interactive:
                console.print("\n[bold cyan]── Simulation (mode interactive) ─────────────────────[/bold cyan]")
                session_id_3 = await self._run_test(
                    "POST /sim/start (interactive)",
                    self.test_sim_start(mode="interactive"),
                )
                if session_id_3:
                    await self._run_test(
                        "GET /sim/{id}/actions (interactive)",
                        self.test_sim_actions(session_id_3),
                    )
                    await self._run_test(
                        "POST /sim/{id}/stop (cleanup)",
                        self.test_sim_stop(session_id_3),
                    )

            # ─── Cleanup : supprimer les réseaux de test ─────────────────────
            console.print("\n[bold cyan]── Cleanup ─────────────────────────────────────────────[/bold cyan]")
            await self._run_test("POST /network/remove_all (cleanup)", self._cleanup_networks())

        self.results.end_time = time.monotonic()
        return self.results

    async def _cleanup_networks(self) -> Dict:
        """Nettoyage : supprimer tous les réseaux simatk créés par le test."""
        r = await self._client.post("/network/remove_all?force=true", headers=self._headers)
        r.raise_for_status()
        return r.json()


# ─────────────────────────────────────────────────────────────────────────────
# Affichage des résultats
# ─────────────────────────────────────────────────────────────────────────────

def display_results(results: TestSuiteResult) -> None:
    console.print()
    console.print(Rule("[bold cyan]📊 Résultats des tests[/bold cyan]"))

    stats_table = Table(title="Statistiques", box=box.ROUNDED, border_style="cyan")
    stats_table.add_column("Métrique", style="bold cyan")
    stats_table.add_column("Valeur", style="white")

    stats_table.add_row("Total", str(results.total))
    stats_table.add_row("✅ Passés", f"[green]{results.passed}[/green]")
    stats_table.add_row("❌ Échecs", f"[red]{results.failed}[/red]" if results.failed else "[dim]0[/dim]")
    stats_table.add_row("⏭️ Ignorés", f"[yellow]{results.skipped}[/yellow]" if results.skipped else "[dim]0[/dim]")
    stats_table.add_row("💥 Erreurs", f"[red]{results.errors}[/red]" if results.errors else "[dim]0[/dim]")
    stats_table.add_row("Taux de succès", f"{results.success_rate:.1f}%")
    stats_table.add_row("Durée", f"{results.duration:.2f}s")

    console.print(stats_table)

    if results.results:
        detail_table = Table(title="Détail des tests", box=box.ROUNDED, border_style="blue", show_lines=True)
        detail_table.add_column("Status", style="bold", width=4)
        detail_table.add_column("Test", style="bold cyan", no_wrap=False)
        detail_table.add_column("Message", style="white")
        detail_table.add_column("Durée", style="dim", width=10)

        for r in results.results:
            icon = {
                TestStatus.PASSED: "✅",
                TestStatus.FAILED: "❌",
                TestStatus.SKIPPED: "⏭️",
                TestStatus.ERROR: "💥",
            }.get(r.status, "❓")

            color = {
                TestStatus.PASSED: "green",
                TestStatus.FAILED: "red",
                TestStatus.SKIPPED: "yellow",
                TestStatus.ERROR: "red",
            }.get(r.status, "white")

            detail_table.add_row(icon, r.name, f"[{color}]{r.message}[/{color}]", f"{r.duration:.2f}s" if r.duration > 0 else "—")

        console.print(detail_table)

    failures = results.get_failures()
    if failures:
        console.print()
        console.print(Rule("[bold red]❌ Échecs détaillés[/bold red]"))
        for i, r in enumerate(failures, 1):
            console.print(Panel(
                Text(f"{i}. {r.name}", style="bold red"),
                subtitle=f"Message: {r.message}",
                border_style="red",
                padding=(1, 2),
            ))

    console.print()
    if results.failed == 0 and results.errors == 0:
        console.print(Panel.fit("🎉 Tous les tests sont passés !", style="bold green", border_style="green"))
    else:
        console.print(Panel.fit(
            f"⚠️  {results.failed + results.errors} test(s) en échec",
            style="bold yellow",
            border_style="yellow",
        ))

    console.print()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000/api")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--image", required=True, help="Image Docker pour la simulation")
    parser.add_argument("--with-clone", action="store_true", help="Teste aussi le clonage (lourd)")
    parser.add_argument("--clone-src", default=None, help="Répertoire source pour le clonage")
    parser.add_argument("--interactive", action="store_true", help="Teste aussi le mode interactif")
    parser.add_argument("--timeout", type=float, default=30.0, help="Timeout pour les requêtes HTTP")
    args = parser.parse_args()

    if args.with_clone and not args.clone_src:
        console.print("[yellow]⚠️  --clone-src non spécifié, clonage avec src par défaut[/yellow]")

    runner = TestRunner(
        base_url=args.base_url,
        username=args.username,
        password=args.password,
        image=args.image,
        with_clone=args.with_clone,
        clone_src=args.clone_src,
        interactive=args.interactive,
        timeout=args.timeout,
    )

    try:
        results = await runner.run()
        display_results(results)
        return 1 if results.failed > 0 or results.errors > 0 else 0

    except KeyboardInterrupt:
        console.print("\n[yellow]⏹️  Interruption par l'utilisateur[/yellow]")
        return 130

    except Exception as e:
        console.print(f"[red]❌ Erreur inattendue: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))