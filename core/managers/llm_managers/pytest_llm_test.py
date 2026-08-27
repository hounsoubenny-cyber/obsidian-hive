#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jul  2 08:55:11 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suite de tests pour LLMManager (ShieldAI / ObsidianHive).

Prérequis :
    pip install pytest pytest-asyncio python-dotenv --break-system-packages

.env attendu à la racine du projet (JAMAIS commité, dans .gitignore) :
    GROQ_API_KEY_1=gsk_...
    GROQ_API_KEY_2=gsk_...
    GROQ_API_KEY_3=gsk_...

Lancement :
    pytest test_llm_manager.py -v -s
"""
import os, sys
# sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", "..", ".."))))
import asyncio
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from dotenv import load_dotenv

load_dotenv()

# Adapte cet import à ton arborescence réelle
from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager  # noqa

GROQ_MODEL = "llama-3.3-70b-versatile"

GROQ_KEYS = [
    os.environ.get("GROQ_API_KEY_1"),
    os.environ.get("GROQ_API_KEY_2"),
    os.environ.get("GROQ_API_KEY_3"),
]

pytestmark = pytest.mark.asyncio


def _skip_if_no_keys():
    if not all(GROQ_KEYS):
        pytest.skip("GROQ_API_KEY_1/2/3 manquantes dans .env — tests réels ignorés")


# ─────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def dummy_local_server_path(tmp_path):
    """
    Contourne l'exigence os.path.exists(llama_server_path) même quand
    on ne teste que des providers cloud. Crée un faux binaire vide.
    À terme : rendre llama_server_path optionnel si aucune paire
    api_keys n'a le préfixe 'local'.
    """
    fake_binary = tmp_path / "fake_llama_server"
    fake_binary.write_text("#!/bin/sh\necho fake\n")
    fake_binary.chmod(0o755)
    return str(fake_binary)


@pytest.fixture
def groq_api_keys():
    _skip_if_no_keys()
    return [(GROQ_MODEL, k) for k in GROQ_KEYS]


@pytest_asyncio.fixture
async def manager(dummy_local_server_path, groq_api_keys, unused_tcp_port):
    mgr = LLMManager(
        llama_server_path=dummy_local_server_path,
        port=unused_tcp_port,
        api_keys=groq_api_keys,
        sync=False,
    )
    yield mgr
    if mgr._server_process is not None:
        mgr.stop_server()


# ─────────────────────────────────────────────────────────────
# 1. Validation à l'init — fail-fast strict
# ─────────────────────────────────────────────────────────────

async def test_init_fails_fast_on_invalid_model(dummy_local_server_path, unused_tcp_port):
    """Une paire (model_name invalide, clé valide) doit lever à l'instanciation,
    pas au premier appel."""
    _skip_if_no_keys()
    with pytest.raises(ValueError):
        LLMManager(
            llama_server_path=dummy_local_server_path,
            port=unused_tcp_port,
            api_keys=[("modele-qui-nexiste-pas-du-tout", GROQ_KEYS[0])],
            sync=False,
        )


async def test_init_fails_fast_on_invalid_key(dummy_local_server_path, unused_tcp_port):
    """Une clé invalide doit lever à l'instanciation."""
    with pytest.raises(ValueError):
        LLMManager(
            llama_server_path=dummy_local_server_path,
            port=unused_tcp_port,
            api_keys=[(GROQ_MODEL, "gsk_clef_totalement_invalide_000000")],
            sync=False,
        )


async def test_init_rejects_malformed_pairs(dummy_local_server_path, unused_tcp_port):
    """Une paire qui n'est pas (model_name, api_key) de longueur 2 doit lever
    avant même la validation réseau."""
    with pytest.raises(ValueError):
        LLMManager(
            llama_server_path=dummy_local_server_path,
            port=unused_tcp_port,
            api_keys=[(GROQ_MODEL, GROQ_KEYS[0], "trop_dargs")],
            sync=False,
        )

# ─────────────────────────────────────────────────────────────
# 2. Appels réels — bout en bout sur Groq
# ─────────────────────────────────────────────────────────────

async def test_real_call_returns_success(manager):
    result = await manager.call(
        prompt="Réponds uniquement par le mot: PONG",
        system="Tu es un echo bot minimal.",
        max_tokens=10,
        temperature=0.0,
    )
    assert result["success"] is True
    assert result["response"]
    assert "pong" in result["response"].lower()
    print(f"\n[call] Réponse: {result['response']!r} en {result['total_time']:.2f}s")


async def test_real_chat_keeps_history(manager):
    r1 = await manager.chat(
        prompt="Mon prénom est Xavier. Retiens-le.",
        system="Tu es concis.",
        model_name=GROQ_MODEL,
        max_tokens=30,
        temperature=0.0,
    )
    assert r1["success"] is True

    r2 = await manager.chat(
        prompt="Quel est mon prénom ?",
        model_name=GROQ_MODEL,
        max_tokens=30,
        temperature=0.0,
    )
    assert r2["success"] is True
    assert "xavier" in r2["response"].lower()
    assert len(manager.get_history()) >= 4  # system + 2x(user+assistant)


async def test_list_available_models_pool(manager):
    models = await manager.list_available_models()
    assert isinstance(models, list)
    assert len(models) > 0
    assert GROQ_MODEL in models
    print(f"\n[list_available_models] {len(models)} modèles trouvés, ex: {models[:5]}")


# ─────────────────────────────────────────────────────────────
# 3. Clé utilisateur explicite — isolation du pool système
# ─────────────────────────────────────────────────────────────

async def test_user_key_bypasses_pool_without_mutating_it(manager):
    """Passer api_key= explicitement ne doit JAMAIS toucher self._current_api_key
    / self._current_model_name du pool partagé (pas de race condition)."""
    _skip_if_no_keys()

    before_key = manager._current_api_key
    before_model = manager._current_model_name

    result = await manager.run_agent(
        model_name=GROQ_MODEL,
        api_key=GROQ_KEYS[1],
        user="Réponds juste OK",
        max_tokens=5,
        temperature=0.0,
    )

    assert result["success"] is True
    assert manager._current_api_key == before_key, "la clé user a pollué l'état partagé !"
    assert manager._current_model_name == before_model, "le modèle user a pollué l'état partagé !"


async def test_validate_user_key_valid(manager):
    ok, msg = await manager.validate_user_key(
        api_key=GROQ_KEYS[2], model_name=GROQ_MODEL, raise_=False
    )
    assert ok is True, msg


async def test_validate_user_key_invalid_model(manager):
    ok, msg = await manager.validate_user_key(
        api_key=GROQ_KEYS[2], model_name="modele-inexistant-xyz", raise_=False
    )
    assert ok is False
    assert "disponible" in msg.lower() or "not" in msg.lower()


# ─────────────────────────────────────────────────────────────
# 4. Rotation sur rate-limit — MOCKÉ (pas de vrai 429 à la demande)
# ─────────────────────────────────────────────────────────────

async def test_rotation_on_rate_limit_switches_key_and_model(manager):
    """
    Simule un rate-limit sur le premier appel, vérifie que:
    - self._rotate() est appelé
    - le model_name utilisé pour le 2e essai vient bien de la NOUVELLE paire
      (c'est exactement le bug #2 qu'on avait identifié — ne doit plus arriver)
 
    Piège évité ici : _rotate() remplace ENTIÈREMENT self._client par un nouvel
    objet (via _make_client()). Un mock posé seulement sur l'ancien objet
    self._client.chat.completions.create ne survit donc pas à la rotation —
    le 2e essai tape alors le VRAI réseau. On patch donc _make_client lui-même,
    tout en reproduisant sa vraie logique de consommation du pool (next(self._keys)
    + mise à jour _current_api_key/_current_model_name), pour rester 100% offline
    tout en testant le vrai comportement de rotation.
    """
    call_count = {"n": 0}
    seen_models = []
 
    class FakeRateLimitError(Exception):
        def __str__(self):
            return "Error code: 429 - rate_limit_exceeded"
 
    async def fake_create(**kwargs):
        call_count["n"] += 1
        seen_models.append(kwargs.get("model"))
        if call_count["n"] == 1:
            raise FakeRateLimitError()
        choice = MagicMock()
        choice.finish_reason = "stop"
        choice.message.tool_calls = None
        choice.message.content = "ok apres rotation"
        choice.message.reasoning = None
        fake_response = MagicMock()
        fake_response.choices = [choice]
        return fake_response
 
    def fake_client_factory():
        fake_client = MagicMock()
        fake_client.chat.completions.create = fake_create
        return fake_client
 
    model_before_rotation = manager._current_model_name
    key_before_rotation = manager._current_api_key
 
    # Client initial mocké (1er essai, celui qui va "rate-limiter")
    manager._client = fake_client_factory()
 
    def patched_make_client(api_key=None):
        # Reproduit la vraie logique de _make_client pour le cas pool (api_key=None) :
        # on consomme réellement le cycle, donc _current_api_key/_current_model_name
        # évoluent exactement comme en prod — seul le CLIENT retourné est mocké.
        if api_key is None:
            model_name, key = next(manager._keys)
            manager._current_api_key = key
            manager._current_model_name = model_name
        return fake_client_factory()
 
    with patch.object(manager, "_make_client", side_effect=patched_make_client):
        result = await manager.run_agent(
            model_name=model_before_rotation,
            user="test rotation",
            max_retries=2,
        )
 
    assert call_count["n"] == 2, "la rotation n'a pas déclenché de 2e tentative"
    assert result["success"] is True
    assert result["response"] == "ok apres rotation"
    assert manager._current_api_key != key_before_rotation, "la clé n'a pas tourné"
    # Le modèle vu par le CLIENT lors du 2e appel HTTP doit correspondre au
    # _current_model_name mis à jour par la rotation — pas être resté figé
    # sur l'ancien modèle (c'était exactement le bug #2 historique).
    assert seen_models[1] == manager._current_model_name
 
    print(f"\n[rotation] clé avant: {key_before_rotation[:10]}..., après: {manager._current_api_key[:10]}...")
    print(f"[rotation] modèle avant: {model_before_rotation!r}, après: {manager._current_model_name!r}")
    print(f"[rotation] modèles vus par le client à chaque appel: {seen_models}")


async def test_user_key_rate_limit_does_not_rotate(manager):
    """Avec api_key= explicite, un rate-limit doit échouer proprement
    SANS jamais appeler self._rotate() (pas de fallback vers le pool système)."""

    async def fake_create_always_fails(**kwargs):
        raise Exception("Error code: 429 - rate_limit_exceeded")

    with patch.object(manager, "_rotate") as mock_rotate:
        active_client = manager._make_client(api_key=GROQ_KEYS[0])
        active_client.chat.completions.create = fake_create_always_fails

        with patch.object(manager, "_make_client", return_value=active_client):
            result = await manager.run_agent(
                model_name=GROQ_MODEL,
                api_key=GROQ_KEYS[0],
                user="test",
                max_retries=1,
            )

        mock_rotate.assert_not_called()
        assert result["success"] is False


# ─────────────────────────────────────────────────────────────
# 5. Concurrence — le lock protège bien la rotation partagée
# ─────────────────────────────────────────────────────────────

async def test_concurrent_calls_dont_corrupt_shared_state(manager):
    """Lance plusieurs run_agent() en parallèle sur le pool partagé,
    vérifie qu'aucune exception de state incohérent ne remonte."""
    _skip_if_no_keys()

    async def one_call(i):
        return await manager.call(
            prompt=f"Réponds juste le chiffre {i}",
            max_tokens=5,
            temperature=0.0,
        )

    results = await asyncio.gather(*[one_call(i) for i in range(5)], return_exceptions=True)

    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors, f"Exceptions en concurrence: {errors}"
    successes = [r for r in results if not isinstance(r, Exception) and r.get("success")]
    print(f"\n[concurrence] {len(successes)}/5 appels réussis")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v", "-s", "-p no:logfire"]))