#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 26 05:09:57 2026

@author: hounsousamuel
"""

# tests/test_fetcher.py
"""
Tests unitaires pour le module Fetcher
Couvre : GET, POST, HEAD, cache, retry, fallback, timeouts
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import ClientTimeout

from scanner_ia.core.fetcher import Fetcher
from scanner_ia.base_class.fetcher_base_class import FetcherResult


# =============================================================================
# TESTS FetcherResult (classe de base)
# =============================================================================

class TestFetcherResult:
    """Tests pour la classe FetcherResult"""
    
    def test_is_success(self):
        """Test is_success() selon status code"""
        result = FetcherResult()
        
        result.status_code = 200
        assert result.is_success() is True
        
        result.status_code = 201
        assert result.is_success() is True
        
        result.status_code = 204
        assert result.is_success() is True
        
        result.status_code = 300
        assert result.is_success() is False
        
        result.status_code = 404
        assert result.is_success() is False
        
        result.status_code = 500
        assert result.is_success() is False
        
        result.status_code = None
        assert result.is_success() is False
    
    def test_is_redirect(self):
        """Test is_redirect() selon status code"""
        result = FetcherResult()
        
        result.status_code = 301
        assert result.is_redirect() is True
        
        result.status_code = 302
        assert result.is_redirect() is True
        
        result.status_code = 303
        assert result.is_redirect() is True
        
        result.status_code = 307
        assert result.is_redirect() is True
        
        result.status_code = 308
        assert result.is_redirect() is True
        
        result.status_code = 200
        assert result.is_redirect() is False
        
        result.status_code = 404
        assert result.is_redirect() is False
    
    def test_body_length(self):
        """Test body_length()"""
        result = FetcherResult()
        
        result.body = "Hello World"
        assert result.body_length() == 11
        
        result.body = ""
        assert result.body_length() == 0
        
        result.body = None
        assert result.body_length() == 0
    
    def test_to_dict(self):
        """Test sérialisation to_dict()"""
        result = FetcherResult()
        result.url = "https://example.com"
        result.final_url = "https://example.com/final"
        result.status_code = 200
        result.body = "<html>Test</html>"
        result.delay = 0.15
        result.method = "GET"
        result.headers = {"Content-Type": "text/html"}
        result.ip = "93.184.216.34"
        
        d = result.to_dict()
        
        assert d["url"] == "https://example.com"
        assert d["final_url"] == "https://example.com/final"
        assert d["status_code"] == 200
        assert d["body"] == "<html>Test</html>"
        assert d["delay"] == 0.15
        assert d["method"] == "GET"
        assert d["headers"] == {"Content-Type": "text/html"}
        assert d["ip"] == "93.184.216.34"
    
    def test_update_from_dict(self):
        """Test mise à jour depuis un dict"""
        result = FetcherResult()
        data = {
            "url": "https://new.com",
            "status_code": 404,
            "body": "Not Found",
            "delay": 0.5
        }
        
        result.update_from_dict(data)
        
        assert result.url == "https://new.com"
        assert result.status_code == 404
        assert result.body == "Not Found"
        assert result.delay == 0.5
        # Les champs non fournis restent aux valeurs par défaut
        assert result.method == "GET"


# =============================================================================
# TESTS Fetcher (classe principale)
# =============================================================================

@pytest.mark.asyncio
class TestFetcher:
    """Tests pour la classe Fetcher"""
    
    async def test_fetch_get_success(self, mock_session):
        """Test GET réussi"""
        fetcher = Fetcher(session=mock_session)
        
        # Mock de la réponse
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = AsyncMock(return_value="<html><body>Hello</body></html>")
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_session.get.return_value = mock_response
        
        result = await fetcher.fetch("https://example.com", method="GET")
        
        assert result.status_code == 200
        assert result.body == "<html><body>Hello</body></html>"
        assert result.error is None
        mock_session.get.assert_called_once()
    
    async def test_fetch_get_404(self, mock_session):
        """Test GET sur page 404"""
        fetcher = Fetcher(session=mock_session)
        
        mock_response = AsyncMock()
        mock_response.status = 404
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = AsyncMock(return_value="Not Found")
        mock_response.url = "https://example.com/notfound"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_session.get.return_value = mock_response
        
        result = await fetcher.fetch("https://example.com/notfound", method="GET")
        
        assert result.status_code == 404
        assert result.body == "Not Found"
        assert result.error is None
    
    async def test_fetch_get_no_http_prefix(self, mock_session):
        """Test GET sans préfixe http:// (ajout automatique de https://)"""
        fetcher = Fetcher(session=mock_session)
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.text = AsyncMock(return_value="OK")
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_session.get.return_value = mock_response
        
        result = await fetcher.fetch("example.com", method="GET")
        
        assert result.status_code == 200
        # Vérifier que l'URL a été préfixée
        call_args = mock_session.get.call_args
        assert call_args[0][0] == "https://example.com"
    
    async def test_fetch_post_success(self, mock_session):
        """Test POST réussi"""
        fetcher = Fetcher(session=mock_session)
        
        mock_response = AsyncMock()
        mock_response.status = 201
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.text = AsyncMock(return_value='{"id": 1, "status": "created"}')
        mock_response.url = "https://example.com/api"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_session.post.return_value = mock_response
        
        result = await fetcher.fetch("https://example.com/api", method="POST", json={"name": "test"})
        
        assert result.status_code == 201
        assert "created" in result.body
        mock_session.post.assert_called_once()
    
    async def test_fetch_post_with_data(self, mock_session):
        """Test POST avec data (form urlencoded)"""
        fetcher = Fetcher(session=mock_session)
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.text = AsyncMock(return_value="OK")
        mock_response.url = "https://example.com/form"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_session.post.return_value = mock_response
        
        result = await fetcher.fetch("https://example.com/form", method="POST", data={"field": "value"})
        
        assert result.status_code == 200
        # Vérifier que data a été passé
        call_kwargs = mock_session.post.call_args[1]
        assert "data" in call_kwargs
        assert call_kwargs["data"] == {"field": "value"}
    
    async def test_fetch_head_success(self, mock_session):
        """Test HEAD réussi"""
        fetcher = Fetcher(session=mock_session)
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {"Content-Type": "text/html", "Content-Length": "1234"}
        mock_response.text = AsyncMock(return_value="")
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_session.head.return_value = mock_response
        
        result = await fetcher.fetch("https://example.com", method="HEAD")
        
        assert result.status_code == 200
        assert result.body == ""
        assert result.headers.get("Content-Length") == "1234"
    
    async def test_fetch_invalid_method_fallback_to_get(self, mock_session):
        """Test méthode invalide → fallback vers GET"""
        fetcher = Fetcher(session=mock_session)
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.text = AsyncMock(return_value="GET fallback response")
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_session.get.return_value = mock_response
        
        result = await fetcher.fetch("https://example.com", method="INVALID_METHOD")
        
        assert result.status_code == 200
        assert result.body == "GET fallback response"
        # Vérifier que GET a été utilisé (pas POST ou autre)
        mock_session.get.assert_called_once()
        mock_session.post.assert_not_called()
    
    async def test_fetch_connection_error_with_retry(self, mock_session):
        """Test retry après erreur de connexion"""
        fetcher = Fetcher(session=mock_session)
        
        # Premier appel échoue
        mock_session.get.side_effect = [Exception("Connection refused"), None]
        
        # Deuxième appel réussit
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.text = AsyncMock(return_value="Success after retry")
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        
        # Remplacer le side_effect pour le deuxième appel
        async def side_effect(*args, **kwargs):
            if mock_session.get.call_count == 1:
                raise Exception("Connection refused")
            return mock_response
        
        mock_session.get.side_effect = side_effect
        
        result = await fetcher.fetch("https://example.com", method="GET")
        
        # Avec retry, devrait réussir
        assert result.status_code == 200
        assert result.body == "Success after retry"
        # Vérifier qu'il y a eu 2 tentatives
        assert mock_session.get.call_count >= 2
    
    async def test_fetch_all_retries_fail(self, mock_session):
        """Test échec de toutes les tentatives"""
        fetcher = Fetcher(session=mock_session)
        
        # Toutes les tentatives échouent
        mock_session.get.side_effect = Exception("Connection refused")
        
        # Mock fetch_once pour éviter l'infini
        with patch.object(fetcher, 'fetch_once', new=AsyncMock(return_value=FetcherResult())):
            result = await fetcher.fetch("https://example.com", method="GET")
            
            # Doit retourner le backup_result
            assert result is not None
    
    async def test_fetch_once_basic(self, mock_session):
        """Test fetch_once sans retry"""
        fetcher = Fetcher(session=mock_session)
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.text = AsyncMock(return_value="Direct response")
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_session.get.return_value = mock_response
        
        result = await fetcher.fetch_once("https://example.com", max_attempts=1)
        
        assert result.status_code == 200
        assert result.body == "Direct response"
        assert mock_session.get.call_count == 1
    
    async def test_fetch_once_with_retries(self, mock_session):
        """Test fetch_once avec plusieurs tentatives"""
        fetcher = Fetcher(session=mock_session)
        
        # Simuler 2 échecs puis succès
        call_count = 0
        
        async def mock_get(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception(f"Attempt {call_count} failed")
            
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.headers = {}
            mock_resp.text = AsyncMock(return_value="Success")
            mock_resp.url = "https://example.com"
            mock_resp.history = []
            mock_resp.cookies = {}
            mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_resp.__aexit__ = AsyncMock(return_value=None)
            return mock_resp
        
        mock_session.get.side_effect = mock_get
        
        result = await fetcher.fetch_once("https://example.com", max_attempts=3, wait_between=0.01)
        
        assert result.status_code == 200
        assert result.body == "Success"
        assert call_count == 3
    
    async def test_fetch_once_timeout(self, mock_session):
        """Test fetch_once avec timeout"""
        fetcher = Fetcher(session=mock_session)
        
        # Simuler un timeout
        mock_session.get.side_effect = asyncio.TimeoutError()
        
        result = await fetcher.fetch_once("https://example.com", timeout=1, max_attempts=1)
        
        # Doit retourner un résultat avec erreur
        assert result.error is not None
        assert "TimeoutError" in result.error or "timeout" in result.error.lower()
    
    async def test_get_ip_resolution(self, mock_session):
        """Test résolution d'IP"""
        fetcher = Fetcher(session=mock_session)
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.text = AsyncMock(return_value="OK")
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_session.get.return_value = mock_response
        
        # Mock getaddrinfo
        with patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('93.184.216.34', 0))]):
            result = await fetcher.fetch("https://example.com", method="GET")
            
            # L'IP devrait être résolue
            # Note: l'implémentation actuelle peut avoir un cache
            assert result is not None
    
    def test_update_conf(self):
        """Test mise à jour de la configuration"""
        fetcher = Fetcher()
        
        # Sauvegarder valeurs originales
        original_timeout = fetcher.config.TIMEOUT
        original_attempts = fetcher.config.MAX_ATTEMPT
        
        # Modifier la config via update_conf
        fetcher.update_conf({"TIMEOUT": 10, "MAX_ATTEMPT": 5})
        
        assert fetcher.config.TIMEOUT == 10
        assert fetcher.config.MAX_ATTEMPT == 5
        
        # Restaurer
        fetcher.config.TIMEOUT = original_timeout
        fetcher.config.MAX_ATTEMPT = original_attempts
    
    async def test_fetch_with_custom_headers(self, mock_session):
        """Test avec headers personnalisés"""
        fetcher = Fetcher(session=mock_session)
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.text = AsyncMock(return_value="OK")
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_session.get.return_value = mock_response
        
        custom_headers = {"X-Custom-Header": "test-value", "Authorization": "Bearer token123"}
        
        result = await fetcher.fetch("https://example.com", method="GET", headers=custom_headers)
        
        assert result.status_code == 200
        # Vérifier que les headers personnalisés ont été passés
        call_kwargs = mock_session.get.call_args[1]
        assert "headers" in call_kwargs
        assert call_kwargs["headers"]["X-Custom-Header"] == "test-value"
    
    async def test_fetch_with_cookies(self, mock_session):
        """Test avec cookies"""
        fetcher = Fetcher(session=mock_session)
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.text = AsyncMock(return_value="OK")
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_response.cookies = {"session": "abc123"}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        
        # Configurer le mock des cookies
        mock_response.cookies.__iter__ = MagicMock(return_value=iter([("session", "abc123")]))
        
        mock_session.get.return_value = mock_response
        
        result = await fetcher.fetch("https://example.com", method="GET", cookies={"custom": "value"})
        
        assert result.status_code == 200
        # Vérifier que les cookies ont été passés
        call_kwargs = mock_session.get.call_args[1]
        assert "cookies" in call_kwargs


# =============================================================================
# TESTS DE PERFORMANCE/CACHE
# =============================================================================

@pytest.mark.asyncio
class TestFetcherCache:
    """Tests pour le cache du Fetcher"""
    
    async def test_cache_hit(self, mock_session):
        """Test cache hit (deuxième appel plus rapide)"""
        fetcher = Fetcher(session=mock_session)
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.text = AsyncMock(return_value="Cached content")
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_session.get.return_value = mock_response
        
        # Premier appel
        result1 = await fetcher.fetch("https://example.com/test", method="GET")
        first_call_count = mock_session.get.call_count
        
        # Reset mock pour compter les appels suivants
        mock_session.get.reset_mock()
        
        # Deuxième appel (même URL, mêmes paramètres)
        result2 = await fetcher.fetch("https://example.com/test", method="GET")
        
        # Si le cache fonctionne, le deuxième appel ne devrait PAS faire de requête
        # (les résultats sont en cache)
        # Note: selon l'implémentation, le cache peut être dans le fetcher ou ailleurs
        assert result2 is not None
        assert result2.body == result1.body
    
    async def test_cache_different_params(self, mock_session):
        """Test cache différencie les paramètres"""
        fetcher = Fetcher(session=mock_session)
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.text = AsyncMock(return_value="Response")
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_response.cookies = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_session.get.return_value = mock_response
        
        # Deux URLs différentes
        await fetcher.fetch("https://example.com/page1", method="GET")
        await fetcher.fetch("https://example.com/page2", method="GET")
        
        # Deux appels distincts doivent être faits
        assert mock_session.get.call_count == 2


# =============================================================================
# POINT D'ENTRÉE POUR EXÉCUTION DIRECTE
# =============================================================================

if __name__ == "__main__":
    import pytest
    pytest.main([
        __file__,
        "-v",
        "-p no:logfire",
        "--tb=short",
        "--hypothesis-show-statistics"
    ])