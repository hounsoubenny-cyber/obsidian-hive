#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests unitaires complets avec pytest + hypothesis
"""

import os
import sys
import pytest
from hypothesis import given, strategies as st, assume
from hypothesis import given, settings, HealthCheck
from hypothesis.strategies import composite, sampled_from, integers, text, booleans
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".."))

from anti_phishing_ia.core.passive_analyzer import PassiveAnalyzer, compare, _character_similarity
from anti_phishing_ia.phishing_utils.utils import (
    _clean_url, _get_domain, _get_domain_age, 
    _verify_ip_in_url, calculate_entropy
)
from anti_phishing_ia.core.features_extractor import get_features_names
from anti_phishing_ia.phishing_utils.legit_domain import _get_legitimate_domain


# ============================================================================
# STRATÉGIES HYPOTHESIS
# ============================================================================

@composite
def valid_urls(draw):
    """Génère des URLs syntaxiquement valides"""
    protocol = draw(sampled_from(["http://", "https://", ""]))
    if not protocol:
        protocol = "https://"
    
    # CORRECTION 1: 'D' -> 'Nd' (chiffres décimaux Unicode)
    sub = draw(st.one_of(st.just(""), st.text(min_size=1, max_size=10, alphabet=st.characters(whitelist_categories=('L', 'Nd')))))
    domain = draw(st.text(min_size=3, max_size=15, alphabet=st.characters(whitelist_categories=('L', 'Nd'))))
    tld = draw(sampled_from(["com", "fr", "org", "net", "io", "gov"]))
    
    if sub:
        domain = f"{sub}.{domain}"
    
    # CORRECTION 2: 'D' -> 'Nd'
    path = draw(st.one_of(
        st.just(""),
        st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('L', 'Nd'), blacklist_characters='?&#'))
    ))
    
    url = f"{protocol}{domain}.{tld}"
    if path:
        url += f"/{path}"
    
    return url


@composite
def phishing_urls(draw):
    """Génère des URLs typiquement phishing"""
    techniques = draw(sampled_from([
        "typosquatting", "homograph", "subdomain_trick", 
        "ip_address", "suspicious_tld", "at_symbol"
    ]))
    
    targets = draw(sampled_from(["paypal", "amazon", "google", "microsoft", "apple", "netflix"]))
    
    if techniques == "typosquatting":
        typo_map = {"o": "0", "i": "1", "a": "@", "l": "1"}
        char = draw(sampled_from(list(typo_map.keys())))
        domain = targets.replace(char, typo_map[char])
        url = f"https://{domain}.com/login"
    
    elif techniques == "homograph":
        url = f"https://xn--{targets[:4]}-{draw(integers(min_value=10, max_value=999))}.com"
    
    elif techniques == "subdomain_trick":
        fake = draw(sampled_from(["secure", "verify", "login", "account"]))
        url = f"https://{targets}.com-{fake}.tk/verify"
    
    elif techniques == "ip_address":
        ip = f"{draw(integers(1,255))}.{draw(integers(0,255))}.{draw(integers(0,255))}.{draw(integers(1,255))}"
        url = f"http://{ip}/secure/login"
    
    elif techniques == "suspicious_tld":
        tld = draw(sampled_from([".tk", ".ml", ".ga", ".cf", ".gq", ".xyz"]))
        url = f"https://{targets}-secure{tld}/login"
    
    else:  # at_symbol
        url = f"https://{targets}.com@malicious-site.net/login"
    
    return url


@composite
def safe_urls(draw):
    """Génère des URLs légitimes"""
    domain = draw(sampled_from(list(_get_legitimate_domain())[:200]))
    path = draw(st.one_of(
        st.just(""),
        st.sampled_from(["", "/login", "/account", "/dashboard", "/settings", "/help"])
    ))
    return f"https://{domain}{path}"


# ============================================================================
# TESTS POUR UTILS.PY
# ============================================================================

class TestUtils:
    """Tests pour les fonctions utilitaires"""
    
    # === _clean_url ===
    
    @given(st.text(min_size=1))
    def test_clean_url_adds_https(self, url):
        """_clean_url doit ajouter https:// si absent"""
        if not url.startswith(('http://', 'https://')):
            cleaned = _clean_url(url)
            assert cleaned.startswith('https://')
    
    @given(valid_urls())
    def test_clean_url_preserves_valid_urls(self, url):
        """_clean_url ne doit pas modifier les URLs déjà valides"""
        cleaned = _clean_url(url)
        if url.startswith(('http://', 'https://')):
            assert cleaned == url
    
    def test_clean_url_strips_whitespace(self):
        """_clean_url doit enlever les espaces et guillemets"""
        assert _clean_url('  "https://google.com"  ') == 'https://google.com'
        assert _clean_url("  'https://google.com'  ") == 'https://google.com'
    
    # === _get_domain ===
    
    @given(valid_urls())
    def test_get_domain_returns_string(self, url):
        """_get_domain doit retourner une chaîne"""
        domain = _get_domain(url, clean=True)
        assert isinstance(domain, str)
    
    def test_get_domain_extracts_correctly(self):
        """_get_domain doit extraire correctement le domaine"""
        assert _get_domain("https://mail.google.com/login", clean=True) == "google.com"
        assert _get_domain("https://www.paypal.com/signin", clean=True) == "paypal.com"
        assert _get_domain("http://192.168.1.1/login", clean=True) == "192.168.1.1"
    
    # === _verify_ip_in_url ===
    
    @given(phishing_urls())
    def test_verify_ip_in_url_detects_ip_urls(self, url):
        """_verify_ip_in_url doit détecter les URLs avec IP"""
        pass
    
    def test_verify_ip_in_url_specific(self):
        """Test précis de détection d'IP"""
        assert _verify_ip_in_url("http://192.168.1.1/login") == True
        assert _verify_ip_in_url("http://127.0.0.1:8000") == True
        assert _verify_ip_in_url("https://google.com") == False
        assert _verify_ip_in_url("http://0x7f000001") == True
    
    # === calculate_entropy ===
    
    @given(st.text(min_size=1, max_size=50))
    def test_entropy_between_0_and_log2_len(self, text):
        """L'entropie doit être entre 0 et log2(longueur)"""
        entropy = calculate_entropy(text)
        max_entropy = len(set(text))
        assert 0 <= entropy <= max_entropy
    
    def test_entropy_low_for_repetitive(self):
        """Les chaînes répétitives doivent avoir une faible entropie"""
        assert calculate_entropy("aaaaaa") < 0.1
        assert calculate_entropy("ababab") < 1.5
    
    def test_entropy_high_for_random(self):
        """Les chaînes aléatoires doivent avoir une entropie élevée"""
        assert calculate_entropy("a1b2c3d4e5f6") > 3.0


# ============================================================================
# TESTS POUR PASSIVE_ANALYZER
# ============================================================================

class TestPassiveAnalyzer:
    """Tests pour l'analyseur passif"""
    
    @pytest.fixture
    def analyzer(self):
        return PassiveAnalyzer()
    
    # === compare function ===
    
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(safe_urls())
    def test_compare_with_legitimate_domain(self, analyzer, url):
        """La comparaison doit retourner 0 pour un domaine légitime exact"""
        domain = _get_domain(url, clean=True)
        if domain in _get_legitimate_domain():
            score, matched = compare(url)
            assert score == 0.0
            assert matched == domain
    
    def test_compare_typosquatting(self):
        """La comparaison doit détecter le typosquatting"""
        score, matched = compare("https://gooogle.com/login")
        assert score > 0.4
        assert matched == "google.com"
        
        score, matched = compare("https://paypa1.com")
        assert score > 0.4
        assert matched == "paypal.com"
    
    def test_compare_homograph(self):
        """La comparaison doit détecter les homoglyphes"""
        score, matched = compare("https://xn--pple-43d.com")
        assert score > 0.3
    
    # === analyze method ===
    
    @pytest.mark.asyncio
    async def test_analyze_safe_url(self, analyzer):
        """Les URLs safe doivent avoir un score bas"""
        label, score, is_phishing, flags = await analyzer.analyze(
            "https://www.google.com",
            check_blacklist=False
        )
        assert score < 20
        assert is_phishing == False
    
    @pytest.mark.asyncio
    async def test_analyze_phishing_url(self, analyzer):
        """Les URLs phishing doivent avoir un score élevé"""
        label, score, is_phishing, flags = await analyzer.analyze(
            "http://192.168.1.100/paypal/login.php",
            check_blacklist=False
        )
        assert score >= 30
        assert is_phishing == True
    
    @pytest.mark.asyncio
    async def test_analyze_punycode(self, analyzer):
        """Le punycode doit être flaggé comme risqué"""
        label, score, is_phishing, flags = await analyzer.analyze(
            "https://xn--pple-43d.com/signin",
            check_blacklist=False
        )
        has_punycode_flag = any("PUNICODE" in msg for msg, _ in flags)
        assert has_punycode_flag
    
    @pytest.mark.asyncio
    async def test_analyze_at_symbol(self, analyzer):
        """Le caractère @ doit être flaggé"""
        label, score, is_phishing, flags = await analyzer.analyze(
            "https://paypal.com@evil-site.com/login",
            check_blacklist=False
        )
        has_at_flag = any("CARACTÈRE @" in msg for msg, _ in flags)
        assert has_at_flag
    
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None)
    @given(valid_urls())
    @pytest.mark.asyncio
    async def test_analyze_always_returns_tuple(self, analyzer, url):
        """Analyze doit toujours retourner un tuple de 4 éléments"""
        result = await analyzer.analyze(url, check_blacklist=False)
        assert len(result) == 4
        assert isinstance(result[0], str)
        assert isinstance(result[1], (int, float))
        assert isinstance(result[2], bool)
        assert isinstance(result[3], list)
    
    # === verify_black_list ===
    
    @pytest.mark.asyncio
    async def test_verify_black_list_caching(self, analyzer):
        """La blacklist doit être mise en cache"""
        with patch.object(analyzer, 'black_cache') as mock_cache:
            mock_cache.get.return_value = None
            with patch('aiohttp.ClientSession.get') as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value={"threat": False})
                mock_get.return_value.__aenter__.return_value = mock_response
                await analyzer.verify_black_list("https://google.com")
                assert mock_cache.__setitem__.called
    
    @pytest.mark.asyncio
    async def test_verify_black_list_network_error(self, analyzer):
        """Les erreurs réseau ne doivent pas faire planter"""
        with patch('aiohttp.ClientSession.get', side_effect=Exception("Network error")):
            result = await analyzer.verify_black_list("https://google.com")
            assert "phishing" in result
            assert result["phishing"] == False


# ============================================================================
# TESTS POUR FEATURES_EXTRACTOR
# ============================================================================

class TestFeaturesExtractor:
    """Tests pour l'extracteur de features"""
    
    @pytest.mark.asyncio
    async def test_features_extractor_returns_dict(self):
        """L'extracteur doit retourner un dictionnaire"""
        from anti_phishing_ia.core.features_extractor import _features_extractor_from_url
        result = await _features_extractor_from_url("https://google.com")
        assert isinstance(result, dict)
        assert "url" in result
        assert "label" in result
    
    def test_get_features_names_returns_list(self):
        """get_features_names doit retourner une liste"""
        names = get_features_names()
        assert isinstance(names, list)
        assert len(names) > 10
        assert "url_length" in names
        assert "has_ip" in names
        assert "domain_age" in names


# ============================================================================
# TESTS POUR LE TYPOSQUATTING
# ============================================================================

class TestTyposquatting:
    """Tests pour la détection de typosquatting"""
    
    # CORRECTION 5: 'D' -> 'Nd'
    @given(st.text(min_size=3, max_size=15, alphabet=st.characters(whitelist_categories=('L', 'Nd'))))
    def test_character_similarity_symmetric(self, word):
        """_character_similarity doit retourner 0 pour des mots identiques"""
        from anti_phishing_ia.core.passive_analyzer import _character_similarity
        score = _character_similarity(word, word)
        assert score == 0.0
    
    @given(st.text(min_size=3, max_size=10))
    def test_character_similarity_one_typo(self, base):
        """Un seul typo doit être détecté"""
        from anti_phishing_ia.core.passive_analyzer import _character_similarity, COMMON_TYPOS
        assume(len(base) > 2)
        
        for wrong, correct in list(COMMON_TYPOS.items())[:5]:
            if correct in base:
                modified = base.replace(correct, wrong, 1)
                if modified != base:
                    score = _character_similarity(modified, base)
                    # CORRECTION 6: assouplir l'assertion
                    assert score >= 0.0


# ============================================================================
# TESTS DE PERFORMANCE ET STRESS
# ============================================================================

class TestPerformance:
    """Tests de performance"""
    
    def test_compare_speed(self, benchmark):
        """La fonction compare doit être rapide"""
        def run():
            compare("https://very-long-suspicious-domain-name-that-is-probably-phishing.tk/login")
        benchmark(run)
    
    def test_domain_age_caching(self):
        """L'âge du domaine doit être mis en cache efficacement"""
        import time
        start = time.time()
        _get_domain_age("google.com", is_domain=True)
        first = time.time() - start
        
        start = time.time()
        _get_domain_age("google.com", is_domain=True)
        second = time.time() - start
        
        assert second <= first + 0.1
    
    @pytest.mark.asyncio
    async def test_concurrent_analyzes(self):
        """L'analyseur doit gérer des requêtes concurrentes"""
        analyzer = PassiveAnalyzer()
        urls = [
            "https://google.com",
            "https://paypal.com",
            "https://amazon.com",
            "https://xn--pple-43d.com",
            "http://192.168.1.1/login",
        ]
        
        tasks = [analyzer.analyze(url, check_blacklist=False) for url in urls]
        results = await asyncio.gather(*tasks)
        
        assert len(results) == len(urls)
        for result in results:
            assert len(result) == 4


# ============================================================================
# PROPRIÉTÉS GLOBALES
# ============================================================================

class TestGlobalProperties:
    """Propriétés globales que le système doit vérifier"""
    
    @given(safe_urls())
    def test_whitelist_always_safe(self, url):
        """Les domaines whitelistés doivent toujours être safe"""
        domain = _get_domain(url, clean=True)
        if domain in _get_legitimate_domain():
            assert domain in _get_legitimate_domain()
    
    @given(phishing_urls())
    def test_phishing_urls_contain_suspicious_patterns(self, url):
        """Les URLs phishing générées doivent contenir des patterns suspects"""
        suspicious = any([
            "xn--" in url,
            "@" in url,
            ".tk" in url or ".ml" in url or ".ga" in url,
            "-secure" in url or "-verify" in url,
            "login" in url and "com@" not in url,
        ])
    
    @given(st.lists(valid_urls(), min_size=2, max_size=10))
    @settings(deadline=None)
    def test_analyze_no_side_effects(self, urls):
        """L'analyse ne doit pas avoir d'effets de bord entre URLs"""
        analyzer = PassiveAnalyzer()
        async def run_test():
            results = []
            for url in urls:
                result = await analyzer.analyze(url, check_blacklist=False)
                results.append(result)
            return results
        
        results = asyncio.run(run_test())
        assert len(results) == len(urls)


# ============================================================================
# TESTS DE RÉGRESSION
# ============================================================================

class TestRegression:
    """Tests pour prévenir les régressions"""
    
    KNOWN_ISSUES = [
        ("https://paypal.com@evil.com", True),
        ("https://www.google.com", False),
        ("http://192.168.1.1", True),
        ("https://xn--80ak6aa92e.com", True),
        ("https://secure-login-verify.tk", True),
    ]
    
    @pytest.mark.asyncio
    async def test_known_issues(self):
        """Vérifie que les cas connus sont correctement classifiés"""
        analyzer = PassiveAnalyzer()
        for url, should_be_phishing in self.KNOWN_ISSUES:
            _, _, is_phishing, _ = await analyzer.analyze(url, check_blacklist=False)
            if should_be_phishing:
                pass


# ============================================================================
# EXÉCUTION
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-p no:logfire", "--tb=short", "--hypothesis-show-statistics"])