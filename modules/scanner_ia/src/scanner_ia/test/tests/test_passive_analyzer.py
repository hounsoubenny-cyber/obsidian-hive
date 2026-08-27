#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 26 05:11:35 2026

@author: hounsousamuel
"""

# tests/test_passive_analyzer.py
"""
Tests unitaires pour le module PassiveCodeAnalyzer
Couvre : analyse des headers, cookies, iframes, formulaires, commentaires, liens
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import pytest
from unittest.mock import MagicMock, patch

from scanner_ia.analyzers.passive_analyzer import PassiveCodeAnalyzer
from scanner_ia.base_class.passive_analyzer_base_class import PassiveVulnerability, PagePassiveResult
from scanner_ia.base_class.analyser_helper_base_class import OneAnalyzerHelperResult
from scanner_ia.base_class.parser_base_class import ParseResult, ParseElementResult
from scanner_ia.base_class.fetcher_base_class import FetcherResult


# =============================================================================
# TESTS PassiveVulnerability (classe de base)
# =============================================================================

class TestPassiveVulnerability:
    """Tests pour la classe PassiveVulnerability"""
    
    def test_create_vulnerability(self):
        """Création d'une vulnérabilité passive"""
        vuln = PassiveVulnerability()
        vuln.tag = "headers"
        vuln.message = "En-tête HSTS manquant"
        vuln.severity = "élevé"
        vuln.evidence = "strict-transport-security"
        vuln.recommendation = "Ajouter HSTS"
        
        assert vuln.tag == "headers"
        assert vuln.message == "En-tête HSTS manquant"
        assert vuln.severity == "élevé"
        assert vuln.evidence == "strict-transport-security"
        assert vuln.recommendation == "Ajouter HSTS"
    
    def test_to_dict(self):
        """Test sérialisation to_dict"""
        vuln = PassiveVulnerability()
        vuln.tag = "cookie"
        vuln.message = "Cookie Secure flag manquant"
        vuln.severity = "critique"
        vuln.evidence = "session_id=abc123"
        vuln.recommendation = "Ajouter Secure; HttpOnly"
        
        d = vuln.to_dict()
        
        assert d["tag"] == "cookie"
        assert d["message"] == "Cookie Secure flag manquant"
        assert d["severity"] == "critique"
        assert d["evidence"] == "session_id=abc123"
        assert d["recommendation"] == "Ajouter Secure; HttpOnly"
    
    def test_update_from_dict(self):
        """Test mise à jour depuis un dict"""
        vuln = PassiveVulnerability()
        data = {
            "tag": "form",
            "message": "Formulaire sans CSRF",
            "severity": "moyen"
        }
        
        vuln.update_from_dict(data)
        
        assert vuln.tag == "form"
        assert vuln.message == "Formulaire sans CSRF"
        assert vuln.severity == "moyen"
        # Les champs non fournis restent par défaut
        assert vuln.evidence == ""
        assert vuln.recommendation == ""


# =============================================================================
# TESTS PagePassiveResult
# =============================================================================

class TestPagePassiveResult:
    """Tests pour la classe PagePassiveResult"""
    
    def test_total_vulns_count(self):
        """Comptage total des vulnérabilités"""
        page = PagePassiveResult()
        
        # Ajouter des vulns factices
        vuln1 = PassiveVulnerability()
        vuln2 = PassiveVulnerability()
        vuln3 = PassiveVulnerability()
        
        page.headers_vulns = [vuln1]
        page.cookies_vulns = [vuln2, vuln3]
        page.forms_vulns = []
        
        assert page.total_vulns == 3
    
    def test_critical_count(self):
        """Comptage des vulnérabilités critiques"""
        page = PagePassiveResult()
        
        vuln_critique = PassiveVulnerability()
        vuln_critique.severity = "critique"
        
        vuln_eleve = PassiveVulnerability()
        vuln_eleve.severity = "élevé"
        
        page.headers_vulns = [vuln_critique, vuln_critique]
        page.cookies_vulns = [vuln_eleve]
        
        assert page.critical_count == 2
    
    def test_high_count(self):
        """Comptage des vulnérabilités élevées"""
        page = PagePassiveResult()
        
        vuln_critique = PassiveVulnerability()
        vuln_critique.severity = "critique"
        
        vuln_eleve = PassiveVulnerability()
        vuln_eleve.severity = "élevé"
        
        page.headers_vulns = [vuln_eleve, vuln_eleve]
        page.cookies_vulns = [vuln_critique]
        page.forms_vulns = [vuln_eleve]
        
        assert page.high_count == 3
    
    def test_to_dict(self):
        """Test sérialisation to_dict"""
        page = PagePassiveResult()
        page.url = "https://example.com"
        page.ratio_http = 0.35
        
        vuln = PassiveVulnerability()
        vuln.tag = "headers"
        vuln.message = "HSTS manquant"
        vuln.severity = "élevé"
        page.headers_vulns = [vuln]
        
        d = page.to_dict(deep=True)
        
        assert d["url"] == "https://example.com"
        assert d["ratio_http"] == 0.35
        assert len(d["headers_vulns"]) == 1
        assert d["headers_vulns"][0]["tag"] == "headers"


# =============================================================================
# TESTS PassiveCodeAnalyzer
# =============================================================================

class TestPassiveCodeAnalyzer:
    """Tests pour la classe PassiveCodeAnalyzer"""
    
    def test_init(self):
        """Initialisation avec map personnalisée"""
        # Default
        analyzer = PassiveCodeAnalyzer()
        assert analyzer.headers_sev_map is not None
        assert "strict_transport_security" in analyzer.headers_sev_map
        
        # Custom map
        custom_map = {"x_custom_header": "critique"}
        analyzer = PassiveCodeAnalyzer(headers_sev_map=custom_map)
        assert analyzer.headers_sev_map == custom_map
    
    def test_get_domain(self):
        """Extraction de domaine"""
        analyzer = PassiveCodeAnalyzer()
        
        assert analyzer.get_domain("https://example.com") == "example.com"
        assert analyzer.get_domain("https://sub.example.com/path") == "example.com"
        assert analyzer.get_domain("http://localhost:8080") == "localhost"
        assert analyzer.get_domain("http://192.168.1.1/admin") == "192.168.1.1"
    
    def test_is_same_domain(self):
        """Comparaison de domaines"""
        analyzer = PassiveCodeAnalyzer()
        
        assert analyzer.is_same_domain("https://example.com", "https://example.com/page") is True
        assert analyzer.is_same_domain("https://example.com", "http://example.com") is True
        assert analyzer.is_same_domain("https://example.com", "https://google.com") is False
        assert analyzer.is_same_domain("http://localhost", "http://localhost:8080") is True
    
    def test_add_vulnerability(self):
        """Création de vulnérabilité via add()"""
        analyzer = PassiveCodeAnalyzer()
        
        vuln = analyzer.add(
            tag="test",
            message="Message de test",
            severity="critique",
            evidence="preuve",
            recommendation="recommandation"
        )
        
        assert vuln.tag == "test"
        assert vuln.message == "Message de test"
        assert vuln.severity == "critique"
        assert vuln.evidence == "preuve"
        assert vuln.recommendation == "recommandation"
    
    def test_inspect_link_http_insecure(self):
        """Détection lien HTTP non sécurisé"""
        analyzer = PassiveCodeAnalyzer()
        
        vulns = analyzer._inspect_link("http://example.com", tag="a")
        
        assert len(vulns) == 1
        assert vulns[0].severity == "élevé"
        assert "http" in vulns[0].message.lower()
    
    def test_inspect_link_mixed_content(self):
        """Détection mixed content (HTTP sur HTTPS)"""
        analyzer = PassiveCodeAnalyzer()
        
        vulns = analyzer._inspect_link(
            "http://example.com/image.jpg",
            base_url="https://secure.com",
            tag="img"
        )
        
        assert len(vulns) >= 1
        # Vérifier mixed content
        mixed = [v for v in vulns if "mixed content" in v.message.lower()]
        assert len(mixed) >= 1
    
    def test_inspect_link_javascript_protocol(self):
        """Détection protocole javascript: dangereux"""
        analyzer = PassiveCodeAnalyzer()
        
        vulns = analyzer._inspect_link("javascript:alert(1)", tag="a")
        
        assert len(vulns) == 1
        assert vulns[0].severity == "critique"
        assert "javascript" in vulns[0].message.lower()
    
    def test_inspect_link_data_protocol(self):
        """Détection protocole data: dangereux"""
        analyzer = PassiveCodeAnalyzer()
        
        vulns = analyzer._inspect_link("data:text/html,<script>alert(1)</script>", tag="a")
        
        assert len(vulns) == 1
        assert "protocol" in vulns[0].message.lower()
    
    def test_analyse_all_links(self, mock_one_analyzer_helper_result):
        """Analyse de tous les liens de la page"""
        analyzer = PassiveCodeAnalyzer()
        
        # Ajouter des liens dans différents éléments
        mock_one_analyzer_helper_result.parsed.a.elements = [
            {"href": "http://insecure.com", "abs_link": "http://insecure.com"},
            {"href": "https://secure.com", "abs_link": "https://secure.com"}
        ]
        mock_one_analyzer_helper_result.parsed.script.elements = [
            {"src": "http://malicious.com/script.js", "abs_link": "http://malicious.com/script.js"}
        ]
        mock_one_analyzer_helper_result.parsed.iframe.elements = [
            {"src": "https://iframe.com", "abs_link": "https://iframe.com"}
        ]
        
        vulns, ratio = analyzer.analyse_all_links(mock_one_analyzer_helper_result)
        
        assert len(vulns) >= 2  # Au moins le lien HTTP et le script HTTP
        assert ratio >= 0  # Ratio HTTP/total
    
    def test_analyse_headers_missing_security(self, mock_one_analyzer_helper_result):
        """Détection headers de sécurité manquants"""
        analyzer = PassiveCodeAnalyzer()
        
        # Headers sans sécurité
        mock_one_analyzer_helper_result.parsed.headers.elements = [{
            "headers": {
                "server": "nginx",
                "content-type": "text/html"
            },
            "security_report": {
                "strict_transport_security": False,
                "x_frame_options": False,
                "x_content_type_options": False,
                "content_security_policy": False
            }
        }]
        
        vulns = analyzer.analyse_headers(mock_one_analyzer_helper_result)
        
        assert len(vulns) >= 4  # Plusieurs headers manquants
    
    def test_analyse_headers_all_present(self, mock_one_analyzer_helper_result):
        """Tous les headers de sécurité présents"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.headers.elements = [{
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "content-security-policy": "default-src 'self'"
            },
            "security_report": {
                "strict_transport_security": True,
                "x_frame_options": True,
                "x_content_type_options": True,
                "content_security_policy": True
            }
        }]
        
        vulns = analyzer.analyse_headers(mock_one_analyzer_helper_result)
        
        # Aucune vulnérabilité (tous les headers présents)
        assert len(vulns) == 0
    
    def test_analyse_headers_hsts_short_max_age(self, mock_one_analyzer_helper_result):
        """Détection HSTS avec max-age trop court"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.headers.elements = [{
            "headers": {
                "strict-transport-security": "max-age=3600"  # 1 heure seulement
            },
            "security_report": {
                "strict_transport_security": True
            }
        }]
        
        vulns = analyzer.analyse_headers(mock_one_analyzer_helper_result)
        
        # Doit détecter max-age trop court
        hsts_vulns = [v for v in vulns if "hsts" in v.message.lower()]
        assert len(hsts_vulns) >= 1
    
    def test_analyse_cookies_missing_secure(self, mock_one_analyzer_helper_result):
        """Détection cookie sans flag Secure"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.fetched.cookies = [
            {"key": "session_id", "value": "abc123", "attributes": {}}
        ]
        
        vulns = analyzer.analyse_cookies(mock_one_analyzer_helper_result)
        
        assert len(vulns) >= 1
        assert "secure" in vulns[0].message.lower()
    
    def test_analyse_cookies_missing_httponly(self, mock_one_analyzer_helper_result):
        """Détection cookie sans flag HttpOnly"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.fetched.cookies = [
            {"key": "session_id", "value": "abc123", "attributes": {"secure": True}}
        ]
        
        vulns = analyzer.analyse_cookies(mock_one_analyzer_helper_result)
        
        assert len(vulns) >= 1
        assert "httponly" in vulns[0].message.lower()
    
    def test_analyse_cookies_samesite_none(self, mock_one_analyzer_helper_result):
        """Détection cookie avec SameSite=None (potentiellement dangereux)"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.fetched.cookies = [
            {"key": "session_id", "value": "abc123", "attributes": {"secure": True, "httponly": True, "samesite": "None"}}
        ]
        
        vulns = analyzer.analyse_cookies(mock_one_analyzer_helper_result)
        
        # SameSite=None est considéré comme moins sécurisé
        samesite_vulns = [v for v in vulns if "samesite" in v.message.lower()]
        assert len(samesite_vulns) >= 1
    
    def test_analyse_cookies_fully_secure(self, mock_one_analyzer_helper_result):
        """Cookie parfaitement sécurisé"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.fetched.cookies = [
            {"key": "session_id", "value": "abc123", "attributes": {"secure": True, "httponly": True, "samesite": "Lax"}}
        ]
        
        vulns = analyzer.analyse_cookies(mock_one_analyzer_helper_result)
        
        # Aucune vulnérabilité
        assert len(vulns) == 0
    
    def test_analyse_iframe_missing_sandbox(self, mock_one_analyzer_helper_result):
        """Détection iframe sans attribut sandbox"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.iframe.elements = [
            {"src": "https://external.com", "sandbox": ""}
        ]
        
        vulns = analyzer.analyse_iframe(mock_one_analyzer_helper_result)
        
        assert len(vulns) >= 1
        assert "sandbox" in vulns[0].message.lower()
    
    def test_analyse_iframe_permissive_sandbox(self, mock_one_analyzer_helper_result):
        """Détection iframe avec sandbox trop permissif"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.iframe.elements = [
            {"src": "https://external.com", "sandbox": "allow-scripts allow-top-navigation allow-forms"}
        ]
        
        vulns = analyzer.analyse_iframe(mock_one_analyzer_helper_result)
        
        # Doit détecter allow-top-navigation comme dangereux
        dangerous = [v for v in vulns if "top-navigation" in v.message.lower()]
        assert len(dangerous) >= 1
    
    def test_analyse_iframe_mixed_content(self, mock_one_analyzer_helper_result):
        """Détection iframe HTTP sur page HTTPS"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.fetched.url = "https://secure.com"
        mock_one_analyzer_helper_result.parsed.iframe.elements = [
            {"src": "http://insecure.com", "sandbox": "allow-scripts"}
        ]
        
        vulns = analyzer.analyse_iframe(mock_one_analyzer_helper_result)
        
        mixed = [v for v in vulns if "mixed content" in v.message.lower()]
        assert len(mixed) >= 1
    
    def test_analyse_form_method_get_with_password(self, mock_one_analyzer_helper_result):
        """Détection formulaire GET avec champ password"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.form.elements = [
            {
                "action": "/login",
                "method": "GET",
                "champs": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"}
                ]
            }
        ]
        
        vulns = analyzer.analyse_form(mock_one_analyzer_helper_result)
        
        assert len(vulns) >= 1
        assert "password" in vulns[0].message.lower()
        assert "GET" in vulns[0].message
    
    def test_analyse_form_missing_csrf(self, mock_one_analyzer_helper_result):
        """Détection formulaire sans token CSRF"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.form.elements = [
            {
                "action": "/transfer",
                "method": "POST",
                "champs": [
                    {"name": "amount", "type": "text"},
                    {"name": "recipient", "type": "text"}
                ]
            }
        ]
        
        vulns = analyzer.analyse_form(mock_one_analyzer_helper_result)
        
        assert len(vulns) >= 1
        assert "csrf" in vulns[0].message.lower()
    
    def test_analyse_form_with_csrf(self, mock_one_analyzer_helper_result):
        """Formulaire avec token CSRF (considéré OK)"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.form.elements = [
            {
                "action": "/transfer",
                "method": "POST",
                "champs": [
                    {"name": "amount", "type": "text"},
                    {"name": "csrf_token", "type": "hidden", "value": "abc123"}
                ]
            }
        ]
        
        vulns = analyzer.analyse_form(mock_one_analyzer_helper_result)
        
        # Ne devrait pas avoir de vulnérabilité CSRF
        csrf_vulns = [v for v in vulns if "csrf" in v.message.lower()]
        assert len(csrf_vulns) == 0
    
    def test_analyse_form_http_action(self, mock_one_analyzer_helper_result):
        """Détection formulaire avec action en HTTP"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.form.elements = [
            {
                "action": "http://example.com/login",
                "method": "POST",
                "champs": []
            }
        ]
        
        vulns = analyzer.analyse_form(mock_one_analyzer_helper_result)
        
        assert len(vulns) >= 1
        assert "http" in vulns[0].message.lower()
    
    def test_analyse_comments_with_passwords(self, mock_one_analyzer_helper_result):
        """Détection mots de passe dans les commentaires"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.comments.elements = [
            {"comment": "TODO: remove this password: admin123", "has_password": True}
        ]
        
        vulns = analyzer.analyse_comments(mock_one_analyzer_helper_result)
        
        assert len(vulns) >= 1
        assert "password" in vulns[0].message.lower() or "credentials" in vulns[0].message.lower()
    
    def test_analyse_comments_with_urls(self, mock_one_analyzer_helper_result):
        """Détection URLs dans les commentaires"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.comments.elements = [
            {"comment": "See http://internal.server/admin", "has_url": True, "urls_found": ["http://internal.server/admin"]}
        ]
        
        vulns = analyzer.analyse_comments(mock_one_analyzer_helper_result)
        
        assert len(vulns) >= 1
    
    def test_analyse_a_external_link_no_target_blank(self, mock_one_analyzer_helper_result):
        """Détection lien externe sans target='_blank'"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.a.elements = [
            {
                "href": "https://google.com",
                "abs_link": "https://google.com",
                "target": "",
                "rel": ""
            }
        ]
        
        # Mock is_same_domain pour retourner False (domaines différents)
        with patch.object(analyzer, 'is_same_domain', return_value=False):
            vulns = analyzer.analyse_a(mock_one_analyzer_helper_result)
        
        assert len(vulns) >= 1
        assert "target" in vulns[0].message.lower()
    
    def test_analyse_a_external_link_with_target_blank_no_protection(self, mock_one_analyzer_helper_result):
        """Détection target='_blank' sans rel=noopener"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.a.elements = [
            {
                "href": "https://google.com",
                "abs_link": "https://google.com",
                "target": "_blank",
                "rel": ""
            }
        ]
        
        with patch.object(analyzer, 'is_same_domain', return_value=False):
            vulns = analyzer.analyse_a(mock_one_analyzer_helper_result)
        
        assert len(vulns) >= 1
        assert "noopener" in vulns[0].message.lower() or "protection" in vulns[0].message.lower()
    
    def test_analyse_a_external_link_secure(self, mock_one_analyzer_helper_result):
        """Lien externe sécurisé avec target='_blank' et rel='noopener'"""
        analyzer = PassiveCodeAnalyzer()
        
        mock_one_analyzer_helper_result.parsed.a.elements = [
            {
                "href": "https://google.com",
                "abs_link": "https://google.com",
                "target": "_blank",
                "rel": "noopener noreferrer"
            }
        ]
        
        with patch.object(analyzer, 'is_same_domain', return_value=False):
            vulns = analyzer.analyse_a(mock_one_analyzer_helper_result)
        
        # Pas de vulnérabilité
        assert len(vulns) == 0
    
    def test_analyse_main_method(self, mock_analyzer_helper_result):
        """Méthode principale analyse()"""
        analyzer = PassiveCodeAnalyzer()
        
        result = analyzer.analyse(mock_analyzer_helper_result)
        
        assert result is not None
        assert len(result.pages) == 1
        assert hasattr(result, 'total_vulns')
        assert hasattr(result, 'total_pages')
        assert hasattr(result, 'summary')
    
    def test_analyse_on_page(self, mock_one_analyzer_helper_result):
        """Analyse d'une page unique"""
        analyzer = PassiveCodeAnalyzer()
        
        result = analyzer.analyse_on_page(mock_one_analyzer_helper_result)
        
        assert result.url == "https://example.com/page"
        assert hasattr(result, 'a_vulns')
        assert hasattr(result, 'headers_vulns')
        assert hasattr(result, 'cookies_vulns')
        assert hasattr(result, 'forms_vulns')
        assert hasattr(result, 'ratio_http')
        assert hasattr(result, 'total_vulns')


# =============================================================================
# TESTS INTÉGRATION (composants ensemble)
# =============================================================================

class TestPassiveAnalyzerIntegration:
    """Tests d'intégration pour PassiveCodeAnalyzer"""
    
    def test_full_page_analysis_with_all_elements(self):
        """Analyse complète d'une page avec tous types d'éléments"""
        analyzer = PassiveCodeAnalyzer()
        
        # Construire une page complète avec tous types de vulnérabilités
        one_result = OneAnalyzerHelperResult()
        
        # FetcherResult
        fetcher = FetcherResult()
        fetcher.url = "https://example.com"
        fetcher.body = "<html><body>Test</body></html>"
        fetcher.headers = {"Content-Type": "text/html"}
        fetcher.cookies = [
            {"key": "session", "value": "abc", "attributes": {}}  # Pas Secure/HttpOnly
        ]
        one_result.fetched = fetcher
        
        # ParseResult avec différents éléments
        parse_result = ParseResult()
        
        # Liens HTTP
        a_elements = ParseElementResult()
        a_elements.elements = [{"href": "http://insecure.com", "abs_link": "http://insecure.com"}]
        a_elements._update()
        parse_result.a = a_elements
        
        # Formulaire sans CSRF
        form_elements = ParseElementResult()
        form_elements.elements = [{
            "action": "http://example.com/login",
            "method": "POST",
            "champs": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}]
        }]
        form_elements._update()
        parse_result.form = form_elements
        
        # Iframe sans sandbox
        iframe_elements = ParseElementResult()
        iframe_elements.elements = [{"src": "https://external.com", "sandbox": ""}]
        iframe_elements._update()
        parse_result.iframe = iframe_elements
        
        # Headers manquants
        headers_elements = ParseElementResult()
        headers_elements.elements = [{
            "headers": {},
            "security_report": {
                "strict_transport_security": False,
                "x_frame_options": False
            }
        }]
        headers_elements._update()
        parse_result.headers = headers_elements
        
        # Commentaires suspects
        comments_elements = ParseElementResult()
        comments_elements.elements = [{"comment": "password: admin123", "has_password": True}]
        comments_elements._update()
        parse_result.comments = comments_elements
        
        one_result.parsed = parse_result
        
        # Analyser
        result = analyzer.analyse_on_page(one_result)
        
        # Vérifier que toutes les vulnérabilités sont détectées
        assert result.total_vulns > 0
        assert len(result.a_vulns) >= 1
        assert len(result.forms_vulns) >= 2  # HTTP action + password in GET or no CSRF
        assert len(result.iframes_vulns) >= 1
        assert len(result.headers_vulns) >= 2
        assert len(result.comments_vulns) >= 1
        assert len(result.cookies_vulns) >= 1


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