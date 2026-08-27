#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar  8 14:42:14 2026

@author: hounsousamuel
"""

import re
from scanner_ia.base_class.analyser_helper_base_class import (
    AnalyzerHelperResult, OneAnalyzerHelperResult
)
from scanner_ia.base_class.passive_analyzer_base_class import (
    PagePassiveResult, PassiveAnalyzerResult, PassiveVulnerability
)
from scanner_ia.core.parser import Parser
from scanner_ia.scanner_utils.logger import get_logger

logger = get_logger()

class PassiveCodeAnalyzer:
    """
    Classe d'analyse passive des vulnérabilté structurelle comme l'usage des lien http.
    Ses methodes:
        analyse: Méthode principale d'analyse(synchone).
        analyse_on_page: Méthode d'analyse d'une page, elle est utilisé par analyse.
        get_domain: Methode pour obtenir le nom de domain.
        is_same_domain: Méthode pour vérifié si deux urls sont du même domaine.
        add: Méthode d'ajout de Vulnérabilité.
        _inspect_link: Méthode d'inspection de lien pour trouvé des vulns comme lien http, lien http sur lien https(méthode privée).
        analyse_all_links: Méthode d'anlyse de tout les liens de la page.
        etc.
    """
    def __init__(self, headers_sev_map:dict = None):
        self.headers_sev_map = headers_sev_map or {
            "strict_transport_security": "élevé",
            "content_security_policy": "élevé",
            "x_frame_options": "élevé",
            "x_content_type_options": "moyen",
            "x_xss_protection": "moyen",
            "referrer_policy": "moyen",
            "permissions_policy": "moyen"
        }
    
    def analyse(self, analyzer_helper_result: AnalyzerHelperResult) -> PassiveAnalyzerResult:
        """
        Méthode principale d'analyse(synchone).

        Parameters
        ----------
        analyzer_helper_result : AnalyzerHelperResult
            Lé résultat du AnalyzerHelper.

        Returns
        -------
        PassiveAnalyzerResult
            Les vulnérabilités structurelles truvées sur les pages.

        """
        result = PassiveAnalyzerResult()
        for url, page in analyzer_helper_result.elements.items():
            result.pages[url] = self.analyse_on_page(page)
        return result
    
    def analyse_on_page(self, analyzer_one_page: OneAnalyzerHelperResult) -> PagePassiveResult:
        """
        Méthode d'analyse d'une page, elle est utilisé par analyse.

        Parameters
        ----------
        analyzer_one_page : OneAnalyzerHelperResult
            Une page, un élément du AnalyzerHelperResult qui équivaut à une page web.

        Returns
        -------
        PagePassiveResult
            Les vulnérabilités de la page.

        """
        result = PagePassiveResult()
        result.url = analyzer_one_page.fetched.url
        
        a = self.analyse_a(analyzer_one_page)
        iframe = self.analyse_iframe(analyzer_one_page)
        headers = self.analyse_headers(analyzer_one_page)
        cookies = self.analyse_cookies(analyzer_one_page)
        comment = self.analyse_comments(analyzer_one_page)
        form = self.analyse_form(analyzer_one_page)
        links, ratio = self.analyse_all_links(analyzer_one_page)
        
        result.a_vulns = a
        result.forms_vulns = form
        result.iframes_vulns = iframe
        result.cookies_vulns = cookies
        result.comments_vulns = comment
        result.links_vulns = links
        result.ratio_http = ratio
        result.headers_vulns = headers
        
        return result
    
    def get_domain(self, url: str) -> str:
        """
        Methode pour obtenir le nom de domain.

        Parameters
        ----------
        url : str
            L'url cible.

        Returns
        -------
        str
            Le nom de domaine extrait de l'url.

        """
        return Parser.get_domain(url)
    
    def is_same_domain(self, url1: str, url2: str) -> bool:
        """
        Méthode pour vérifié si deux urls sont du même domaine

        Parameters
        ----------
        url1 : str
            L'url 1.
        url2 : str
            L'url 2.

        Returns
        -------
        bool
            True -> même domaine, False -> Pas du même domaine.

        """
        return Parser.is_same_domain(url1, url2)
    
    def add(self, tag: str, message: str = "", severity: str = "info", 
            evidence: str = "", recommendation: str = "") -> PassiveVulnerability:
        """
        Méthode d'ajout de Vulnérabilité.

        Parameters
        ----------
        tag : str
            La balise d'où elle est extraite. The default is "a".
        message : str, optional
            Message à ajouter. The default is "".
        severity : str, optional
            La sévérité de la vulnérabilité. The default is "info".
        evidence : str, optional
            La preuve de la vulnérabilité. The default is "".
        recommendation : str, optional
            Recommandation pour y remédier. The default is "".

        Returns
        -------
        PassiveVulnerability
            DESCRIPTION.

        """
        result = PassiveVulnerability()
        result.tag = tag
        result.message = message
        result.severity = severity
        result.evidence = evidence
        result.recommendation = recommendation
        return result
    
    def _inspect_link(self, url: str, base_url: str = "", tag: str = "a") -> list[PassiveVulnerability]:
        """
        Méthode d'inspection de lien pour trouvé des vulns comme lien http, lien http sur lien https.

        Parameters
        ----------
        url : str
            L'url.
        base_url : str, optional
            L'url mère, optionnel. The default is "".
        tag : str, optional
            La balise d'où elle est extraite. The default is "a".

        Returns
        -------
        list[PassiveVulnerability]
            Une liste de vulnérabilité.

        """
        result = []
        
        if url.startswith("http:"):
            result.append(
                self.add(
                    tag=tag,
                    message="Protocole non sécurisé (http)",
                    severity="élevé",
                    recommendation="Passer en HTTPS",
                    evidence=url
                )
            )
        
        if base_url and base_url.startswith("https:") and url.startswith("http:"):
            result.append(
                self.add(
                    tag=tag,
                    message="Mixed content - ressource HTTP sur page HTTPS",
                    severity="critique" if tag in ["script", "iframe", "form"] else "élevé",
                    recommendation="Charger la ressource en HTTPS",
                    evidence=f"base={base_url} url={url}"
                )
            )
        
        if url.startswith(("javascript:", "data:")):
            severity = "critique" if url.startswith("javascript:") else "élevé"
            result.append(
                self.add(
                    tag=tag,
                    message=f"Protocole potentiellement dangereux ({url.split(':')[0]})",
                    severity=severity,
                    recommendation="Éviter javascript: et data: URIs",
                    evidence=url
                )
            )
        
        return result
    
    def analyse_all_links(self, analyzer_one_page: OneAnalyzerHelperResult) -> tuple[list[PassiveVulnerability], float]:
        """
        Méthode d'anlyse de tout les liens de la page.

        Parameters
        ----------
        analyzer_one_page : OneAnalyzerHelperResult
            Une page, un élément du AnalyzerHelperResult qui équivaut à une page web.

        Returns
        -------
        (tuple[list[PassiveVulnerability], float])
            Une tuple des vulnérabiltés et du pourcentage http/https.

        """
        url = analyzer_one_page.fetched.url
        parse_result = analyzer_one_page.parsed
        checks = [
            (parse_result.script.elements, "src", "script"),
            (parse_result.iframe.elements, "src", "iframe"),
            (parse_result.img.elements, "src", "img"),
            (parse_result.a.elements, "href", "a"),
            (parse_result.form.elements, "action", "form"),
            (parse_result.link.elements, "href", "link"),
            (parse_result.video.elements, "src", "video"),
            (parse_result.audio.elements, "src", "audio"),
            (parse_result.embed.elements, "src", "embed"),
        ]
        n_links = 0
        http = 0
        result = []
        
        for elements, key, tag in checks:
            for obj in elements:
                value = obj.get(key, None)
                if value:
                    n_links += 1
                    value = str(value)
                    if value.startswith("http:"):
                        http += 1
                    result.extend(
                        self._inspect_link(
                            url=value,
                            base_url=url if url else "",
                            tag=tag
                        )
                    )
        
        return result, http / max(n_links, 1)
    
    def analyse_a(self, analyzer_one_page: OneAnalyzerHelperResult) -> list[PassiveVulnerability]:
        """
        Méthode d'analyse des balises <a>.

        Parameters
        ----------
        analyzer_one_page : OneAnalyzerHelperResult
            Une page, un élément du AnalyzerHelperResult qui équivaut à une page web.

        Returns
        -------
        list[PassiveVulnerability]
            Liste des vulnérabilités trouvées.

        """
        balises_a = analyzer_one_page.parsed.a.elements
        result = []
        
        for balise in balises_a:
            url = balise.get("href", "")
            base_url = balise.get("abs_link", analyzer_one_page.fetched.url)
            target = balise.get("target", "")
            rel = balise.get("rel", "").lower()
            
            if target.lower() == "_blank" and not self.is_same_domain(url, base_url):
                if "noopener" not in rel and "noreferrer" not in rel:
                    result.append(
                        self.add(
                            tag="a",
                            message="Lien externe avec target='_blank' sans protection",
                            severity="élevé",
                            recommendation="Ajouter rel='noopener noreferrer'",
                            evidence=f"url={url} rel={rel}"
                        )
                    )
            
            if not self.is_same_domain(url, base_url) and target != "_blank":
                result.append(
                    self.add(
                        tag="a",
                        message="Lien externe sans target='_blank' (ouvre dans même onglet)",
                        severity="info",
                        recommendation="Utiliser target='_blank' pour les liens externes",
                        evidence=url
                    )
                )
        
        return result
    
    def analyse_headers(self, analyzer_one_page: OneAnalyzerHelperResult) -> list[PassiveVulnerability]:
        """
        Méthode d'analyse des headers.

        Parameters
        ----------
        analyzer_one_page : OneAnalyzerHelperResult
            Une page, un élément du AnalyzerHelperResult qui équivaut à une page web.

        Returns
        -------
        list[PassiveVulnerability]
            Liste des vulnérabilités trouvées.

        """
        elements = analyzer_one_page.parsed.headers.elements
        result = []
        
        if not elements:
            result.append(
                self.add(
                    tag="headers",
                    message="En-têtes HTTP non analysés",
                    severity="info"
                )
            )
            return result
        
        element = elements[0]
        security_report = element.get("security_report", {})
        
        if not security_report:
            headers = {str(k).lower(): v for k, v in element.get("headers", {}).items()}
            security_report = {
                "strict_transport_security": headers.get("strict-transport-security") is not None,
                "x_frame_options": headers.get("x-frame-options") is not None,
                "x_content_type_options": headers.get("x-content-type-options") is not None,
                "content_security_policy": headers.get("content-security-policy") is not None,
                "x_xss_protection": headers.get("x-xss-protection") is not None,
                "referrer_policy": headers.get("referrer-policy") is not None,
                "permissions_policy": headers.get("permissions-policy") is not None,
            }
        
        for k, v in security_report.items():
            if not v:
                severity = self.headers_sev_map.get(k, "moyen")
                result.append(
                    self.add(
                        tag="headers",
                        message=f"En-tête de sécurité manquant: {k}",
                        severity=severity,
                        recommendation=f"Configurer {k}",
                        evidence=k
                    )
                )
        
        # Vérifier les valeurs faibles
        headers = element.get("headers", {})
        if "strict-transport-security" in headers:
            hsts = headers["strict-transport-security"]
            if "max-age" in hsts:
                match = re.search(r'max-age=(\d+)', hsts)
                if match:
                    max_age = int(match.group(1))
                    if max_age < 31536000: 
                        result.append(
                            self.add(
                                tag="headers",
                                message="HSTS max-age trop court (< 1 an)",
                                severity="moyen",
                                recommendation="Augmenter max-age à 31536000",
                                evidence=f"max-age={max_age}"
                            )
                        )
        
        return result
    
    def analyse_cookies(self, analyzer_one_page: OneAnalyzerHelperResult) -> list[PassiveVulnerability]:
        """
        Méthode d'analyse des cookies.

        Parameters
        ----------
        analyzer_one_page : OneAnalyzerHelperResult
            Une page, un élément du AnalyzerHelperResult qui équivaut à une page web.

        Returns
        -------
        list[PassiveVulnerability]
            Liste des vulnérabilités trouvées.

        """
        cookies = analyzer_one_page.fetched.cookies
        result = []
        
        if not cookies:
            return result
        
        for cookie in cookies:
            attrs = cookie.get("attributes", {})

            # Le flag "secure" vit dans le même sous-dict "attributes" que
            # httponly/samesite (voir fetcher.py: {"key":..,"value":..,
            # "attributes": dict(morsel.items())}). Il n'existe PAS de clé
            # "secure" au niveau racine du dict cookie — la checker là
            # faisait échouer ce test sur 100% des cookies, y compris ceux
            # parfaitement configurés avec Secure activé.
            if not attrs.get("secure", False):
                result.append(
                    self.add(
                        tag="cookies",
                        message=f"Cookie sans flag Secure: {cookie.get('key', 'inconnu')}",
                        severity="critique",
                        recommendation="Ajouter le flag Secure",
                        evidence=str(cookie)
                    )
                )
            
            if not attrs.get("httponly", False):
                result.append(
                    self.add(
                        tag="cookies",
                        message=f"Cookie sans flag HttpOnly: {cookie.get('key', 'inconnu')}",
                        severity="élevé",
                        recommendation="Ajouter le flag HttpOnly",
                        evidence=str(cookie)
                    )
                )
            
            if attrs.get("samesite", "").lower() not in ["lax", "strict"]:
                result.append(
                    self.add(
                        tag="cookies",
                        message=f"Cookie sans SameSite ou SameSite=None: {cookie.get('key', 'inconnu')}",
                        severity="moyen",
                        recommendation="Configurer SameSite=Lax ou Strict",
                        evidence=str(cookie)
                    )
                )
        
        return result
    
    def analyse_iframe(self, analyzer_one_page: OneAnalyzerHelperResult) -> list[PassiveVulnerability]:
        """
        Méthode d'analyse des iframes.

        Parameters
        ----------
        analyzer_one_page : OneAnalyzerHelperResult
            Une page, un élément du AnalyzerHelperResult qui équivaut à une page web.

        Returns
        -------
        list[PassiveVulnerability]
            Liste des vulnérabilités trouvées.

        """
        balises_iframe = analyzer_one_page.parsed.iframe.elements
        result = []
        
        for balise in balises_iframe:
            src = balise.get("src", "")
            sandbox = balise.get("sandbox", "")
            
            if not sandbox:
                result.append(
                    self.add(
                        tag="iframe",
                        message="iframe sans attribut sandbox",
                        severity="critique",
                        recommendation="Ajouter sandbox avec les permissions minimales nécessaires",
                        evidence=src
                    )
                )
            
            elif sandbox and sandbox not in ["", "allow-scripts"]:
                dangerous = ["allow-top-navigation", "allow-forms", "allow-popups"]
                for perm in dangerous:
                    if perm in sandbox:
                        result.append(
                            self.add(
                                tag="iframe",
                                message=f"iframe avec sandbox permissive: {perm}",
                                severity="élevé",
                                recommendation=f"Éviter {perm} si non nécessaire",
                                evidence=f"src={src} sandbox={sandbox}"
                            )
                        )
            
            if src.startswith("http:") and analyzer_one_page.fetched.url.startswith("https:"):
                result.append(
                    self.add(
                        tag="iframe",
                        message="iframe en HTTP sur page HTTPS (mixed content)",
                        severity="critique",
                        recommendation="Charger l'iframe en HTTPS",
                        evidence=src
                    )
                )
        
        return result
    
    def analyse_form(self, analyzer_one_page: OneAnalyzerHelperResult) -> list[PassiveVulnerability]:
        """
        Méthode d'analyse des formulaires.

        Parameters
        ----------
        analyzer_one_page : OneAnalyzerHelperResult
            Une page, un élément du AnalyzerHelperResult qui équivaut à une page web.

        Returns
        -------
        list[PassiveVulnerability]
            Liste des vulnérabilités trouvées.

        """
        result = []
        forms = analyzer_one_page.parsed.form.elements
        
        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            
            if method == "GET":
                for champ in form.get("champs", []):
                    if champ.get("type") == "password":
                        result.append(
                            self.add(
                                tag="form",
                                message="Formulaire avec champ password en method=GET",
                                severity="critique",
                                recommendation="Utiliser method=POST pour les formulaires",
                                evidence=f"action={action}"
                            )
                        )
            
            # La protection CSRF n'a de sens que pour les requêtes qui changent
            # un état côté serveur (POST/PUT/DELETE/PATCH). Un formulaire GET
            # (ex: barre de recherche) n'a normalement pas besoin de token —
            # le signaler comme vulnérable serait un faux positif systématique.
            if method in ("POST", "PUT", "DELETE", "PATCH"):
                has_csrf = False
                for champ in form.get("champs", []):
                    name = champ.get("name", "").lower()
                    if "csrf" in name or "token" in name:
                        has_csrf = True
                        break
                
                if not has_csrf:
                    result.append(
                        self.add(
                            tag="form",
                            message="Formulaire sans champ CSRF token visible",
                            severity="moyen",
                            recommendation="Ajouter un token CSRF",
                            evidence=f"action={action}"
                        )
                    )
            
            if action.startswith("http:"):
                result.append(
                    self.add(
                        tag="form",
                        message="Formulaire avec action en HTTP",
                        severity="critique",
                        recommendation="Utiliser HTTPS",
                        evidence=action
                    )
                )
        
        return result
    
    def analyse_comments(self, analyzer_one_page: OneAnalyzerHelperResult) -> list[PassiveVulnerability]:
        """
        Méthode d'analyse des commentaires.

        Parameters
        ----------
        analyzer_one_page : OneAnalyzerHelperResult
            Une page, un élément du AnalyzerHelperResult qui équivaut à une page web.

        Returns
        -------
        list[PassiveVulnerability]
            Liste des vulnérabilités trouvées.

        """
        result = []
        keys = [
            ("has_url", "URL trouvée dans commentaire"),
            ("has_password", "Mot de passe trouvé dans commentaire"),
            ("credentials_found", "Credentials trouvés dans commentaire"),
            ("has_security_keyword", "Mot de sécurité identifié dans commentaire"),
        ]
        comments = analyzer_one_page.parsed.comments.elements
        
        for comment in comments:
            comment_text = comment.get("comment", "")
            for k, msg in keys:
                if comment.get(k, False):
                    severity = "critique" if k in ["has_password", "credentials_found"] else "moyen"
                    result.append(
                        self.add(
                            tag="comment",
                            message=msg,
                            severity=severity,
                            recommendation="Ne pas mettre d'informations sensibles dans les commentaires",
                            evidence=comment_text[:100]
                        )
                    )
            
            urls = comment.get("urls_found", [])
            for url in urls:
                result.extend(
                    self._inspect_link(url=url, tag="comment_url")
                )
        
        return result
    
    async def test(self, urls: list = None):
        """Test l'analyseur sur des URLs"""
        from core.analyzer_helper import AnalyzerHelper
        import aiohttp
        
        if urls is None:
            urls = ["http://localhost:8080", "https://example.com"]
        
        logger.info("\n" + "🔥"*60)
        logger.info("🔥 TEST PASSIVE ANALYZER")
        logger.info("🔥"*60)
        
        async with aiohttp.ClientSession() as session:
            helper = AnalyzerHelper(session, use_cache=True)
            
            for url in urls:
                logger.info(f"\n📌 Analyse de {url}")
                
                # Récupérer les données
                helper_result = await helper.analyse_and_parse_all(
                    url=url,
                    verify_reachability=True,
                    restore=False,
                    fetch=True,
                    silent=False
                )
                
                # Analyser
                result = self.analyse(helper_result)
                
                # Afficher résumé
                logger.info(f"  Pages analysées: {result.total_pages}")
                logger.info(f"  Vulnérabilités totales: {result.total_vulns}")
                logger.info(f"  Critiques: {result.summary['critical']}")
                logger.info(f"  Élevées: {result.summary['high']}")
                
                # Afficher quelques vulnérabilités
                for page_url, page in result.pages.items():
                    if page.total_vulns > 0:
                        logger.info(f"\n  📄 {page_url[:50]}...")
                        for vuln in page.a_vulns[:2]:
                            logger.info(f"    • {vuln.message} [{vuln.severity}]")
                        for vuln in page.iframes_vulns[:2]:
                            logger.info(f"    • {vuln.message} [{vuln.severity}]")
                        if page.ratio_http > 0:
                            logger.info(f"    • {page.ratio_http*100:.0f}% des liens en HTTP")
            
            await helper.close()


if __name__ == "__main__":
    analyzer = PassiveCodeAnalyzer()
    # asyncio.run(analyzer.test(["http://localhost:8080"]))
    print(analyzer.get_domain("sam.com"))