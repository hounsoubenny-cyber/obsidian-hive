#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar  8 14:42:01 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import re
import json
import copy
import time
import aiohttp
import asyncio
import traceback
# from loguru import logger
from collections import Counter
from scanner_ia.analyzers.config import HTML_SIGNATURE_FILE, JS_SIGNATURE_FILE
from scanner_ia.base_class.analyser_helper_base_class import AnalyzerHelperResult
from scanner_ia.base_class.code_analyse_base_class import CheckResult, CodeAnalyzerResult
from scanner_ia.scanner_utils.logger import get_logger
from scanner_ia.core.analyzer_helper import AnalyzerHelper
from nest_asyncio import apply
apply()

# logger.remove()
# logger.add(
#     sys.stdout,
#     format=(
#         "<yellow>{time:HH:mm:ss}</yellow> | "
#         "<level>{level: <8}</level> | "
#         "<magenta>{name}</magenta>:<cyan>{function}</cyan>:<cyan>{line}</cyan>\n"
#         "└─ <level>{message}</level>"
#     ),
#     level="DEBUG",
#     colorize=True
# )
# logger.add(
#     "logs/code_analyzer.log",
#     rotation="10 MB",
#     retention="30 days",
#     level="DEBUG",
#     format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
#     encoding="utf-8"
# )
logger = get_logger()

class CodeAnalyzer:
    """
    Analyseur de code pour détecter des vulnérabilités dans le HTML et JavaScript.
    
    Cette classe charge des fichiers de signatures (règles) et les utilise pour
    scanner du texte à la recherche de patterns dangereux.
    
    Attributes:
        debug (bool): Mode debug avec plus de logs et regex verbose
        html_rules (dict): Règles pour l'analyse HTML
        js_rules (dict): Règles pour l'analyse JavaScript
    """
    
    def __init__(self, debug:bool = False):
        """
        Initialise l'analyseur de code.
        
        Args:
            debug: Active le mode debug avec plus de détails dans les logs
                  et active le flag re.VERBOSE pour les regex
        """
        self.debug = debug
        self.html_rules = {}
        self.js_rules = {}
        self.load_rules()
    
    def _traite_sig(self, sig:dict) -> dict:
        """
        Traite les signatures en compilant les expressions régulières.
        
        Cette méthode parcourt toutes les catégories et signatures,
        compile les patterns regex pour une recherche plus rapide.
        
        Args:
            sig: Dictionnaire des signatures à traiter
            
        Returns:
            dict: Signatures avec patterns compilés (ou dict vide si erreur)
        """
        if sig:
            cat:dict = sig.get("categories", {})
            for k, v in list(cat.items()):
                signatures:list[dict] = v.get("signatures", [])
                for i, sv in enumerate(copy.deepcopy(signatures)):
                    pattern = sv.get("patterns", [])
                    copy_pattern = []
                    flags = re.IGNORECASE | re.DOTALL | re.MULTILINE 
                    if self.debug:
                        flags = re.IGNORECASE | re.DOTALL | re.MULTILINE | re.VERBOSE
                    for pat in pattern:
                        try:
                            cm = re.compile(
                                    pattern=pat,
                                    flags=flags
                                )
                            copy_pattern.append(cm)
                        except Exception as e:
                            logger.error(f"Erreur de compilation d'un pattern ({pat} de {sv.get('name', None)}) : {str(e)}")
                            if self.debug:
                                logger.error(traceback.format_exc())
                                
                    signatures[i]["patterns"] = copy_pattern
                cat[k]["signatures"] = signatures
            sig["categories"] = cat
            return sig
        return {}
    
    def load_rules(self) -> None:
        """
        Charge les fichiers de règles HTML et JavaScript.
        
        Cette méthode lit les fichiers JSON, compile les patterns regex
        et initialise les dictionnaires de règles.
        
        Raises:
            ValueError: Si un fichier de règles est invalide
            FileNotFoundError: Si un fichier de signature n'existe pas
            json.JSONDecodeError: Si le fichier JSON est mal formaté
        """
        try:
            html_success, js_success = False, False
            html_sig:dict|None|str = None
            with open(HTML_SIGNATURE_FILE, "r") as f:
                html_sig = json.load(f)
                html_success = True
                logger.info("Réussite du chargement du fichier de règles html")
            
            html_sig = self._traite_sig(html_sig)
            if html_sig:
                self.html_rules = html_sig
                logger.info("Traitement du fichier de règles html réussi !")
            else:
                logger.warning("Fichier des règles html est invalide")
                raise ValueError
            
            js_sig:dict|None|str = None
            with open(JS_SIGNATURE_FILE, "r") as f:
                js_sig = json.load(f)
                js_success = True
                logger.info("Réussite du chargement du fichier de règles JS")
            
            js_sig = self._traite_sig(js_sig)
            if js_sig:
                self.js_rules = js_sig
                logger.info("Traitement du fichier de règles JS réussi !")
            else:
                logger.warning("Fichier des règles JS est invalide")
                raise ValueError
            
            if html_success and js_success:
                logger.success("Le traitement de tout les fichiers signatures a réussi ")
        except Exception as e:
            logger.error(f"Erreur dans le traitement du fichier signature de {'html' if not html_success else 'json'} : {str(e)}")
            if self.debug:
                logger.error(traceback.format_exc())
    
    
    def get_vuls_names(self, html:bool = True) -> tuple[list, list]:
        """
        Récupère les noms et abréviations des vulnérabilités.
        
        Args:
            html: True pour les règles HTML, False pour JavaScript
            
        Returns:
            tuple: (liste_des_noms, liste_des_abréviations)
            
        Example:
            >>> names, abbrs = analyzer.get_vuls_names()
            >>> print(names[0], abbrs[0])
            'sql_injection', 'SQLi'
        """
        rules = self.html_rules if html else self.js_rules
        vulnerability_names = rules.get("vulnerability_names", {})
        return list(vulnerability_names.keys()), list(vulnerability_names.values())
    
    def get_vuls_cat(self, html:bool = True) -> list:
        """
        Récupère la liste des catégories de vulnérabilités.
        
        Args:
            html: True pour les règles HTML, False pour JavaScript
            
        Returns:
            list: Noms des catégories
            
        Example:
            >>> cats = analyzer.get_vuls_cat()
            >>> print(cats)
            ['web_vulnerabilities', 'authentication_vulnerabilities', ...]
        """
        rules = self.html_rules if html else self.js_rules
        return list(rules.get("categories").keys())
    
    def get_vuls_names_per_cat(self, html:bool = True) -> dict[str, list]:
        """
        Récupère les vulnérabilités organisées par catégorie.
        
        Args:
            html: True pour les règles HTML, False pour JavaScript
            
        Returns:
            dict: {catégorie: [liste_des_noms_de_vuln]}
            
        Example:
            >>> per_cat = analyzer.get_vuls_names_per_cat()
            >>> print(per_cat['web_vulnerabilities'][:3])
            ['sql_injection', 'cross-site_scripting', 'xml_external_entity']
        """
        rules = self.html_rules if html else self.js_rules
        cat = rules.get("categories", {})
        to_return = {}
        for k, v in cat.items():
            sig = v.get("signatures", [])
            names = [p.get("name", "") for p in sig]
            to_return[k] = names
            
        return to_return
    
    def name_to_id(self, name:str, html:bool = True) -> str:
        """
        Convertit un nom de vulnérabilité en ID.
        
        Args:
            name: Nom de la vulnérabilité (ex: "sql_injection")
            html: True pour les règles HTML, False pour JavaScript
            
        Returns:
            str: ID correspondant (ex: "SQL-001") ou chaîne vide si non trouvé
        """
        rules = self.html_rules if html else self.js_rules
        name = name.lower().strip()
        cat = rules.get("categories", {})
        for k, v in cat.items():
            sig = v.get("signatures", [])
            for sv in sig:
                if name == sv.get("name", "").lower().strip():
                    return sv.get("id", "")
    
        return ""
    
    def id_to_name(self, id:str, html:bool = True) -> str:
        """
        Convertit un ID en nom de vulnérabilité.
        
        Args:
            id: ID de la vulnérabilité (ex: "SQL-001")
            html: True pour les règles HTML, False pour JavaScript
            
        Returns:
            str: Nom correspondant (ex: "sql_injection") ou chaîne vide si non trouvé
        """
        rules = self.html_rules if html else self.js_rules
        id = id.lower().strip()
        cat = rules.get("categories", {})
        for k, v in cat.items():
            sig = v.get("signatures", [])
            for sv in sig:
                if id == sv.get("id", "").lower().strip():
                    return sv.get("name", "")
    
        return ""
    
    def get_metastat(self, html:bool = True) -> dict:
        """
        Récupère les métadonnées du fichier de signatures.
        
        Args:
            html: True pour les règles HTML, False pour JavaScript
            
        Returns:
            dict: Métadonnées (version, description, total_signatures, etc.)
        """
        rules = self.html_rules if html else self.js_rules
        return rules.get("metadata", {})
    
    def get_full_cat(self, html:bool = True, cat:str = "") -> dict:
        """
        Récupère une catégorie complète avec toutes ses signatures.
        
        Args:
            html: True pour les règles HTML, False pour JavaScript
            cat: Nom de la catégorie
            
        Returns:
            dict: Catégorie complète avec toutes ses signatures
                  ou dict vide si non trouvée
        """
        rules = self.html_rules if html else self.js_rules
        cat_ = rules.get("categories", {})
        return cat_.get(cat, {})
    
    def get_full_vuln(self, html:bool = True, vuln:str = "", cat:str="") -> dict:
        """
        Récupère les détails complets d'une vulnérabilité.
        
        Args:
            html: True pour les règles HTML, False pour JavaScript
            vuln: Nom ou ID de la vulnérabilité
            cat: Catégorie (optionnel, pour accélérer la recherche)
            
        Returns:
            dict: Détails complets de la vulnérabilité (patterns, severity, etc.)
                  ou dict vide si non trouvée
        """
        rules = self.html_rules if html else self.js_rules
        cat_ = rules.get("categories", {})
        vuln = vuln.lower().strip()
        if cat:
            sig = cat_.get(cat, {})
            for sv in sig:
                if vuln in (sv.get("id", "").lower().strip(), sv.get("name", "").lower().strip()):
                    return sv
        else:
            for k, v in cat_.items():
                sig = v.get("signatures", [])
                for sv in sig:
                    if vuln in (sv.get("id", "").lower().strip(), sv.get("name", "").lower().strip()):
                        return sv
        return {}
    
    def _is_false_positive(self, matched: str, keywords: list) -> bool:
        """Check faux positifs"""
        return any(kw.lower() in matched.lower() for kw in keywords)
    
    def check(self, text:str, html:bool = True, context:str = "body") -> CheckResult:
        """
        Vérifie un texte contre les signatures de vulnérabilités.
        
        Cette méthode parcourt toutes les signatures et cherche les patterns
        dans le texte fourni.
        
        Args:
            text: Texte à analyser (HTML, JavaScript, etc.)
            html: True pour utiliser les règles HTML, False pour JavaScript
            context: Contexte de l'analyse (ex: "body", "balise_script_externe")
            
        Returns:
            CheckResult: Résultat de l'analyse avec:
                - vulns: Liste des vulnérabilités trouvées
                - stats: Statistiques par vulnérabilité
                - list_vulns: Liste des noms de vulnérabilités uniques
                - context: Contexte de l'analyse
        """
        result = CheckResult()
        try:
            if not text:
                result.context = context
                return result
            rules = self.html_rules if html else self.js_rules
            stats = {}
            severity = []
            for k, v in rules.get("categories", {}).items():
                signatures:list[dict] = v["signatures"]
                for sig in signatures:
                    pattern:list[re.Pattern] = sig["patterns"]
                    for pat in pattern:
                        for m in pat.finditer(text):
                            find = m.group(0).strip()
                            if not find:
                                continue
                            extended = {k:v for k, v in sig.items() if k != "patterns"}
                            extended["custom_categorie"] = f"{k}__{sig.get('categorie', '')}"
                            extended["pattern"] = pat.pattern
                            extended["find"] = find
                            extended["line_number"] = text[:text.find(find)].count('\n') + 1
                            extended["name_abbr"] = rules["vulnerability_names"][extended["name"]]
                            lines = text.splitlines()
                            ln = extended["line_number"] - 1   # 0-indexed
                            start = max(0, ln - 2)
                            end = min(len(lines), ln + 3)
                            extended["code"] = "\n".join(
                                f"{'→ ' if i == ln else '  '}{lines[i]}" 
                                for i in range(start, end)
                            )
                            if self._is_false_positive(find, sig.get('false_positive_keywords', [])):
                                logger.info("Faux positf détecter et ignoré !")
                                continue
                            
                            result.vulns.append(extended)
                            if extended["name"] not in result.list_vulns:
                                result.list_vulns.append(extended["name"])
                            severity.append(extended["severity"])
                            if extended["name"] not in stats:
                                stats[extended["name"]] = {
                                    "total": 0, 
                                    "name_abbr": extended["name_abbr"], 
                                    "severity": extended["severity"]
                                }
                            stats[extended["name"]]['total'] += 1
            
            stats["severity_count"] = dict(Counter(severity))
            result.stats = stats
            logger.info(f"Fin du checking pour un text(len={len(text)}, context={context}), nbr_vulns={len(result.list_vulns)}")
            
        except Exception as e:
            logger.error(f"Erreur dans check, erreur: {str(e)}")
            if self.debug:
                logger.error(traceback.format_exc())
        
        result.context = context
        return result
        
    def analyse(self, analyzer_helper_result:AnalyzerHelperResult) -> CodeAnalyzerResult:
        """
        Analyse complète d'un résultat d'AnalyzerHelper.
        
        Cette méthode analyse le corps HTML et les scripts JavaScript
        pour détecter des vulnérabilités.
        
        Args:
            analyzer_helper_result: Résultat de l'AnalyzerHelper contenant
                                  les pages crawllées et leur contenu
                                  
        Returns:
            CodeAnalyzerResult: Résultats d'analyse pour chaque URL avec:
                - results: Dict {url: {"body": CheckResult, "balises_script": dict}}
                - elapsed: Temps d'exécution
        """
        result = CodeAnalyzerResult()
        try:
            start_time = time.time()
            logger.info(f"Début analyse code à {time.ctime()}\n")
            for url, value in analyzer_helper_result.elements.items():
                body = value.fetched.body
                body_check = self.check(text=body, html=True, context="body")
                i = 0
                bs_checks = {}
                for bs in value.parsed.script.elements:
                    ct = bs["contenu"]
                    if not ct:
                        continue
                    nature = bs["nature"]
                    key = f"balise_script_{nature}"
                    bs_checks[f"{key}__{i}"] = self.check(text=ct, html=False, context=key)
                    i += 1
                result.results[url] = {
                    "body": body_check,
                    "balises_script": bs_checks
                }
        except Exception as e:
            logger.error(f"Erreur dans analyse, erreur: {str(e)}")
            if self.debug:
                logger.error(traceback.format_exc())
        result.elapsed = time.time() - start_time
        return result
    
    
    def test_check(self) -> None:
        """
        Test la méthode check avec des exemples simples.
        
        Utilise des textes prédéfinis contenant des patterns de vulnérabilités
        pour vérifier que la détection fonctionne correctement.
        """
        logger.info("\n" + "="*60)
        logger.info("🧪 TEST DE LA MÉTHODE CHECK")
        logger.info("="*60)
        
        test_texts = [
            ("<script>eval('alert(1)')</script>", "html", "XSS dans script"),
            ("document.cookie = 'user=admin'", "js", "Cookie manipulation"),
            ("<!-- TODO: enlever ce mot de passe: admin123 -->", "html", "Commentaire suspect"),
            ("let x = '<img src=x onerror=alert(1)>';", "js", "XSS dans string"),
        ]
        
        for text, type_, desc in test_texts:
            logger.info(f"\n📌 Test: {desc}")
            result = self.check(text=text, html=(type_=="html"), context="test")
            logger.info(f"  Vulnérabilités trouvées: {len(result.vulns)}")
            for i, vuln in enumerate(result.vulns[:3]):
                logger.info(f"    {i+1}. {vuln.get('name')} ({vuln.get('severity')}) - {vuln.get('find')[:50]}")
    
    def test_utils(self) -> None:
        """
        Test les méthodes utilitaires (get_vuls_names, etc.).
        
        Vérifie que les méthodes d'accès aux données retournent
        des résultats cohérents.
        """
        logger.info("\n" + "="*60)
        logger.info("🧪 TEST DES MÉTHODES UTILITAIRES")
        logger.info("="*60)
        
        # Test get_vuls_names
        names, abbrs = self.get_vuls_names()
        logger.info(f"\n📌 get_vuls_names: {len(names)} vulnérabilités")
        logger.info(f"  Exemples: {names[:3]} -> {abbrs[:3]}")
        
        # Test get_vuls_cat
        cats = self.get_vuls_cat()
        logger.info(f"\n📌 get_vuls_cat: {len(cats)} catégories")
        logger.info(f"  {cats[:3]}")
        
        # Test name_to_id / id_to_name
        if names:
            test_name = names[0]
            test_id = self.name_to_id(test_name)
            back_name = self.id_to_name(test_id)
            logger.info("\n📌 name_to_id / id_to_name")
            logger.info(f"  {test_name} -> {test_id} -> {back_name}")
    
    async def test_on_real_sites(self, urls:list = None) -> dict:
        """
        Test le CodeAnalyzer sur des sites réels via AnalyzerHelper.
        
        Cette méthode :
        1. Utilise AnalyzerHelper pour crawler les sites
        2. Analyse le code HTML et JavaScript trouvé
        3. Affiche des statistiques détaillées
        
        Args:
            urls: Liste d'URLs à analyser (par défaut: sites de test)
            
        Returns:
            dict: Résultats détaillés pour chaque URL analysée
            
        Example:
            >>> results = await analyzer.test_on_real_sites(["http://localhost:8080"])
            >>> print(results["http://localhost:8080"]["total_vulns"])
            42
        """
        if urls is None:
            urls = [
                "http://localhost:8080",
                # "https://example.com",
                # "https://httpbin.org/html",
                # "https://quotes.toscrape.com/",
            ]
        
        logger.info("\n" + "🔥"*70)
        logger.info("🔥 TEST SUR SITES RÉELS AVEC ANALYZERHELPER")
        logger.info("🔥"*70)
        logger.info(f"📌 {len(urls)} URL(s) à analyser")
        
        async with aiohttp.ClientSession() as session:
            analyzer_helper = AnalyzerHelper(session=session, use_cache=True)
            
            all_results = {}
            total_start = time.time()
            
            for i, url in enumerate(urls, 1):
                logger.info(f"\n📌 Test {i}/{len(urls)}: {url}")
                logger.info("-"*60)
                
                logger.info("  ⏳ Récupération des données...")
                helper_result = await analyzer_helper.analyse_and_parse_all(
                    url=url,
                    verify_reachability=True,
                    restore=True,
                    fetch=True,
                    silent=False
                )
                logger.info("  ⏳ Analyse des vulnérabilités...")
                start = time.time()
                code_result = self.analyse(helper_result)
                with open("results.json", "w") as f:
                    json.dump(code_result.to_dict(True), f, indent=2, ensure_ascii=False)
                elapsed = time.time() - start
                
                logger.info(f"  ✅ Analyse terminée en {elapsed:.2f}s")
                
                total_vulns = 0
                v = []
                for page_url, page_result in code_result.results.items():
                    body_vulns = len(page_result["body"].vulns)
                    v.append(page_result["body"].vulns)
                    script_vulns = sum(len(s.vulns) for s in page_result["balises_script"].values())
                    page_total = body_vulns + script_vulns
                    total_vulns += page_total
                    
                    logger.info(f"    📄 {page_url[:60]}...")
                    logger.info(f"      ├─ Body: {body_vulns} vulns")
                    logger.info(f"      └─ Scripts: {script_vulns} vulns")
                
                all_results[url] = {
                    "helper_elapsed": helper_result.elapsed,
                    "analyzer_elapsed": elapsed,
                    "total_vulns": total_vulns,
                    "details": code_result
                }
            
            total_time = time.time() - total_start
            
            # Résumé final
            logger.info("\n" + "★"*70)
            logger.info("📊 RÉSUMÉ DES TESTS SUR SITES RÉELS")
            logger.info("★"*70)
            
            grand_total = sum(r["total_vulns"] for r in all_results.values())
            logger.info(f"📌 URLs testées: {len(urls)}")
            logger.info(f"⏱️  Temps total: {total_time:.2f}s")
            logger.info(f"🔍 Vulnérabilités trouvées: {grand_total}")
            
            for url, res in all_results.items():
                logger.info(f"\n  {url}: {res['total_vulns']} vulns")
            
            logger.info("★"*70)
            
            await analyzer_helper.close()
            print('VULNS')
            print(v[:10])
            return all_results
    
    def test_all(self) -> None:
        """
        Lance tous les tests unitaires.
        
        Exécute test_check() et test_utils() et affiche
        le temps total d'exécution.
        """
        logger.info("\n" + "🔥"*60)
        logger.info("🔥 TEST COMPLET DU CODE ANALYZER")
        logger.info("🔥"*60)
        
        start = time.time()
        self.test_check()
        self.test_utils()
        logger.info("\n✅ Tests unitaires terminés")
        logger.info(f"⏱️  Temps: {time.time() - start:.2f}s")


async def main() -> None:
    """
    Fonction principale pour lancer les tests.
    
    Exécute les tests unitaires puis optionnellement
    les tests sur sites réels.
    """
    analyzer = CodeAnalyzer(debug=True)
    
    # Tests unitaires
    analyzer.test_all()
    
    # await analyzer.test_on_real_sites()
    
    input("Appuyez sur Entrée pour lancer les tests sur sites réels...")
    # Test sur un site spécifique
    return await analyzer.test_on_real_sites()


if __name__ == "__main__":
    ca = CodeAnalyzer(debug=True)
    print(ca.id_to_name("CredExpose"))
    
    results = asyncio.run(main())