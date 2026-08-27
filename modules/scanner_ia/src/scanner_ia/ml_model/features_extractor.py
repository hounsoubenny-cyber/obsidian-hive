#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 18 11:22:09 2026

@author: hounsousamuel
"""

import os
import asyncio
import aiohttp
import traceback
import pandas as pd
import numpy as np
from collections import defaultdict
from sklearn.experimental import enable_iterative_imputer
from sklearn.impute import IterativeImputer
from scanner_ia.scanner_utils.utils_scanner import calculate_entropy
from scanner_ia.base_class.analyser_helper_base_class import AnalyzerHelperResult, OneAnalyzerHelperResult
from scanner_ia.base_class.fuzzer_base_class import FuzzerResult
from scanner_ia.base_class.feature_extractor_base_class import WorkerExtractorEntry
from scanner_ia.base_class.passive_analyzer_base_class import PassiveAnalyzerResult, PagePassiveResult
from scanner_ia.base_class.code_analyse_base_class import CodeAnalyzerResult, CheckResult
from scanner_ia.ml_model.config import VULNS, FEATURES_BY_CATEGORY, FEATURES_LIST
from scanner_ia.scanner_utils.logger import get_logger

feature_extractor_logger = get_logger()

pd.set_option("display.max_rows", 200)
pd.set_option("display.max_columns", 200)

TECHS = {
    'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
    'joomla': ['joomla', 'com_'],
    'drupal': ['drupal'],
    'laravel': ['laravel', 'csrf-token'],
    'django': ['django', 'csrftoken'],
    'express': ['express', 'node'],
    'php': ['.php', 'php/'],
    'aspnet': ['.aspx', 'asp.net'],
    'jquery': ['jquery'],
    'angular': ['angular', 'ng-'],
    'react': ['react', 'react-dom']
}

class FeatureExtractor:
    """
    Classe dédiée à l'extraction des features.
    Ses methodes:
        save_dataset(synchrone).
        _process_data(synchrone, privée).
        _create_worker_entry(asynchrone, privée).
        extract(asynchrone). Méthode principale d'extraction des features.
        get_features_name(synchrone).
    """
    @staticmethod
    def save_dataset(data:pd.DataFrame|np.ndarray, path:str) -> bool:
        """
        Méthode de sauvegarde du dataset.

        Parameters
        ----------
        data : pd.DataFrame|np.ndarray
            Les données.
        path : str
            Chemin où sauvegarder les données.

        Returns
        -------
        bool
            Flage de succès.

        """
        try:
            base = os.path.splitext(path)[0]
            data = pd.DataFrame(data)
            pd.to_pickle(data.to_dict(orient="records"), base + ".pkl")
            data.to_csv(base + ".csv", index=False)
            feature_extractor_logger.success(f"""Données sauvegardé en pkl(dict) et en csv dans {base + ".pkl"} et {base + ".csv"}""")
            return True
        except Exception as e:
            feature_extractor_logger.error(f"Erreur lors de la sauvegarde des données : {str(e)}")
            feature_extractor_logger.error(f"Traceback : \n {traceback.format_exc()}")
            return False
    
    def _process_data(self, data:pd.DataFrame|np.ndarray, impute:bool = True, special_cols:list[str] = None) -> pd.DataFrame|np.ndarray:
        """
        Méthode de traitement des données après extraction.

        Parameters
        ----------
        data : pd.DataFrame|np.ndarray
            Les données.
        impute : bool, optional
            Flag pour imputation des NaN. The default is True.
        special_cols : list[str], optional
            Des collonnes à exclure dans le traitement. The default is [].

        Returns
        -------
        TYPE
            Les données traitées.

        """
        special_cols = special_cols or []
        try:
            is_np = isinstance(data, np.ndarray)
            frame = pd.DataFrame(data)
            num_isna = frame.isna().sum().sum()
            try:
                describe = frame.describe()
                feature_extractor_logger.info(f'Describe : \n{describe}')
            except Exception as e:
                feature_extractor_logger.warning(f"Erreur sur describe : {str(e)}")
            cols_values = None
            if special_cols:
                special_cols = [col for col in special_cols if col in frame.columns]
                cols_values = frame[special_cols]
                frame.drop(special_cols, axis=1, inplace=True)
            feature_extractor_logger.info(f"Num NaN : {num_isna}")
            # feature_extractor_logger.info(f'Describe : \n{describe}')
            if impute and num_isna != 0:
                imputer = IterativeImputer(
                    random_state=42,
                    max_iter=30,         
                    tol=1e-3,            
                    verbose=0
                )
                frame = pd.DataFrame(
                    imputer.fit_transform(frame),
                    columns=frame.columns,
                    index=frame.index
                )
            if cols_values is not None:
                frame = pd.concat([cols_values, frame], axis=1)
                if impute and num_isna != 0:
                    feature_extractor_logger.info('Après imputation : ', frame.isna().sum().sum())
                # feature_extractor_logger.info(data)
        except Exception as e:
            feature_extractor_logger.error(f"Erreur lors du processing des données : {str(e)}")
            feature_extractor_logger.error(f"Traceback : \n {traceback.format_exc()}")
            
        return frame.to_numpy() if is_np else frame
    
    async def _create_worker_entry(
        self,
        analyzer_helper_result:AnalyzerHelperResult,
        passive_analyzer_result:PassiveAnalyzerResult,
        code_analyzer_result:CodeAnalyzerResult,
        fuzzer_result:FuzzerResult = None,
    ) -> dict[str, WorkerExtractorEntry]:
        
        entries = {}
        elements = 0
        if not isinstance(fuzzer_result, FuzzerResult):
            fuzzer_result = FuzzerResult()
        for url, page in analyzer_helper_result.elements.items():
            entry = WorkerExtractorEntry()
            entry.url = url
            fuzzer_match = [worker_result for worker_result in fuzzer_result.results if worker_result.url == url]
            elements += len(fuzzer_match)
            entry.fuzzer_element = fuzzer_match
            entry.analyzer_helper_element = page
            entry.passive_analyzer_result = passive_analyzer_result.pages.get(url, PagePassiveResult())
            entry.code_analyzer_result = code_analyzer_result.results.get(url, None)
            entries[url] = entry
            
        feature_extractor_logger.info(f" Nombre d'element du fuzzer = {len(fuzzer_result.results)}, pris en compte {elements}")
        if len(fuzzer_result.results) == elements:
            feature_extractor_logger.success("Tout les éléments ont été pris en compte")
        
        return entries
            
    async def extract(
        self, 
        analyzer_helper_result:AnalyzerHelperResult,
        passive_analyzer_result:PassiveAnalyzerResult,
        code_analyzer_result:CodeAnalyzerResult,
        fuzzer_result:FuzzerResult = FuzzerResult(),
    ) -> pd.DataFrame:
        """
        Méthode d'extraction des features.

        Parameters
        ----------
        analyzer_helper_result : AnalyzerHelperResult
            Sortie de AnalyzerHelper.
        passive_analyzer_result : PassiveAnalyzerResult
            Sortie de PassiveCodeAnalyzer.
        code_analyzer_result : CodeAnalyzerResult
            Sortie de CodeAnalyzer.
        fuzzer_result : FuzzerResult, optional
            Sortie du Fuzzer. The default is FuzzerResult().

        Returns
        -------
        dataset : DataFrame
            Données extraites.

        """
        dataset:list[dict] = []  # Liste de dictionnaire, a convertir en DataFrame
        entries = await self._create_worker_entry(
            analyzer_helper_result,
            passive_analyzer_result,
            code_analyzer_result,
            fuzzer_result
            )
        
        async def _extract(
            url:str,
            dataset:list,
            lock:asyncio.Lock
        ) -> None:
            try:
                data = None
                result = {}
                async with lock:
                    data:WorkerExtractorEntry = entries[url]
                    
                if data is None:
                    return
                
                # Analyse du OneAnalyzerHelperResult
                analyzer_helper_element:OneAnalyzerHelperResult = data.analyzer_helper_element
                balises_name = ['a', 'img', 'script', 'link', 'style', 'iframe', 'video', 
                             'audio', 'embed', 'object', 'form', 'meta', 'cite']
                
                balise_num = {f"num_balise_{k}": len(analyzer_helper_element.parsed[k].elements) for k in balises_name}
                js_code = ""
                for element in analyzer_helper_element.parsed.script.elements:
                    js_code += element.get("contenu", "") + "\n"
                    
                body = analyzer_helper_element.fetched.body
                num_html_link = analyzer_helper_element.crawl.nbr_html_links
                num_other_link = analyzer_helper_element.crawl.nbr_other_links
                
                result.update({
                        "url": url,
                        "status_code" : int(analyzer_helper_element.fetched.status_code or 000),
                        "deep": int(analyzer_helper_element.crawl.deep or 0),
                        "response_time" : float(analyzer_helper_element.fetched.delay or 0.0),
                        "body_length" : analyzer_helper_element.fetched.body_length(),
                        "body_entropy" : calculate_entropy(body),
                        "js_code_entropy" : calculate_entropy(js_code) if js_code else 0.0,
                        "has_password_field": int("type='password'" in body or 'type="password"' in body),
                        "has_file_upload": int("type='file'" in body or 'type="file"' in body),
                        "has_hidden_fields": int("type='hidden'" in body or 'type="hidden"' in body),
                        "num_links" : num_html_link + num_other_link,
                        "num_html_link": num_html_link,
                        "other_link_ratio" :  num_other_link / max(num_html_link + num_other_link, 1),
                        "n_redirects": len(analyzer_helper_element.fetched.history),
                    })
                result.update(balise_num)
                
                security_report = {}
                if analyzer_helper_element.parsed.headers.elements:
                    security_report = analyzer_helper_element.parsed.headers.elements[0].get("security_report", {}) or {}
                    
                if not security_report:
                    headers = analyzer_helper_element.fetched.headers
                    security_report = {
                        "strict_transport_security": headers.get("strict-transport-security") is not None,
                        "x_frame_options": headers.get("x-frame-options") is not None,
                        "x_content_type_options": headers.get("x-content-type-options") is not None,
                        "content_security_policy": headers.get("content-security-policy") is not None, 
                        "x_xss_protection": headers.get("x-xss-protection") is not None,
                        "referrer_policy": headers.get("referrer-policy") is not None,
                        "permissions_policy": headers.get("permissions-policy") is not None,
                    }
                    
                for k in ("cookies_secure", "server", "powered_by"):
                    if k in security_report:
                        security_report.pop(k)
                
                result.update({k: int(v) for k, v in security_report.items()})
    
                #Techs
                result.update({
                    f"tech_{tech}": int(
                        any(
                            pattern in analyzer_helper_element.fetched.headers or \
                            pattern in body for pattern in patterns)
                        ) for tech, patterns in TECHS.items()
                    })
                    
                # Analyse du PassiveAnalyzerResult
                page_vuln:PagePassiveResult = data.passive_analyzer_result
                result.update({
                    "total_passive_issues": page_vuln.total_vulns,
                    "passive_high_count": page_vuln.high_count,
                    "passive_critical_count": page_vuln.critical_count,
                    })
                
                # Analyse du CodeAnalyzerResult
                code_vuln:PagePassiveResult = data.code_analyzer_result
                if code_vuln is not None:
                    body_vulns:CheckResult = code_vuln.get("body", CheckResult())
                    balises_script = code_vuln.get("balises_script", {})
                    result.update({
                        "code_body_total_vulns": body_vulns.total_vulns,
                        "code_body_critical_vulns": body_vulns.critical_count,
                        "code_body_medium_vulns": body_vulns.medium_count,
                        "code_body_high_vulns": body_vulns.high_count,
                        "code_body_low_vulns": body_vulns.low_count,
                        "code_body_max_score": body_vulns.max_score,
                        "code_scripts_total_vulns": sum(s.total_vulns for s in balises_script.values()),
                        "code_scripts_high_vulns": sum(s.high_count for s in balises_script.values()),
                        "code_scripts_critical_vulns": sum(s.critical_count for s in balises_script.values()),
                        "code_scripts_medium_vulns": sum(s.medium_count for s in balises_script.values()),
                        "code_scripts_low_vulns": sum(s.low_count for s in balises_script.values()),
                        # "code_scripts_max_score": max((s.max_score for s in balises_script.values()), default=0.0),
                        })
                    
                else:
                    #Mettre des valeurs par défaut
                    result.update({
                        "code_body_total_vulns": 0,
                        "code_body_critical_vulns": 0,
                        "code_body_medium_vulns": 0,
                        "code_body_high_vulns": 0,
                        "code_body_low_vulns": 0,
                        "code_body_max_score": 0,
                        "code_scripts_total_vulns": 0,
                        "code_scripts_high_vulns": 0,
                        "code_scripts_critical_vulns": 0,
                        "code_scripts_medium_vulns": 0,
                        "code_scripts_low_vulns": 0,
                        # "code_scripts_max_score": 0,
                        })
                
                #Fuzzer analyse
                fuzzer_element = data.fuzzer_element
                vuln_dict = defaultdict(int)
                for vuln in VULNS:
                    vuln_dict[f"fuzzer_{vuln}"] = 0
                    
                for worker_fuzzer in fuzzer_element:
                    worker_fuzzer.response_analyzer_result.found_indicators
                    if worker_fuzzer.response_analyzer_result.is_vulnerable:
                        vuln_dict[f"fuzzer_{worker_fuzzer.vuln_name}"] = 1
                
                result.update(vuln_dict)
                n_fuzzer = max(len(fuzzer_element), 1)
                result.update({
                    "num_active_test": len(fuzzer_element),
                    "fuzer_ratio_vuln": sum(vuln_dict.values()) / max(len(VULNS), 1),
                    "fuzzer_ratio_indicators_matched": sum(1 for worker_fuzzer in fuzzer_element if worker_fuzzer.response_analyzer_result.found_indicators) / n_fuzzer,
                    "fuzzer_ration_status_changed": sum(1 for worker_fuzzer in fuzzer_element if worker_fuzzer.response_analyzer_result.status_changed) / n_fuzzer,
                    "fuzzer_ratio_headers_changed": sum(1 for worker_fuzzer in fuzzer_element if worker_fuzzer.response_analyzer_result.headers_changed) / n_fuzzer,
                    "fuzzer_ratio_body_changed": sum(1 for worker_fuzzer in fuzzer_element if worker_fuzzer.response_analyzer_result.body_length_changed) / n_fuzzer,
                    "fuzzer_max_score": max((worker_fuzzer.response_analyzer_result.score for worker_fuzzer in fuzzer_element), default=0.0)
                    })
                
                async with lock:
                    dataset.append(result)
            except Exception as e:
                feature_extractor_logger.error(f"Erreur _extract(features): {str(e)}")
                feature_extractor_logger.error(traceback.format_exc())
                
        lock = asyncio.Lock()
        tasks = [
                asyncio.create_task(
                    _extract(url, dataset, lock)
                ) for url in entries.keys()
            ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                feature_extractor_logger.warning(f"Exception survenu dans un worker, {result}")
        
        dataset:pd.DataFrame = self._process_data(pd.DataFrame(dataset), True, special_cols=["url"])
        return dataset
    
    @staticmethod
    def get_features_name(by_cat:bool = False) -> list|dict:
        return FEATURES_BY_CATEGORY if by_cat else FEATURES_LIST

async def test_features(urls:list|None = [], max_tests:int|None = 100):
    from scanner_ia.core.analyzer_helper import AnalyzerHelper
    from scanner_ia.analyzers.code_analyzer import CodeAnalyzer
    from scanner_ia.analyzers.passive_analyzer import PassiveCodeAnalyzer
    from scanner_ia.fuzzer.active_fuzzer import Fuzzer, Config
    
    if urls is None:
        urls = ["http://localhost:8080", "http://localhost:5000"]
    datasets = []
    i = 0
    async with aiohttp.ClientSession() as session:
        an = AnalyzerHelper(session=session)
        ca = CodeAnalyzer(True)
        pa = PassiveCodeAnalyzer()
        fuzzer = Fuzzer(session=session)
        fuzzer.config.MAX_TEST = max_tests
        fe = FeatureExtractor()
        for url in urls:
            feature_extractor_logger.info(f"Traitement de l'url {url}, {i}/{len(urls)}")
            analyzer_response = await an.analyse_and_parse_all(url, verify_reachability=True, restore=True, silent=False)
            ca_result = ca.analyse(analyzer_response)
            pa_result = pa.analyse(analyzer_response)
            fuzzer_result = await fuzzer.fuzz(url, analyzer_response, dynamic_timeout=True)
            features = await fe.extract(analyzer_response, pa_result, ca_result, fuzzer_result)
            datasets.extend(features.to_dict(orient="records"))
            i += 1
            feature_extractor_logger.info(f"Fin pour url {url}, shape={features.shape}")
    
    datasets = pd.DataFrame(datasets)
    print("="*10)
    print(datasets[:10])
            
    
if __name__ == "__main__":
    FE = FeatureExtractor()
    print(len(FeatureExtractor.get_features_name()))
    asyncio.run(test_features(None, 100))
        