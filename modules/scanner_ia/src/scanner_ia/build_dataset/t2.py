#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep 17 17:58:12 2026

@author: hounsousamuel
"""

import asyncio
import joblib
from scanner_ia.base_class.analyser_helper_base_class import AnalyzerHelperResult
from scanner_ia.analyzers.code_analyzer import CodeAnalyzer
from scanner_ia.analyzers.passive_analyzer import PassiveCodeAnalyzer
from scanner_ia.base_class.fuzzer_base_class import FuzzerResult
from scanner_ia.ml_model.features_extractor import FeatureExtractor

FUZZER_COLS = [
    'fuzzer_SQLi', 'fuzzer_CMDi', 'fuzzer_InsecDeser', 'fuzzer_InsecUpload',
    'fuzzer_BufOvr', 'fuzzer_CredsExpose', 'fuzzer_BrokenAuth', 'fuzzer_XSS',
    'fuzzer_DirTrav', 'fuzzer_XXE', 'fuzzer_NoSQLi', 'fuzzer_LDAPi',
    'fuzzer_InsecPerm', 'fuzzer_IDOR', 'fuzzer_SessFix', 'fuzzer_SSRF',
    'fuzzer_SSTI', 'fuzzer_Prototype_Pollution', 'fuzzer_HTTP_Request_Smuggling',
    'fuzzer_XPATH_Injection', 'fuzzer_GraphQLi', 'fuzzer_CORS', 'fuzzer_CSRF',
    'fuzzer_RateLimit', 'fuzzer_InfoDisc', 'fuzzer_InsecCrypto',
    'fuzzer_OpenRedirect', 'fuzzer_JWT', 'fuzzer_CRLF_Injection',
    'fuzzer_RaceCondition',
    'num_active_test', 'fuzer_ratio_vuln', 'fuzzer_ratio_indicators_matched',
    'fuzzer_ration_status_changed', 'fuzzer_ratio_headers_changed',
    'fuzzer_ratio_body_changed', 'fuzzer_max_score',
]

async def rebuild(data: dict[str, AnalyzerHelperResult], concurrency: int = 30):
    
    dlen = len(data)
    async def worker(
        queue: asyncio.Queue, lock: asyncio.Lock, result: dict,
        code_analyzer: CodeAnalyzer, passive_analyzer: PassiveCodeAnalyzer, 
        feature_extractor: FeatureExtractor, fr: FuzzerResult
    ):
        while True:
            item = await queue.get()
            if item is None:  # signal d'arrêt
                queue.task_done()
                print("Fin !")
                break
            
            idx, key, analyzer_response = item
            print(idx, "/", dlen)
            ca_result = code_analyzer.analyse(analyzer_response)
            pa_result = passive_analyzer.analyse(analyzer_response)
            features = await feature_extractor.extract(
                analyzer_response, pa_result, ca_result, fr
            )
            features.reset_index(drop=True, inplace=True)
            async with lock:
                result[key] = features
            queue.task_done()
        
    
    queue = asyncio.Queue()
    for idx, (key, ar) in enumerate(list(data.items())):
        queue.put_nowait((idx, key, ar))
    for _ in range(concurrency):
        queue.put_nowait(None) 
    
    lock = asyncio.Lock()
    fr = FuzzerResult()
    code_analyzer = CodeAnalyzer()
    passive_analyzer = PassiveCodeAnalyzer()
    feature_extractor = FeatureExtractor()
    result = {}
    workers = [
        asyncio.create_task(
            worker(
                lock=lock, result=result, queue=queue,
                code_analyzer=code_analyzer, passive_analyzer=passive_analyzer,
                feature_extractor=feature_extractor, fr=fr,
            )
        )
        for _ in range(concurrency)
    ]
    await queue.join()
    for _ in workers:
        _.cancel()
        try:
            await _
        except Exception:
            pass
        
    await asyncio.gather(*workers, return_exceptions=True)
    joblib.dump(result, "./crawl_final_result")
    return result

if __name__ == "__main__":
    import nest_asyncio
    nest_asyncio.apply()
    path = '/home/hounsousamuel/PROJET/obsidian_hive/modules/scanner_ia/src/scanner_ia/build_dataset/crawl_result_'
    data = joblib.load(path)
    r = asyncio.run(rebuild(data, 6000))