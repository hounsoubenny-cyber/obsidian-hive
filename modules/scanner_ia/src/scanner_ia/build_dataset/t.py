#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Sep 16 08:57:11 2026

@author: hounsousamuel
"""

import asyncio
import aiohttp
from scanner_ia.core.analyzer_helper import AnalyzerHelper
from scanner_ia.build_dataset.utils_update_json_features import (
    URLS, CHUNK_FILES as DATASET_PATHS
)
OUTPUT_PATHS = DATASET_PATHS.copy()

async def main(urls: list[str], concurrency: int = 10):
    queue = asyncio.Queue()
    for idx, url in enumerate(urls):
        queue.put_nowait((idx, url))
    for _ in range(concurrency):
        queue.put_nowait(None) 
        
    async def worker(an: AnalyzerHelper, lock: asyncio.Lock, result: dict, queue: asyncio.Queue, n_url: int):
        while True:
            item = await queue.get()
            if item is None:  # signal d'arrêt
                queue.task_done()
                print("Fin !")
                break
            
            idx, url = item
            print(f"[worker] ({idx} / {n_url} {url}")
            key = f"{url}__##__{idx}"
            r = await an.analyse_and_parse_all(
                url, verify_reachability=False,
                restore=False, fetch=True, silent=False, semaphore=10,
            )
            # print(f"{url} -> {r.to_dict(deep=True)}")
            async with lock:
                result[key] = r
                if len(result) > 0 and len(result) % 500 == 0:
                    import joblib
                    joblib.dump(result, "./crawl_result_1")
            await asyncio.sleep(0.001)
            queue.task_done()
            
    
    lock = asyncio.Lock()
    n_url = len(urls)
    result = {}
    connector = aiohttp.TCPConnector(
        limit=concurrency,
        force_close=True,        # pas de réutilisation de socket = plus de race
        enable_cleanup_closed=True,
    )
    async with aiohttp.ClientSession(connector=connector) as session:
        analyzer = AnalyzerHelper(session=session, use_cache=False)
        analyzer.crawler.config.MAX_WORKERS = 1
        analyzer.crawler.config.MAX_DEEPTH = 1
        analyzer.crawler.config.MAX_PAGES = 1
        analyzer.crawler.config.GET_TIMEOUT = 2
        analyzer.crawler.config.JOIN_TIMEOUT = 1 * 10 * 60
        analyzer.crawler.config.USE_CACHE_FOR_GET_LINKS = False
        analyzer.crawler.config.SAVE_ON_CRAWL = False
        analyzer.crawler.parser.fetcher.config.TIMEOUT = 12000
        workers = [
            asyncio.create_task(
                worker(an=analyzer, lock=lock, result=result, queue=queue, n_url=n_url)
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
    return result


if __name__ == "__main__":
    async def m():
        import pandas as pd
        dataframes = [pd.read_csv(p) for p in DATASET_PATHS]
        # samples_n = sum(df.shape[0] for df in dataframes)
        # urls = URLS[:samples_n]
        urls = [u for df in dataframes for u in df["url"]]
        del dataframes
        t = asyncio.create_task(main(urls, 100))
        import joblib
        r  = await t
        joblib.dump(r, "./crawl_result_1")
    
    from nest_asyncio import apply
    apply()
    asyncio.run(m())