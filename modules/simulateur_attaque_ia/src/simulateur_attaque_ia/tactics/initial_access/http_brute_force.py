#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr 23 07:56:40 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import json
import traceback
import asyncio
import requests
import concurrent.futures
from tactics.base import Base
from tactics.mittres import MITRE
from simulateur_utils.utils import normalize_link, HEADERS, clean_url
from tactics.initial_access.data.http_brute_force.http_helper import CATEGORY, COMMON_PATHS
from simulateur_utils.logger import get_logger

logger = get_logger()

class HTTPBruteForce(Base):
    def __init__(self, name="http_brute_force", timeout=2, preference='https://', **kwargs):
        super().__init__(name, **kwargs)
        self.name = name
        self.timeout = timeout
        self.preference = preference
        self.category = CATEGORY or {}
        self.start_time = time.time()
        self.results = {}
        self.founds = []
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=16,
            thread_name_prefix="http_brute_force_"
        )

    def normalize_url(self, url:str, url2:str=""):
        if not url:
            return None
        
        url = clean_url(url, preference=self.preference)
        try:
            normalized = normalize_link(url, url2)
        except Exception:
            normalized = ''

        if normalized is None:
            normalized = ''
        return normalized

    def send_request(self, url):
        try:
            response = requests.get(url, timeout=self.timeout, allow_redirects=True, verify=False, headers=HEADERS)
            return {
                'url': url,
                'status': int(response.status_code),
                'found': True if int(response.status_code) in (200, 403,204, 401) else False,
                'category': self.category.get(int(response.status_code), 'other')
            }
        except requests.Timeout:
            return {'url': url, 'status': 'timeout', 'found': False, "category": "other"}
        except requests.ConnectionError:
            return {'url': url, 'status': 'error', 'found': False, "category": "other"}
        except Exception as e:
            return {'url': url, 'status': str(e), 'found': False, "category": "other"}

    async def find_all_workers(self, url, path):
        new_url = self.normalize_url(url, path)
        if new_url:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                self.thread_pool,
                self.send_request,
                new_url
            )
            return path, result
        return path, {'url': url, 'status': "url invalide", 'found': False, "category": "other"}
    
    async def find_all_async(self, url:str, paths:list, add_common=False, port:str=None):
        if not url:
            raise ValueError("{ATTACK] URL manquante !")
        url = str(url)
        if port :
            url = f'{url}:{port}'
        if add_common:
            paths = list(set(paths or [])) + list(set(COMMON_PATHS))
        else:
            paths = paths or COMMON_PATHS

        self.log(f"Début HTTP BRUTE FORCE à : {time.ctime()}, pour url : {url} et {len(paths)} paths", log=True)
        self.log(paths)
        
        tasks = [
            asyncio.create_task(
                self.find_all_workers(url, path)
            )
            for path in paths
        ]
        results = await asyncio.gather(*tasks)
        for path, result in results:
            self.results[path] = result
            if result.get('found', False):
                status = result['status']
                category = result['category']
                self.log(f"✅ FOUND: {path} → {status} ({category})", log=True)
                self.founds.append(result)
            else:
                self.log(f"❌ NOT FOUND: {path}", log=True)
                
        self.end_time = time.time()
        self.log(f"Fin HTTP BRUTE FORCE : {len(self.results)} tentatives", log=True)
        self.log(f"Réponses positives : {len(self.founds)}", log=True)
        
        return self.get_result()
    
    def find_all_sync(self, *args, **kwargs):
        return asyncio.run(self.find_all_async(*args, **kwargs))

    def get_result(self):
        self.save()
        
        total_attempts = len(self.results)
        total_found = len(self.founds)
        mitres = [MITRE.get("HTTPBruteForce", {})]
        results = {
            'severity': 'LOW',
            'elapsed': self.end_time - self.start_time,
            "mitres": mitres,
            'results': {
                'founds': self.founds,
                'all_attempts': self.results,
                'total_attempts': total_attempts,
                'success_rate': total_found / total_attempts if total_attempts > 0 else 0
            },
        }
    
        return results

def test_http_brute_force(ip):
    from pprint import pprint
    http = HTTPBruteForce(timeout=3, preference="http://")
    result = http.find_all_sync(ip, paths=["/",'/admin', '/backup', '/notfound','/login', '/search','/api/data'], port=9090)
    try:
        logger.print("✅ Résultat :")
        logger.print(f"  Elapsed        : {result['elapsed']:.2f}s")
        logger.print(f"  Success Rate   : {result['results']['success_rate']:.2f}")
        logger.print(f"  Nombre total d'essai  : {len(result['results']['all_attempts'])}", verify=False)
        logger.print(f"  Crédentials Trouvés  : {result['results']['founds']}", verify=False)
        logger.print(json.dumps(result['results']["all_attempts"], indent=2), verify=False)
    except Exception:
        try:
            logger.print(pprint(result['results']["all_attempts"], indent=2))
        except Exception:
            logger.print(result['results']["all_attempts"])
    
