#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 20 10:02:51 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import shutil
import platform
import subprocess
from datetime import datetime
from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from simulateur_attaque_ia.core.services_manager import ServiceManager

logger = get_logger()


LINUX_EXCLUSIONS = [
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/media/",
    "/mnt/",
    "/tmp/",
    "/var/",
    "*.log",
    "*.tmp",
    "/swapfile/",
    "/swap.img",
    "/lost+found"
]

MAC_EXCLUSIONS = [
    "/dev/",
    "/private/",
    "/Volumes/",
    "/Network/",
    "/Library/Caches/",
    "/System/Volumes/",
    "/.fseventsd/",
    ".Spotlight-v100",
    "/.MobileBackups",
    "/.TimeMachine",
    '/.Trashes/',
    '/.TemporaryItems/',
    '/.vol',
    '*.log',
    '*.tmp',
    '/var/vm/sleepimage'
]

WINDOWS_EXCLUSIONS = [
    "C:\\Windows\\Temp\\",
    "C:\\Windows\\Prefetch\\",
    "C:\\Windows\\Logs\\",
    "C:\\Users\\*\\AppData\\Local\\Temp\\",
    "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\",
    "C:\\$Recycle.Bin\\",
    "C:\\System Volume Information\\",
    "*.log",
    "*.tmp",
    "*.cache",
    "C:\\Windows\\CSC\\"
]

class CopyManager:
    def __init__(self):
        self.os_name = self.get_os_name()
        self.default_path = "C:\\" if self.os_name == "windows" else "/"
        if self.os_name == "macos":
            self._excludes = MAC_EXCLUSIONS 
        elif self.os_name == "linux":
            self._excludes = LINUX_EXCLUSIONS
        elif self.os_name == "windows":
            self._excludes = WINDOWS_EXCLUSIONS
        else:
            self._excludes = []
        
    def get_os_name(self):
        if os.name.lower() == "nt":
            return "windows"
        else:
            name = platform.system().lower()
            if name == "darwin":
                return "macos"
            return "linux"
    
    
    def get_sys_info(self, path:str = "/"):
        try:
            disk_usage = shutil.disk_usage(path)
            info = {}
            info['total'] = float(f"{disk_usage.total / (1024 ** 3):.2f}")
            info['free'] = float(f"{disk_usage.free / (1024 ** 3):.2f}")
            info['used'] = float(f"{disk_usage.used / (1024 ** 3):.2f}")
            logger.print("Stats d'utilisation du disk, chemin :", path)
            for k, v in info.items():
                logger.print(k, "---->", v)
            return info
        except Exception as e:
            logger.print("Erreur dans l'obtention des stats d'utilisation du disk :", str(e))
            return {}
    
    def run_cmd(
        self, 
        cmd:list|str,
        check:bool = False, 
        shell:bool = False, 
        success_msg: str = None, 
        error_msg: str = None
    ):
        if shell:
            if isinstance(cmd, list):
                cmd = ' '.join(cmd)
        else:
            if isinstance(cmd, str):
                cmd = cmd.split()
        
        cmd_display = cmd if isinstance(cmd, str) else ' '.join(cmd[:50])
        try:
            r = subprocess.run(cmd, shell=shell, check=check, capture_output=True, text=True)
            logger.print("Cmd : ", cmd_display)
            if r.returncode == 0:
                if success_msg:
                    logger.print(f"  {success_msg}")
                if r.stdout:
                    logger.print(f"    ✓ Stdout: {r.stdout.strip()[:300]}")
            else:
                if error_msg:
                    logger.print(f"    ❌ {error_msg}")
                if r.stderr:
                    logger.print(f"    ⚠️ Stderr: {r.stderr.strip()[:200]}")
            
            return r.returncode
            
        except subprocess.CalledProcessError as e:
            logger.print(f"    ❌ Échec (code {e.returncode})")
            if e.stderr:
                logger.print(f"    ⚠️ Stderr: {e.stderr.strip()[:200]}")
            if check:
                raise
            return e.returncode
        except Exception as e:
            logger.print(f"    ❌ Exception: {e}")
            if check:
                raise
            return 1

    def _get_timestamp(self):
        tms = datetime.now().strftime('%Y%m%d_%H%M%S')
        return tms
    
    def tar_compression(self, output_file:str = "archive.tar.gz", work_dir:str = None):
        if not output_file or not work_dir:
            return False
        else:
            if not output_file.endswith(".tar.gz"):
                output_file = output_file + ".tar.gz"
        
        cmd = [
            "tar", "-czvf", 
            output_file, "-C", work_dir, "."
            ]
        
        returncode = self.run_cmd(
            cmd=cmd,
            shell=False,
            check=False,
            success_msg=f"Compression tar de {work_dir} dans {output_file} réussie",
            error_msg=f"Compression tar de {work_dir} dans {output_file} échouée",
        )
        return returncode, returncode == 0
    
    def rsync_copy(self, src:str, dest:str = "/backup", remove_back_up = True):
        if self.os_name not in ("linux", "macos"):
            logger.print("❌ rsync supporté uniquement pour linux et macos !")
            return {
                "success": False,
                "output": None,
                "size": None,
                "method": "rsync",
                "error": "OS non supporté"
            }
        copy_dir = os.path.join(dest, "system/")
        tms = self._get_timestamp()
        archive_file = os.path.join(dest, f"archive_system-{tms}.tar.gz")
        os.makedirs(copy_dir, exist_ok=True)
        if not src.endswith("/"):
            src = src + "/"
        rsync_cmd = [
            "rsync", "-aAxXvh",
            "--progress"
        ]
        exclusion = self._excludes
        rsync_cmd.extend([f"--exclude={exc}" for exc in exclusion])
        rsync_cmd.extend([src, copy_dir])
        logger.print(f"📦 Copy Rsync de {src} vers {copy_dir}...")
        returncode = self.run_cmd(
            cmd=rsync_cmd,
            check=False,
            shell=False,
            success_msg=f"✅ Copy Rsync de {src} vers {copy_dir} terminée avec succès",
            error_msg=f"Copy Rsync de {src} vers {copy_dir} échouée"
        )
        if returncode == 0:
            logger.print(f"📦 Compression tar de {copy_dir} vers {archive_file}...")
            _, succes = self.tar_compression(
                output_file=archive_file,
                work_dir=copy_dir,
            )
            if succes:
                self.run_cmd(
                    f"tar -tf  {archive_file} | head -10", shell=True,
                    check=False,
                    success_msg="Archive bien crée !",
                    error_msg="Erreur dans la vérification du contenue de l'archive"
                )
            if remove_back_up:
                self.run_cmd(
                    cmd=["rm", "-rf", copy_dir],
                    shell=False,
                    check=False,
                    error_msg="Erreur de la suppression du backup",
                    success_msg="Backup dupprimé avec succès !"
                )
                
            size = os.path.getsize(archive_file) / (1024**3)
            logger.print(f"✅ Backup compressé: {size:.2f} GB")
            return {
                "success": True,
                "output": archive_file,
                "size": size,
                "method": "rsync"
                }
        else:
            logger.print("❌ Erreur dans la copy rsync, la compression tar est donc annulé !")
            return {
                "success": False,
                "output": archive_file,
                "size": None,
                "method": "rsync"
                }
        
    def robocopy_copy(self, src:str, dest:str = "C:\\backup", remove_back_up = True):
        if self.os_name != "windows":
            logger.print("❌ robocopy n'est disponible que sur Windows !")
            return {
                "success": False,
                "output": None,
                "size": None,
                "method": "robocopy",
                "error": "OS non supporté"
            }
        
        if dest.endswith("\\"):
            dest = dest[:-1]
        
        copy_dir = os.path.join(dest, "system\\")
        tms = self._get_timestamp()
        archive_file = os.path.join(dest, f"archive_system-{tms}.tar.gz")
        
        os.makedirs(copy_dir, exist_ok=True)
        
        robocopy_cmd = [
            "robocopy",
            src,
            copy_dir,
            "/E",           # Copier les sous-répertoires, y compris les vides
            "/COPY:DAT",    # Copier les données, attributs, timestamps
            "/R:3",         # 3 tentatives en cas d'échec
            "/W:10",        # Attendre 10 secondes entre les tentatives
            "/NP",          # Pas de progression (pour logs plus propres)
            "/NDL",         # Pas de log des répertoires
            "/NFL",         # Pas de log des fichiers
            "/NJH",         # Pas d'en-tête de job
            "/NJS"          # Pas de résumé de job
        ]
        
        for exc in self._excludes:
            robocopy_cmd.extend(["/XD", exc])
        
        logger.print(f"📦 Copy Robocopy de {src} vers {copy_dir}...")
        returncode = self.run_cmd(
            cmd=robocopy_cmd,
            check=False,
            shell=False,
            success_msg=f"✅ Copy Robocopy de {src} vers {copy_dir} terminée avec succès",
            error_msg=f"Copy Robocopy de {src} vers {copy_dir} échouée"
        )
        
        # Robocopy retourne des codes spécifiques (0-7 = succès partiel ou total)
        # 0 = Aucun fichier copié, 1 = Fichiers copiés avec succès, etc.
        is_success = returncode <= 7
        if is_success:
            logger.print(f"📦 Compression tar de {copy_dir} vers {archive_file}...")
            _, succes = self.tar_compression(
                output_file=archive_file,
                work_dir=copy_dir,
            )
            
            if succes:
                self.run_cmd( 
                    f"tar -tf {archive_file}", 
                    shell=True,
                    check=False,
                    success_msg="Archive bien créée !",
                    error_msg="Erreur dans la vérification du contenu de l'archive"
                )
    
            if remove_back_up:
                self.run_cmd(
                    cmd=["rmdir", "/S", "/Q", copy_dir],
                    shell=False,
                    check=False,
                    error_msg="Erreur de la suppression du backup",
                    success_msg="Backup supprimé avec succès !"
                )
            
            size = os.path.getsize(archive_file) / (1024**3)
            logger.print(f"✅ Backup compressé: {size:.2f} GB")
            return {
                "success": True,
                "output": archive_file,
                "size": size,
                "method": "robocopy"
            }
        else:
            logger.print("❌ Erreur dans la copy robocopy, la compression tar est donc annulée !")
            return {
                "success": False,
                "output": archive_file,
                "size": None,
                "method": "robocopy"
            }

    
    def copy_system(self, src: str = None, dest: str = None, remove_back_up: bool = True):
        """Méthode unifiée qui choisit automatiquement la bonne méthode"""
        if src is None:
            src = self.default_path
        if dest is None:
            dest = "C:\\backup" if self.os_name == "windows" else "/backup"
        
        st = time.time()
        if self.os_name == "windows":
            result = self.robocopy_copy(src, dest, remove_back_up)
        else:
            result = self.rsync_copy(src, dest, remove_back_up)
        
        elapsed = time.time() - st
        logger.print(f"Fin copy en {elapsed:.2f} secondes")
        return result
        
    
    def get_container_name(self):
        date = datetime.now().strftime('%Y%m%d_%H%M%S')
        return 'clone' + f'_{date}'
    
    def find_available_shell(self, container_name):
        shells_to_try = ["/bin/bash", "/bin/sh",
                         "/bin/ash", "/bin/zsh", "/bin/dash"]

        for shell in shells_to_try:
            cmd = f"docker run --rm {container_name}:latest test -f {shell}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ Shell trouvé: {shell}")
                return shell

        cmd = f"docker run --rm {container_name}:latest ls -la /bin 2>/dev/null | head -20"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print("⚠️ Aucun shell standard trouvé!")
        print(f"Contenu de /bin:\n{result.stdout}")

        cmd = f"docker run --rm {container_name}:latest find /bin -type f -executable 2>/dev/null | head -1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.stdout.strip():
            shell = result.stdout.strip()
            print(f"✅ Utilisation du shell trouvé: {shell}")
            return shell
        return "/bin/bash"
    
    def clone(
        self, 
        src:str = None, 
        dest:str = None, 
        archive_path:str = None, 
        remove_back_up:bool = True,
        container_name:str = None,
        network_caps:bool = False,
        authorize_network:bool = False,
    ):
        if not container_name:
            container_name = self.get_container_name()
        logger.print('[WARNING] CLONAGE via DOCKER, assurez vous d\'avoir DOCKER installé !')
        logger.print('Nom du container : ', container_name)
        
        if archive_path:
            if not os.path.exists(archive_path):
                logger.print(f"❌ Fichier non trouvé: {archive_path}")
                return False
            logger.print('Dossier tar suggéré par l\'utilisateur : ', archive_path)
            
        else:
            copy_result = self.copy_system(
                src=src, dest=dest, remove_back_up=remove_back_up
            )
            if not copy_result["success"]:
                logger.print("Copy échoué !")
                return {
                    "success": False,
                    "container_name": container_name,
                    }
            
            archive_path = copy_result["output"]
        
        cmd = [
            "docker", "import",
            archive_path, f"{container_name}:latest"
        ]
        logger.print('Debut de la clonnage à : ', time.ctime())
        st = time.time()
        returncode = self.run_cmd(
            cmd=cmd,
            check=False,
            shell=False,
            success_msg="Succès de la création du container !",
            error_msg="Création du container échoué !",
        )
        if returncode != 0:
            logger.print("❌ Échec du clonage")
            return {
                "success": False,
                "container_name": container_name,
                }
        
        logger.print('Clonnage finie en : ', time.time() - st, 'secs')
        logger.print(f"✅ Système restauré dans container: {container_name}")
        shell = self.find_available_shell(container_name)
        add = ""
        if network_caps:
            add = "--cap-add=NET_RAW --cap-add=NET_ADMIN"
        
        if not authorize_network:
            add += " --network=isolated"
        
        explore_cmd = f"docker run -it --rm {add} {container_name}:latest {shell}"
        services = ServiceManager.capture_services()
        service_path = ServiceManager.save(
            services=services,
            name=container_name
        )
        logger.print("💡 Commande rapide pour explorer les fichiers")
        logger.print(f"  Shell : {shell}")
        logger.print(f"   {explore_cmd}")
        return {
            "success": True,
            "container_name": container_name,
            "explore_cmd": explore_cmd,
            "services_path": service_path,
            "services": services
        }
        

if __name__ == "__main__":
    logger.print("=" * 60)
    logger.print("🧪 TEST DU CopyManager")
    logger.print("=" * 60)
    
    # Créer une instance du gestionnaire
    manager = CopyManager()
    
    # Afficher l'OS détecté
    logger.print(f"\n🖥️  OS détecté: {manager.os_name}")
    logger.print(f"📁 Chemin par défaut: {manager.default_path}")
    
    # Tester get_sys_info
    logger.print("\n📊 Test de get_sys_info:")
    sys_info = manager.get_sys_info(manager.default_path)
    if sys_info:
        logger.print(f"   - Total: {sys_info.get('total')} GB")
        logger.print(f"   - Utilisé: {sys_info.get('used')} GB")
        logger.print(f"   - Libre: {sys_info.get('free')} GB")
    
    # Tester la méthode de copie selon l'OS
    logger.print("\n🔄 Test de la méthode de copie:")
    
    if manager.os_name == "windows":
        # Test avec robocopy sur Windows
        logger.print("\n📦 Test de robocopy_copy:")
        # Créer un réperoire de test
        test_src = "C:\\Windows\\System32\\drivers\\etc"
        test_dest = "C:\\temp_backup_test"
        
        logger.print(f"   Source: {test_src}")
        logger.print(f"   Destination: {test_dest}")
        
        result = manager.robocopy_copy(
            src=test_src,
            dest=test_dest,
            remove_back_up=True
        )
        
        logger.print("\n📊 Résultat:")
        logger.print(f"   - Succès: {result.get('success')}")
        logger.print(f"   - Méthode: {result.get('method')}")
        logger.print(f"   - Fichier: {result.get('output')}")
        if result.get('size'):
            logger.print(f"   - Taille: {result.get('size'):.2f} GB")
    
    else:
        # Test avec rsync sur Linux/Mac
        logger.print("\n📦 Test de rsync_copy:")
        test_src = "/home/hounsousamuel/PROJET/PROJET ZERO"
        test_dest = "/tmp/backup_test"
        
        logger.print(f"   Source: {test_src}")
        logger.print(f"   Destination: {test_dest}")
        
        # Décommenter pour tester (attention: nécessite rsync installé)
        result = manager.rsync_copy(
            src=test_src,
            dest=test_dest,
            remove_back_up=True
        )
        
        logger.print("\n📊 Résultat:")
        logger.print(f"   - Succès: {result.get('success')}")
        logger.print(f"   - Méthode: {result.get('method')}")
        logger.print(f"   - Fichier: {result.get('output')}")
        if result.get('size'):
            logger.print(f"   - Taille: {result.get('size'):.2f} GB")
        
        logger.print("   ⚠️ Test commenté - nécessite rsync installé")
    
    # Tester la compression tar directement
    logger.print("\n📦 Test de tar_compression:")
    # Créer un petit répertoire de test
    test_dir = os.path.join(os.path.dirname(__file__), "test_temp")
    os.makedirs(test_dir, exist_ok=True)
    
    # Créer un fichier test
    test_file = os.path.join(test_dir, "test.txt")
    with open(test_file, "w") as f:
        f.write("Ceci est un fichier de test pour la compression tar.gz")
    
    test_archive = os.path.join(os.path.dirname(__file__), "test_archive.tar.gz")
    returncode, success = manager.tar_compression(
        output_file=test_archive,
        work_dir=test_dir,
    )
    
    logger.print(f"   - Succès: {success}")
    logger.print(f"   - Archive: {test_archive}")
    
    if success and os.path.exists(test_archive):
        size = os.path.getsize(test_archive) / 1024
        logger.print(f"   - Taille: {size:.2f} KB")
        # Nettoyer
        os.remove(test_archive)
    
    # Nettoyer le répertoire test
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
        logger.print("   - Nettoyage effectué")
    
    tar = "/run/media/hounsousamuel/BACKUP/system-20251122_082851.tar"
    manager.clone(src=None, dest=None, archive_path=tar)
    logger.print("\n" + "=" * 60)
    logger.print("✅ Tests terminés")
    logger.print("=" * 60)
            