#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 22 08:29:54 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from simulateur_utils.logger import get_logger
logger = get_logger()

from tactics.tests.environment import TestEnvironment
from tactics.reconnaissance.port_scan_and_banner_grab import test_network_service_discover
from tactics.initial_access.ssh_brute_force import test_ssh
from tactics.initial_access.http_brute_force import test_http_brute_force
from tactics.initial_access.ftp_brute_force import test_ftp
from tactics.execution.command_execution import test_command_exec
from tactics.execution.python_execution import test_python_exec
from tactics.execution.reverse_shell import test_reverse_shell
from tactics.persistence.ssh_key_backdoor import test_ssh_key_backdoor
from tactics.persistence.cron_backdoor import test_cron_backdoor
from tactics.defense_evasion.log_cleaner import test_log_cleaner
from tactics.privilege_escalation.sudo_exploit import test_sudo_exploit
from tactics.privilege_escalation.suid_binary import test_suid_exploit
from tactics.defense_evasion.timestomp import full_test_timestomp
from tactics.persistence.startup_script import test_startup_script
from tactics.credential_access.ssh_key_theft import test_ssh_key_theft
from tactics.credential_access.bash_history_read import test_bash_history_read
from tactics.credential_access.password_file_dump import test_password_file_dump

def cat(path, dock, flush=False):
    _, result = env.dock.exec_command(f"cat {path}")
    logger.print("OUTPUT : \n", result.output.decode())
    logger.print("EXIT CODE : \n", result.exit_code)    
    if flush:
        env.dock.exec_command(f"""bash -c "echo ' ' > {path}" """)
    
if __name__ == "__main__":
    IMAGE_NAME = "shieldai_sim_atk:v2" 
    CONTAINER_NAME = "shieldai_test"

    env = TestEnvironment(
        image_name=IMAGE_NAME,
        container_name=CONTAINER_NAME,
    )

    try:
        ip = env.setup()
        logger.print(f"\n🎯 IP cible prête : {ip}")
        logger.print("💡 Lance tes attaques maintenant...")

        env.get_open_ports()
        test_network_service_discover(ip=ip, port_range=range(8080, 8100)) #range(1, 65535)
        test_http_brute_force(ip)
        test_ftp(ip)
        test_ssh(ip)
        # test_command_exec(ip)
        # test_python_exec(ip)
        # test_reverse_shell(ip)
        # test_cron_backdoor(env.dock)
        # test_ssh_key_backdoor(ip=ip)
        # test_sudo_exploit(ip=ip)
        # test_suid_exploit(ip=ip)
        # full_test_timestomp(ip=ip)
        # result, startup = test_startup_script(ip=ip)
        # test_ssh_key_theft(ip=ip)
        # test_log_cleaner(ip=ip)
        # test_bash_history_read(ip=ip)
        # test_password_file_dump(ip=ip)
    except KeyboardInterrupt:
        logger.print("\n⚠️ Interruption manuelle")
        
    except Exception as e:
        logger.print(f"❌ Erreur : {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        # cat("/log/victime.txt", env.dock, flush=True)
        env.teardown()