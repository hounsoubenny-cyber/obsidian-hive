#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 13:03:30 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

from simulateur_attaque_ia.api.models.sim_models import (
    SimConfig,
)
# ─────────────────────────────────────────────────────────────────────────────
# Conversion SimConfig → flat dict pour DEFAULT_INPUT_DICT
# ─────────────────────────────────────────────────────────────────────────────

def _sim_config_to_flat(cfg: SimConfig) -> dict:
    """
    Traduit le SimConfig Pydantic en clés plates correspondant
    aux clés de SimulatorState / DEFAULT_INPUT_DICT.
    """
    out: dict = {}

    if r := cfg.recon:
        if r.port_range      is not None: out["network_discover_port_range"]      = r.port_range
        if r.timeout_socket  is not None: out["network_discover_timeout_socket"]  = r.timeout_socket

    if s := cfg.ssh:
        if s.timeout         is not None: out["ssh_brute_force_timeout"]           = s.timeout
        if s.total_timeout   is not None: out["ssh_brute_force_total_timeout"]     = s.total_timeout
        if s.delay           is not None: out["ssh_brute_force_delay"]             = s.delay
        if s.max_attempts    is not None: out["ssh_brute_force_max_attempts"]      = s.max_attempts
        if s.add_common      is not None: out["ssh_brute_force_add_common"]        = s.add_common
        if s.usernames       is not None: out["ssh_brute_force_usernames"]         = s.usernames
        if s.passwords       is not None: out["ssh_brute_force_passwords"]         = s.passwords

    if f := cfg.ftp:
        if f.timeout         is not None: out["ftp_brute_force_timeout"]           = f.timeout
        if f.total_timeout   is not None: out["ftp_brute_force_total_timeout"]     = f.total_timeout
        if f.max_attempts    is not None: out["ftp_brute_force_max_attempts"]      = f.max_attempts
        if f.add_common      is not None: out["ftp_brute_force_add_common"]        = f.add_common
        if f.usernames       is not None: out["ftp_brute_force_usernames"]         = f.usernames
        if f.passwords       is not None: out["ftp_brute_force_passwords"]         = f.passwords

    if h := cfg.http:
        if h.timeout         is not None: out["http_brute_force_timeout"]          = h.timeout
        if h.preference      is not None: out["http_brute_force_preference"]       = h.preference
        if h.add_common      is not None: out["http_brute_force_add_common"]       = h.add_common
        if h.paths           is not None: out["http_brute_force_paths"]            = h.paths

    if e := cfg.execution:
        if e.timeout         is not None: out["command_execution_timeout"]         = e.timeout
        if e.exec_timeout    is not None: out["command_execution_exec_timeout"]    = e.exec_timeout
        if e.commands        is not None: out["command_execution_commands"]        = e.commands
        if e.add_common      is not None: out["command_execution_add_common"]      = e.add_common
        if e.quick           is not None: out["command_execution_quick"]           = e.quick

    if p := cfg.python_execution:
        if p.timeout         is not None: out["python_execution_timeout"]          = p.timeout
        if p.exec_timeout    is not None: out["python_execution_exec_timeout"]     = p.exec_timeout
        if p.commands        is not None: out["python_execution_commands"]         = p.commands
        if p.add_common      is not None: out["python_execution_add_common"]       = p.add_common

    if rs := cfg.reverse_shell:
        if rs.attaquant_ip   is not None: out["reverse_shell_attaquant_ip"]        = rs.attaquant_ip
        if rs.attaquant_port is not None: out["reverse_shell_attaquant_port"]      = rs.attaquant_port
        if rs.timeout        is not None: out["reverse_shell_timeout"]             = rs.timeout
        if rs.exec_timeout   is not None: out["reverse_shell_exec_timeout"]        = rs.exec_timeout
        if rs.listener_timeout is not None: out["reverse_shell_listener_timeout"]  = rs.listener_timeout
        if rs.total_timeout  is not None: out["reverse_shell_total_timeout"]       = rs.total_timeout
        if rs.commands       is not None: out["reverse_shell_commands"]            = rs.commands

    if pe := cfg.persistence:
        if pe.ssh_key_timeout      is not None: out["ssh_key_backdoor_timeout"]      = pe.ssh_key_timeout
        if pe.ssh_key_exec_timeout is not None: out["ssh_key_backdoor_exec_timeout"] = pe.ssh_key_exec_timeout
        if pe.ssh_key_algo         is not None: out["ssh_key_backdoor_algo"]         = pe.ssh_key_algo
        if pe.cron_script_path     is not None: out["cron_backdoor_script_path"]     = pe.cron_script_path
        if pe.cron_expression      is not None: out["cron_backdoor_expression"]      = pe.cron_expression
        if pe.cron_level           is not None: out["cron_backdoor_level"]           = pe.cron_level

    if pv := cfg.privesc:
        if pv.timeout        is not None: out["privilege_escalation_timeout"]      = pv.timeout
        if pv.exec_timeout   is not None: out["privilege_escalation_exec_timeout"] = pv.exec_timeout

    if ca := cfg.credential_access:
        if ca.timeout        is not None: out["credential_access_timeout"]         = ca.timeout
        if ca.exec_timeout   is not None: out["credential_access_exec_timeout"]    = ca.exec_timeout

    if lm := cfg.lateral_movement:
        if lm.max_depth      is not None: out["lateral_movement_max_depth"]        = lm.max_depth
        if lm.max_workers    is not None: out["lateral_movement_max_workers"]      = lm.max_workers
        if lm.join_timeout   is not None: out["lateral_movement_join_timeout"]     = lm.join_timeout

    if ex := cfg.exfiltration:
        if ex.c2_url         is not None: out["exfiltration_c2_url"]               = ex.c2_url
        if ex.timeout        is not None: out["exfiltration_timeout"]              = ex.timeout

    if de := cfg.defense_evasion:
        if de.timeout        is not None: out["defense_evasion_timeout"]           = de.timeout
        if de.exec_timeout   is not None: out["defense_evasion_exec_timeout"]      = de.exec_timeout

    return out
