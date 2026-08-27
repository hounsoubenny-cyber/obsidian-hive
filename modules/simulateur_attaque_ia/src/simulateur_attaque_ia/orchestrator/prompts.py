#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jun 17 14:02:04 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from simulateur_attaque_ia.orchestrator.actions import ALL_ACTIONS

def build_prompt(state: dict) -> str:
    lines = []
    already_done = state.get('already_done', [])
    already_done = list(
        map(
            lambda n: n.value if hasattr(n, "value") else n,
            already_done
        )
    )
    # ─── 1. INFOS GÉNÉRALES ───
    lines.append("=== SITUATION ===")
    lines.append(f"cible={state.get('ip', '?')}")
    lines.append(f"etape_actuelle={state.get('actual_step', 'none')}")
    lines.append(f"etapes_faites={','.join(already_done) or 'aucune'}")
    lines.append(f"total_etapes={len(ALL_ACTIONS)}")

    # ─── 2. RÉUSSITES / ÉCHECS ───
    success_dict = state.get('success_dict', {})
    success_by_tactic = {}
    for key, val in success_dict.items():
        tactic = key.split('|')[-1] if '|' in key else 'unknown'
        if tactic not in success_by_tactic:
            success_by_tactic[tactic] = []
        success_by_tactic[tactic].append(val)

    lines.append("\n=== RÉSULTATS PAR TACTIC ===")
    for tactic, results in success_by_tactic.items():
        ok = sum(1 for r in results if r)
        total = len(results)
        lines.append(f"{tactic}={ok}/{total}")

    # ─── 3. DÉCOUVERTES ───
    lines.append("\n=== DÉCOUVERTES ===")
    open_ports = state.get('open_ports', [])
    lines.append(f"ports_ouverts={','.join(map(str, open_ports)) or 'aucun'}")

    port_function = state.get('port_function', {})
    if port_function:
        services = []
        for svc, ports in port_function.items():
            if ports:
                services.append(f"{svc}:{','.join(map(str, ports))}")
        lines.append(f"services={';'.join(services)}" if services else "services=aucun")
    else:
        lines.append("services=aucun")

    # ─── 4. CREDENTIALS ───
    lines.append("\n=== CREDENTIALS ===")
    ssh_creds = state.get('ssh_brute_force_found_credentials', {})
    total_ssh = sum(len(c) for c in ssh_creds.values())
    lines.append(f"ssh_credentials={total_ssh}")

    ftp_creds = state.get('ftp_brute_force_found_credentials', {})
    total_ftp = sum(len(c) for c in ftp_creds.values())
    lines.append(f"ftp_credentials={total_ftp}")

    http_creds = state.get('http_brute_force_found_credentials', {})
    total_http = sum(len(c) for c in http_creds.values())
    lines.append(f"http_paths_trouves={total_http}")

    # ─── 5. EXECUTION ───
    lines.append("\n=== EXECUTION ===")
    cmd_results = state.get('command_execution_results', {})
    cmd_count = len(cmd_results.get('commands', {})) if cmd_results else 0
    lines.append(f"commandes_executees={cmd_count}")

    py_results = state.get('python_execution_results', {})
    py_count = len(py_results.get('commands', {})) if py_results else 0
    lines.append(f"scripts_python={py_count}")

    # ─── 6. PRIVILEGE ESCALATION ───
    lines.append("\n=== PRIVILEGE ESCALATION ===")
    privesc_success = state.get('privilege_escalation_success', False)
    lines.append(f"root_obtenu={'oui' if privesc_success else 'non'}")

    privesc_results = state.get('privilege_escalation_results', {})
    sudo_ok = privesc_results.get('sudo_exploit', {}).get('results', {}).get('success_number', 0) > 0
    suid_ok = privesc_results.get('suid_binary', {}).get('results', {}).get('success_number', 0) > 0
    lines.append(f"sudo_exploit={'ok' if sudo_ok else 'ko'}")
    lines.append(f"suid_binary={'ok' if suid_ok else 'ko'}")

    # ─── 7. CREDENTIAL ACCESS ───
    lines.append("\n=== CREDENTIAL ACCESS ===")
    ca_results = state.get('credential_access_results', {})
    pw_dump = ca_results.get('password_file_dump', {})
    hashes = pw_dump.get('results', {}).get('hashes_count', 0) if pw_dump else 0
    lines.append(f"hashes_extraits={hashes}")

    bash_read = ca_results.get('bash_history_read', {})
    bash_creds = bash_read.get('results', {}).get('credentials_count', 0) if bash_read else 0
    lines.append(f"creds_history={bash_creds}")

    ssh_steal = ca_results.get('ssh_key_theft', {})
    usable_keys = ssh_steal.get('results', {}).get('usable_keys_count', 0) if ssh_steal else 0
    known_hosts = ssh_steal.get('results', {}).get('known_hosts_count', 0) if ssh_steal else 0
    lines.append(f"cles_ssh_volées={usable_keys}")
    lines.append(f"known_hosts={known_hosts}")

    # ─── 8. LATERAL MOVEMENT ───
    lines.append("\n=== LATERAL MOVEMENT ===")
    lm_results = state.get('lateral_movement_results', {})
    compromised = lm_results.get('results', {}).get('compromised_count', 0) if lm_results else 0
    lines.append(f"hosts_compromis={compromised}")

    usable_keys = state.get('lateral_movement_usable_keys', [])
    known_hosts = state.get('lateral_movement_known_hosts', [])
    lines.append(f"cles_disponibles={len(usable_keys)}")
    lines.append(f"hosts_connus={len(known_hosts)}")

    # ─── 9. EXFILTRATION ───
    lines.append("\n=== EXFILTRATION ===")
    exfil_results = state.get('exfiltration_results', {})
    sent = exfil_results.get('results', {}).get('sent_count', 0) if exfil_results else 0
    lines.append(f"payloads_exfiltrés={sent}")
    lines.append(f"c2_url={state.get('exfiltration_c2_url', 'non_defini')}")

    # ─── 10. DEFENSE EVASION ───
    lines.append("\n=== DEFENSE EVASION ===")
    de_results = state.get('defense_evasion_results', {})
    logs_cleaned = de_results.get('log_cleaner', {}).get('results', {}).get('success_number', 0) > 0 if de_results else False
    files_stomped = de_results.get('files_stomped', []) if de_results else []
    lines.append(f"logs_effacés={'oui' if logs_cleaned else 'non'}")
    lines.append(f"fichiers_timestompes={len(files_stomped)}")

    # ─── 11. PERSISTENCE ───
    lines.append("\n=== PERSISTENCE ===")
    ssh_key_ok = state.get('success_dict', {}).get('SSHKeyBackdoor|Persistence', False)
    cron_ok = state.get('success_dict', {}).get('CronBackdoor|Persistence', False)
    lines.append(f"ssh_key_backdoor={'ok' if ssh_key_ok else 'ko'}")
    lines.append(f"cron_backdoor={'ok' if cron_ok else 'ko'}")
    lines.append(f"fichiers_crees={','.join(state.get('created_files', [])) or 'aucun'}")

    # ─── 12. ERREURS ───
    lines.append("\n=== ERREURS ===")
    error_dict = state.get('error_dict', {})
    total_errors = sum(len(errs) for errs in error_dict.values())
    if total_errors > 0:
        err_summary = []
        for key, errs in error_dict.items():
            if errs:
                err_summary.append(f"{key}:{len(errs)}")
        lines.append(f"total={total_errors} ({','.join(err_summary[:3])})")
    else:
        lines.append("aucune")

    # ─── 13. PROCHAINES ÉTAPES POSSIBLES ───
    lines.append("\n=== PROCHAINES ÉTAPES POSSIBLES ===")
    already_done = set(state.get('already_done', []))
    
    all_steps = {step: step not in already_done for step in ALL_ACTIONS}

    available = [step for step, avail in all_steps.items() if avail]
    lines.append(f"disponibles={','.join(available) if available else 'aucune'}")

    # ─── 14. CONTEXTE SPÉCIFIQUE ───
    lines.append("\n=== CONTEXTE ===")
    contexts = []

    if total_ssh > 0 and 'execution' not in already_done:
        contexts.append("CREDS_SSH_DISPONIBLES_EXECUTION_POSSIBLE")
    
    if privesc_success and 'credential_access' not in already_done:
        contexts.append("ROOT_OBTENU_VOL_CREDS_POSSIBLE")

    if len(usable_keys) > 0 and len(known_hosts) > 0 and 'lateral_movement' not in already_done:
        contexts.append("CLES_SSH_VOLEES_MOUVEMENT_LATERAL_POSSIBLE")

    if 'execution' in already_done and 'persistence' not in already_done:
        contexts.append("EXECUTION_FAITE_BACKDOOR_POSSIBLE")

    if all(step in already_done for step in ['execution', 'privilege_escalation', 'credential_access', 'lateral_movement', 'exfiltration', 'defense_evasion', 'persistence']):
        contexts.append("TOUT_EST_FAIT_RAPPORT_FINAL")

    lines.append(f"hints={'|'.join(contexts) if contexts else 'aucun'}")

    # ─── 15. INSTRUCTION FINALE ───
    lines.append("\n=== DECISION ===")
    lines.append("ACTION_A_SUIVRE=(choisis parmi disponibles, ou 'end' pour terminer)")
    
    return "\n".join(lines)

def build_prompt_decision(steps_results: dict, conf: dict) -> str:
    """
    Prompt pour que l'IA décide de la prochaine action.
    Utilise steps_results pour savoir ce qui a été fait.
    """
    lines = []

    # ─── INFOS GÉNÉRALES ───
    lines.append("=== SITUATION ===")
    lines.append(f"cible={conf.get('ip', '?')}")

    # ─── ÉTAPES DÉJÀ FAITES (depuis steps_results) ───
    already_done = set()
    for key in steps_results.keys():
        if "Reconnaissance" in key:
            already_done.add("reconnaissance")
        elif "InitialAccess" in key:
            already_done.add("initial_access")
        elif "Execution" in key:
            already_done.add("execution")
        elif "PrivilegeEscalation" in key:
            already_done.add("privilege_escalation")
        elif "CredentialAccess" in key:
            already_done.add("credential_access")
        elif "LateralMovement" in key:
            already_done.add("lateral_movement")
        elif "Exfiltration" in key:
            already_done.add("exfiltration")
        elif "DefenseEvasion" in key:
            already_done.add("defense_evasion")
        elif "Persistence" in key:
            already_done.add("persistence")
        elif "Report" in key:
            already_done.add("report")

    lines.append(f"etapes_faites={','.join(already_done) if already_done else 'aucune'}")

    # ─── PORTS OUVERTS ───
    open_ports = conf.get('open_ports', [])
    lines.append(f"ports_ouverts={','.join(map(str, open_ports)) if open_ports else 'aucun'}")

    # ─── SERVICES ───
    port_function = conf.get('port_function', {})
    if port_function:
        services = []
        for svc, ports in port_function.items():
            if ports:
                services.append(f"{svc}:{','.join(map(str, ports))}")
        lines.append(f"services={'|'.join(services)}")
    else:
        lines.append("services=aucun")

    # ─── CREDENTIALS SSH ───
    ssh_creds = conf.get('ssh_brute_force_found_credentials', {})
    total_ssh = sum(len(c) for c in ssh_creds.values())
    lines.append(f"ssh_credentials={total_ssh}")

    # ─── PRIVILEGE ESCALATION ───
    privesc_success = conf.get('privilege_escalation_success', False)
    lines.append(f"root_obtenu={'oui' if privesc_success else 'non'}")

    # ─── CLES SSH VOLÉES ───
    usable_keys = conf.get('lateral_movement_usable_keys', [])
    known_hosts = conf.get('lateral_movement_known_hosts', [])
    lines.append(f"cles_ssh_volées={len(usable_keys)}")
    lines.append(f"hosts_connus={len(known_hosts)}")

    # ─── EXFILTRATION ───
    exfil_results = conf.get('exfiltration_results', {})
    sent = exfil_results.get('results', {}).get('sent_count', 0) if exfil_results else 0
    lines.append(f"payloads_exfiltrés={sent}")

    # ─── PERSISTENCE ───
    created_files = conf.get('created_files', [])
    lines.append(f"fichiers_crees={','.join(created_files) if created_files else 'aucun'}")

    # ─── ACTIONS DISPONIBLES ───
    available = [action for action in ALL_ACTIONS if action not in already_done]
    lines.append("\n=== ACTIONS DISPONIBLES ===")
    lines.append(','.join(available) if available else 'aucune')

    # ─── CONTEXTE ───
    contexts = []
    if total_ssh > 0 and 'execution' not in already_done:
        contexts.append("CREDS_SSH_DISPO_EXECUTION")
    if privesc_success and 'credential_access' not in already_done:
        contexts.append("ROOT_OBTENU_VOL_CREDS")
    if len(usable_keys) > 0 and len(known_hosts) > 0 and 'lateral_movement' not in already_done:
        contexts.append("CLES_VOLEES_LATERAL")
    if 'execution' in already_done and 'persistence' not in already_done:
        contexts.append("EXECUTION_FAITE_BACKDOOR")
    if all(step in already_done for step in ['execution', 'privilege_escalation', 'credential_access', 'exfiltration', 'defense_evasion', 'persistence']):
        contexts.append("TOUT_FAIT_RAPPORT")
    lines.append(f"hints={'|'.join(contexts) if contexts else 'aucun'}")

    # ─── DECISION ───
    lines.append("\n=== DECISION ===")
    lines.append("ACTION=")

    return '\n'.join(lines)


def build_prompt_review(steps_results: dict, conf: dict, user_action: str) -> str:
    """
    Prompt pour que l'IA donne son avis sur la proposition utilisateur.
    """
    lines = []

    # ─── INFOS GÉNÉRALES ───
    lines.append("=== SITUATION ===")
    lines.append(f"cible={conf.get('ip', '?')}")

    # ─── ÉTAPES DÉJÀ FAITES ───
    already_done = set()
    for key in steps_results.keys():
        if "Reconnaissance" in key:
            already_done.add("reconnaissance")
        elif "InitialAccess" in key:
            already_done.add("initial_access")
        elif "Execution" in key:
            already_done.add("execution")
        elif "PrivilegeEscalation" in key:
            already_done.add("privilege_escalation")
        elif "CredentialAccess" in key:
            already_done.add("credential_access")
        elif "LateralMovement" in key:
            already_done.add("lateral_movement")
        elif "Exfiltration" in key:
            already_done.add("exfiltration")
        elif "DefenseEvasion" in key:
            already_done.add("defense_evasion")
        elif "Persistence" in key:
            already_done.add("persistence")

    lines.append(f"etapes_faites={','.join(already_done) if already_done else 'aucune'}")

    # ─── CREDENTIALS SSH ───
    ssh_creds = conf.get('ssh_brute_force_found_credentials', {})
    total_ssh = sum(len(c) for c in ssh_creds.values())
    lines.append(f"ssh_credentials={total_ssh}")

    # ─── PROPOSITION UTILISATEUR ───
    lines.append("\n=== PROPOSITION UTILISATEUR ===")
    lines.append(f"action={user_action}")

    # ─── CONTEXTE ───
    contexts = []
    if user_action in already_done:
        contexts.append("ACTION_DEJA_FAITE")
    if user_action not in ALL_ACTIONS:
        contexts.append("ACTION_INCONNUE")
    if user_action == 'lateral_movement':
        usable_keys = conf.get('lateral_movement_usable_keys', [])
        known_hosts = conf.get('lateral_movement_known_hosts', [])
        if not usable_keys or not known_hosts:
            contexts.append("PAS_DE_CLES_OU_HOSTS")
    if user_action == 'execution' and total_ssh == 0:
        contexts.append("PAS_DE_CREDS_SSH")
    if user_action == 'privilege_escalation' and 'execution' not in already_done:
        contexts.append("EXECUTION_NON_FAITE")
    if user_action == 'persistence' and 'execution' not in already_done:
        contexts.append("EXECUTION_NON_FAITE")
    lines.append(f"hints={'|'.join(contexts) if contexts else 'aucun'}")

    # ─── DEMANDE ───
    lines.append("\n=== DEMANDE ===")
    lines.append(f"L'utilisateur propose de faire '{user_action}'.")
    lines.append("Donne un avis concis en 2-3 phrases :")
    lines.append("- Est-ce pertinent ?")
    lines.append("- Y a-t-il des prérequis manquants ?")
    lines.append("- Alternative plus pertinente ?")
    lines.append("\nAVIS=")

    return '\n'.join(lines)