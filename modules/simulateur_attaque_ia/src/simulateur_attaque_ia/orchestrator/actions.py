#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jun 17 13:42:26 2026

@author: hounsousamuel
"""

ALL_ACTIONS = [
    'Reconnaissance',
    'InitialAccess',
    'Execution',
    'PrivilegeEscalation',
    'CredentialAccess',
    'LateralMovement',
    'Exfiltration',
    'DefenseEvasion',
    'Persistence',
    'Report',
    "End"
]

import random
random.shuffle(ALL_ACTIONS)

ACTIONS_MAPPING = {
    'Reconnaissance': "reconnaissance",
    'InitialAccess': "initial_access",
    'Execution': "execution",
    'PrivilegeEscalation': "privilege_escalation",
    'CredentialAccess': "credential_access",
    'LateralMovement': "lateral_movement",
    'Exfiltration': "exfiltration",
    'DefenseEvasion': "defense_evasion",
    'Persistence': "persistence",
    'Report': "report",
    "End": "end"
}

