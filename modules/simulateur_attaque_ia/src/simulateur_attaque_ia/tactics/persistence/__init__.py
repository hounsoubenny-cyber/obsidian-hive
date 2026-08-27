# tactics/initial_access/__init__.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jan  9 06:04:07 2026

@author: hounsousamuel
"""

import os
import sys

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

from simulateur_attaque_ia.tactics.persistence.cron_backdoor import CronBackdoor
from simulateur_attaque_ia.tactics.persistence.ssh_key_backdoor import SSHKeyBackdoor

__all__ = [
    "CronBackdoor",
    "SSHKeyBackdoor",
]