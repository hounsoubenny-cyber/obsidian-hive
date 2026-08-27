# tactics/initial_access/__init__.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jan  9 06:04:07 2026

@author: hounsousamuel
"""

import os
import sys

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from tactics.lateral_movement.ssh_lateral_movement import SSHLateralMovement

__all__ = [
    "SSHLateralMovement",
]