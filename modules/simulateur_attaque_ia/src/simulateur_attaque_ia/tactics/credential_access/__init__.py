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

from tactics.credential_access.password_file_dump import PasswordFileDump
from tactics.credential_access.ssh_key_theft import SSHKeyTheft
from tactics.credential_access.bash_history_read import BashHistoryRead

__all__ = [
    "PasswordFileDump",
    "SSHKeyTheft", 
    "BashHistoryRead",
]