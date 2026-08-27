#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May 24 09:41:10 2026

@author: hounsousamuel
"""

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

from simulateur_attaque_ia.tactics.c2.c2_server import main as run_c2_server

__all__ = [
    "run_c2_server",
]