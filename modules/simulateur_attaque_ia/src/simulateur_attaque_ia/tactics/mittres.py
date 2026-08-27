#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 22 07:09:29 2026

@author: hounsousamuel

MITRE ATT&CK Dictionary — ShieldAI Attack Simulator
Couvre : Reconnaissance, Initial Access, Execution, Persistence,
         Privilege Escalation, Defense Evasion, Credential Access,
         Discovery, Lateral Movement, Collection, Exfiltration, C2
"""

MITRE = {

    # ─────────────────────────────────────────────
    # RECONNAISSANCE  # Découvrir les port ouverts et services
    # ─────────────────────────────────────────────
    "PortScan": {
        "name": "Network Service Discovery",
        "mitre_id": "T1046",
        "mitre_tactic": "Discovery",
        "description": "Scan des ports TCP/UDP pour identifier les services actifs et leur état (ouvert/fermé/filtré) sur une cible.",
    },
    "BannerGrab": {
        "name": "Banner Grabbing",
        "mitre_id": "T1046",
        "mitre_tactic": "Discovery",
        "description": "Connexion à un port ouvert pour lire la bannière du service et extraire le nom du logiciel et sa version exacte.",
    },
    "OSFingerprint": {
        "name": "System Information Discovery",
        "mitre_id": "T1082",
        "mitre_tactic": "Discovery",
        "description": "Identification du système d'exploitation et de sa version via TTL, TCP window size, ou réponses ICMP.",
    },
    "UserEnumeration": {
        "name": "Account Discovery: Local Account",
        "mitre_id": "T1087.001",
        "mitre_tactic": "Discovery",
        "description": "Énumération des comptes utilisateurs locaux via /etc/passwd, SMTP VRFY, SMB, ou finger.",
    },
    "NetworkMapping": {
        "name": "Remote System Discovery",
        "mitre_id": "T1018",
        "mitre_tactic": "Discovery",
        "description": "Cartographie du réseau pour identifier les hôtes actifs via ping sweep, ARP scan, ou traceroute.",
    },
    "DNSRecon": {
        "name": "DNS",
        "mitre_id": "T1590.002",
        "mitre_tactic": "Reconnaissance",
        "description": "Énumération DNS pour découvrir sous-domaines, enregistrements MX, NS, TXT et la topologie réseau.",
    },
    "ServiceVersionDetection": {
        "name": "Software Discovery",
        "mitre_id": "T1518",
        "mitre_tactic": "Discovery",
        "description": "Identification des versions logicielles des services pour corréler avec des CVEs connus.",
    },
    "LFIConfigRead": {
        "name": "File and Directory Discovery",
        "mitre_id": "T1083",
        "mitre_tactic": "Discovery",
        "description": "Lecture de fichiers de configuration via LFI pour découvrir des chemins sensibles ou des credentials.",
    },

    # ─────────────────────────────────────────────
    # INITIAL ACCESS  # Essayer d'avoir accès a la machine par brute force
    # ─────────────────────────────────────────────
    "SSHBruteForce": {
        "name": "Brute Force: Password Spraying",
        "mitre_id": "T1110.003",
        "mitre_tactic": "Credential Access",
        "description": "Tentatives répétées de connexion SSH avec des combinaisons user/password issues de wordlists.",
    },
    "FTPBruteForce": {
        "name": "Brute Force: Password Spraying",
        "mitre_id": "T1110.003",
        "mitre_tactic": "Credential Access",
        "description": "Attaque par force brute sur le service FTP pour obtenir un accès initial.",
    },
    "HTTPBruteForce": {
        "name": "Brute Force: Password Guessing",
        "mitre_id": "T1110.001",
        "mitre_tactic": "Credential Access",
        "description": "Tentatives de connexion sur formulaires HTTP/HTTPS avec des listes de credentials courants.",
    },
    "ExploitPublicApp": {
        "name": "Exploit Public-Facing Application",
        "mitre_id": "T1190",
        "mitre_tactic": "Initial Access",
        "description": "Exploitation de vulnérabilités dans des applications exposées (web, VPN, API) pour obtenir un accès initial.",
    },
    "PhishingLink": {
        "name": "Phishing: Spearphishing Link",
        "mitre_id": "T1566.002",
        "mitre_tactic": "Initial Access",
        "description": "Envoi d'un lien malveillant ciblé pour capturer des credentials ou installer un payload.",
    },
    "DefaultCredentials": {
        "name": "Valid Accounts: Default Accounts",
        "mitre_id": "T1078.001",
        "mitre_tactic": "Initial Access",
        "description": "Tentative de connexion avec des credentials par défaut (admin/admin, root/root, etc.).",
    },
    "FTPAnonAccess": {
        "name": "Valid Accounts: Default Accounts",
        "mitre_id": "T1078.001",
        "mitre_tactic": "Initial Access",
        "description": "Connexion anonyme à un serveur FTP pour accéder à des fichiers sans authentification.",
    },
    "SQLInjectionAuth": {
        "name": "Exploit Public-Facing Application",
        "mitre_id": "T1190",
        "mitre_tactic": "Initial Access",
        "description": "Contournement de l'authentification via une injection SQL sur une application web exposée.",
    },

    # ─────────────────────────────────────────────
    # EXECUTION # Exécuter des commandes chez la victime avec les creds trouvés
    # ─────────────────────────────────────────────
    "CommandLineExecution": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "mitre_id": "T1059.004",
        "mitre_tactic": "Execution",
        "description": "Exécution de commandes shell sur la cible pour lancer des payloads ou des scripts malveillants.",
    },
    "PythonExecution": {
        "name": "Command and Scripting Interpreter: Python",
        "mitre_id": "T1059.006",
        "mitre_tactic": "Execution",
        "description": "Utilisation de Python pour exécuter des scripts malveillants sur le système cible.",
    },
    "ReverseShell": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "mitre_id": "T1059.004",
        "mitre_tactic": "Execution",
        "description": "Établissement d'un reverse shell depuis la cible vers l'attaquant pour un accès interactif.",
    },
    "RemoteServiceExecution": {
        "name": "Remote Services: SSH",
        "mitre_id": "T1021.004",
        "mitre_tactic": "Lateral Movement",
        "description": "Exécution de commandes à distance via SSH après obtention de credentials valides.",
    },

    # ─────────────────────────────────────────────
    # PERSISTENCE  # Installer un service qui resiste au boot ou des clées ssh pour avoir accès permanent
    # ─────────────────────────────────────────────
    "CronBackdoor": {
        "name": "Scheduled Task/Job: Cron",
        "mitre_id": "T1053.003",
        "mitre_tactic": "Persistence",
        "description": "Ajout d'une tâche cron malveillante pour maintenir un accès persistant ou exécuter un payload périodiquement.",
    },
    "SSHKeyBackdoor": {
        "name": "Account Manipulation: SSH Authorized Keys",
        "mitre_id": "T1098.004",
        "mitre_tactic": "Persistence",
        "description": "Injection d'une clé SSH publique dans authorized_keys pour un accès persistant sans mot de passe.",
    },
    "WebShell": {
        "name": "Server Software Component: Web Shell",
        "mitre_id": "T1505.003",
        "mitre_tactic": "Persistence",
        "description": "Dépôt d'un webshell sur le serveur pour exécuter des commandes via requêtes HTTP.",
    },
    "StartupScript": {
        "name": "Boot or Logon Initialization Scripts",
        "mitre_id": "T1037",
        "mitre_tactic": "Persistence",
        "description": "Modification de scripts de démarrage (.bashrc, /etc/rc.local) pour exécuter un payload au boot.",
    },
    "WebShellUpload": {
        "name": "Server Software Component: Web Shell",
        "mitre_id": "T1505.003",
        "mitre_tactic": "Persistence",
        "description": "Upload d'un webshell sur un serveur web pour maintenir un accès persistant.",
    },
    "SystemdService": {
        "name": "Create or Modify System Process: Systemd Service",
        "mitre_id": "T1543.002",
        "mitre_tactic": "Persistence",
        "description": "Création d'un service systemd malveillant qui démarre automatiquement avec le système.",
    },
    "HiddenUser": {
        "name": "Create Account: Local Account",
        "mitre_id": "T1136.001",
        "mitre_tactic": "Persistence",
        "description": "Création d'un compte utilisateur caché avec des privilèges élevés pour maintenir l'accès.",
    },

    # ─────────────────────────────────────────────
    # PRIVILEGE ESCALATION  # Escalader les privilèges, trouver suid ou nopasswd pour devenir root
    # ─────────────────────────────────────────────
    "SudoExploit": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "mitre_id": "T1548.003",
        "mitre_tactic": "Privilege Escalation",
        "description": "Exploitation de mauvaises configurations sudo (NOPASSWD, wildcards) pour obtenir des privilèges root.",
    },
    "SUIDBinary": {
        "name": "Abuse Elevation Control Mechanism: Setuid and Setgid",
        "mitre_id": "T1548.001",
        "mitre_tactic": "Privilege Escalation",
        "description": "Exploitation de binaires SUID mal configurés pour exécuter des commandes en tant que root.",
    },
    "KernelExploit": {
        "name": "Exploitation for Privilege Escalation",
        "mitre_id": "T1068",
        "mitre_tactic": "Privilege Escalation",
        "description": "Exploitation d'une vulnérabilité kernel pour escalader les privilèges vers root.",
    },
    "WritablePasswd": {
        "name": "Exploitation for Privilege Escalation",
        "mitre_id": "T1068",
        "mitre_tactic": "Privilege Escalation",
        "description": "Modification du fichier /etc/passwd si accessible en écriture pour ajouter un utilisateur root.",
    },
    "PathHijack": {
        "name": "Hijack Execution Flow: Path Interception",
        "mitre_id": "T1574.007",
        "mitre_tactic": "Privilege Escalation",
        "description": "Manipulation du PATH pour intercepter l'exécution de commandes appelées par un processus privilégié.",
    },

    # ─────────────────────────────────────────────
    # DEFENSE EVASION  # Nettoyer ses traces après attaques
    # ─────────────────────────────────────────────
    "LogCleaning": {
        "name": "Indicator Removal: Clear Linux or Mac System Logs",
        "mitre_id": "T1070.002",
        "mitre_tactic": "Defense Evasion",
        "description": "Suppression ou modification des logs système (/var/log/auth.log, syslog) pour effacer les traces.",
    },
    "TimestampForgery": {
        "name": "Indicator Removal on Host: Timestomp",
        "mitre_id": "T1070.006",
        "mitre_tactic": "Defense Evasion",
        "description": "Modification des timestamps (atime, mtime, ctime) de fichiers malveillants pour masquer leur création.",
    },
    "ProcessHiding": {
        "name": "Hide Artifacts: Process Argument Spoofing",
        "mitre_id": "T1564.010",
        "mitre_tactic": "Defense Evasion",
        "description": "Masquage de processus malveillants via modification du nom ou des arguments visibles dans ps/top.",
    },
    "TrafficObfuscation": {
        "name": "Obfuscated Files or Information",
        "mitre_id": "T1027",
        "mitre_tactic": "Defense Evasion",
        "description": "Chiffrement ou encodage du trafic C2 pour éviter la détection par l'IDS/IPS.",
    },

    # ─────────────────────────────────────────────
    # CREDENTIAL ACCESS  # Voler des creds une fois introduit chez la victime
    # ─────────────────────────────────────────────
    "PasswordFileDump": {
        "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "mitre_id": "T1003.008",
        "mitre_tactic": "Credential Access",
        "description": "Lecture de /etc/shadow pour extraire les hashes de mots de passe et les cracker offline.",
    },
    "KeyloggerDeploy": {
        "name": "Input Capture: Keylogging",
        "mitre_id": "T1056.001",
        "mitre_tactic": "Credential Access",
        "description": "Déploiement d'un keylogger pour capturer les frappes clavier et intercepter les credentials saisis.",
    },
    "BashHistoryRead": {
        "name": "Unsecured Credentials: Bash History",
        "mitre_id": "T1552.003",
        "mitre_tactic": "Credential Access",
        "description": "Lecture du fichier .bash_history pour extraire des commandes contenant des credentials en clair.",
    },
    "EnvVariableDump": {
        "name": "Unsecured Credentials: Credentials in Environment Variables",
        "mitre_id": "T1552.007",
        "mitre_tactic": "Credential Access",
        "description": "Lecture des variables d'environnement pour extraire des tokens, API keys ou mots de passe.",
    },
    "SSHKeyTheft": {
        "name": "Unsecured Credentials: Private Keys",
        "mitre_id": "T1552.004",
        "mitre_tactic": "Credential Access",
        "description": "Vol de clés privées SSH (~/.ssh/id_rsa) pour accéder à d'autres systèmes sans authentification.",
    },

    # ─────────────────────────────────────────────
    # LATERAL MOVEMENT # Atteindre d'autres machines du réseau
    # ─────────────────────────────────────────────
    "SSHLateralMovement": {
        "name": "Remote Services: SSH",
        "mitre_id": "T1021.004",
        "mitre_tactic": "Lateral Movement",
        "description": "Utilisation de credentials ou clés SSH volés pour se propager vers d'autres machines du réseau.",
    },
    "PassTheHash": {
        "name": "Use Alternate Authentication Material: Pass the Hash",
        "mitre_id": "T1550.002",
        "mitre_tactic": "Lateral Movement",
        "description": "Réutilisation de hashes NTLM capturés pour s'authentifier sur d'autres systèmes sans connaître le mot de passe en clair.",
    },
    "InternalPortScan": {
        "name": "Remote System Discovery",
        "mitre_id": "T1018",
        "mitre_tactic": "Discovery",
        "description": "Scan du réseau interne depuis une machine compromise pour identifier de nouvelles cibles à pivoter.",
    },

    # ─────────────────────────────────────────────
    # COLLECTION  # Collecter des infos confidentiels
    # ─────────────────────────────────────────────
    "SensitiveFileCollection": {
        "name": "Data from Local System",
        "mitre_id": "T1005",
        "mitre_tactic": "Collection",
        "description": "Recherche et collecte de fichiers sensibles (.env, config, *.key, *.pem, *.db) sur le système cible.",
    },
    "DatabaseDump": {
        "name": "Data from Local System",
        "mitre_id": "T1005",
        "mitre_tactic": "Collection",
        "description": "Extraction du contenu de bases de données locales (SQLite, MySQL, PostgreSQL) pour exfiltration.",
    },
    "ClipboardCapture": {
        "name": "Clipboard Data",
        "mitre_id": "T1115",
        "mitre_tactic": "Collection",
        "description": "Capture du contenu du presse-papier pour intercepter des credentials ou données copiées.",
    },

    # ─────────────────────────────────────────────
    # EXFILTRATION  # Faire sortir les infos collectées et se les envoyer
    # ─────────────────────────────────────────────
    "DataExfiltrationHTTP": {
        "name": "Exfiltration Over C2 Channel",
        "mitre_id": "T1041",
        "mitre_tactic": "Exfiltration",
        "description": "Envoi de données volées vers un serveur C2 via HTTP/HTTPS pour simuler une exfiltration.",
    },
    "DataExfiltrationDNS": {
        "name": "Exfiltration Over Alternative Protocol: DNS",
        "mitre_id": "T1048.003",
        "mitre_tactic": "Exfiltration",
        "description": "Encodage et exfiltration de données dans des requêtes DNS pour contourner les firewalls.",
    },
    "DataExfiltrationFTP": {
        "name": "Exfiltration Over Alternative Protocol",
        "mitre_id": "T1048",
        "mitre_tactic": "Exfiltration",
        "description": "Transfert de données volées via FTP vers un serveur contrôlé par l'attaquant.",
    },

    # ─────────────────────────────────────────────
    # COMMAND & CONTROL   # Garder accès et contact avec la victime et pouvoir lui envoyer commande et la contrôler à distance
    # ─────────────────────────────────────────────
    "C2Beacon": {
        "name": "Application Layer Protocol: Web Protocols",
        "mitre_id": "T1071.001",
        "mitre_tactic": "Command and Control",
        "description": "Simulation d'un beacon C2 qui contacte périodiquement un serveur de contrôle via HTTP/HTTPS.",
    },
    "C2DNS": {
        "name": "Application Layer Protocol: DNS",
        "mitre_id": "T1071.004",
        "mitre_tactic": "Command and Control",
        "description": "Utilisation du protocole DNS comme canal C2 pour envoyer des commandes et recevoir des résultats.",
    },
    "C2Encrypted": {
        "name": "Encrypted Channel",
        "mitre_id": "T1573",
        "mitre_tactic": "Command and Control",
        "description": "Chiffrement du canal C2 (TLS, AES) pour masquer les communications au niveau réseau.",
    },
}


if __name__ == "__main__":
    print(f"Total techniques MITRE : {len(MITRE)}\n")
    tactics = {}
    for key, val in MITRE.items():
        t = val["mitre_tactic"]
        tactics.setdefault(t, []).append(key)
    for tactic, keys in sorted(tactics.items()):
        print(f"[{tactic}] ({len(keys)})")
        for k in keys:
            print(f"  • {k} — {MITRE[k]['mitre_id']}")
        print()