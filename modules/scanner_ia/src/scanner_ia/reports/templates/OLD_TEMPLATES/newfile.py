from jinja2 import Environment, FileSystemLoader
from datetime import date

# 1. Charger le template
env = Environment(loader=FileSystemLoader("."))
template = env.get_template("template_report_deluxe++.html")

# 2. Exemple de données
data = {
    "project_name": "Site E-commerce",
    "scan_date": date.today().strftime("%Y-%m-%d"),
    "stats": {
        "critique": 3,
        "majeure": 5,
        "mineure": 7,
        "score": 82
    },
    "infos": {
        "domaine": "exemple.com",
        "ip": "192.168.1.1",
        "os": "Ubuntu 20.04",
        "server": "Nginx 1.18",
        "cms": "WordPress 6.2"
    },
    "vulnerabilities": [
        {
            "title": "SQL Injection",
            "severity": "Critique",
            "description": "Injection possible via paramètre 'id'.",
            "proof": "dump de table 'users'.",
            "remediation": "Utiliser des requêtes préparées."
        },
        {
            "title": "XSS Reflected",
            "severity": "Majeure",
            "description": "Script injecté via paramètre GET.",
            "proof": "popup JavaScript exécutée.",
            "remediation": "Échapper les entrées utilisateurs."
        }
    ],
    "recommendations": [
        "Corriger immédiatement la faille SQL Injection.",
        "Mettre à jour WordPress et plugins.",
        "Activer HSTS et CSP."
    ],
    "annexes": [
        "GET /vulnerable.php?id=1' OR '1'='1 --",
        "Exemple de payload utilisé..."
    ]
}

# 3. Rendu du HTML
html_content = template.render(**data)

with open("rapport.html", "w", encoding="utf-8") as f:
    f.write(html_content)
    
t={
  "project_name": "Site E-commerce",
  "scan_date": "2025-08-21",
  "stats": {
    "critique": 3,
    "majeure": 5,
    "mineure": 7,
    "score": 82
  },
  "infos": {
    "domaine": "exemple.com",
    "ip": "192.168.1.1",
    "os": "Ubuntu 20.04",
    "server": "Nginx 1.18",
    "cms": "WordPress 6.2"
  },
  "vulnerabilities": [
    {
      "title": "SQL Injection",
      "severity": "Critique",
      "description": "Injection possible via paramètre 'id'.",
      "proof": "dump de table 'users'.",
      "remediation": "Utiliser des requêtes préparées."
    },
    {
      "title": "XSS Reflected",
      "severity": "Majeure",
      "description": "Script injecté via paramètre GET.",
      "proof": "popup JavaScript exécutée.",
      "remediation": "Échapper les entrées utilisateurs."
    }
  ],
  "recommendations": [
    "Corriger immédiatement la faille SQL Injection.",
    "Mettre à jour WordPress et plugins.",
    "Activer HSTS et CSP."
  ],
  "annexes": [
    "GET /vulnerable.php?id=1' OR '1'='1 --",
    "Exemple de payload utilisé..."
  ]
}    