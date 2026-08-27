## 📦 **Document 4/6 : `MAPPING_GUIDE.md` (version 1.0.0)**

```markdown
# 🔗 Guide de Mapping des Vulnérabilités

> **Auteur:** Samuel - ShieldAI Scanner  
> **Version:** 1.0.0  
> **Date:** 2026-03-11

---

## 🎯 Objectif

Ce document établit la correspondance entre les trois fichiers de configuration du scanner :

| Fichier | Rôle |
|---------|------|
| `html_signatures.json` | Signatures de détection (patterns, indicateurs) |
| `payloads.json` | Payloads de test pour l'Active Analyzer |
| `weights_v2.json` | Poids pour le scoring des vulnérabilités |

L'objectif est d'avoir une **nomenclature unifiée** pour faciliter l'intégration et la maintenance.

---

## 📋 Table de Mapping Complète

| Clé (`payloads.json` & `weights_v2.json`) | `name_abbr` | `name_full` (dans `html_signatures.json`) |
|--------------------------------------------|-------------|--------------------------------------------|
| `XSS` | XSS | cross-site_scripting |
| `SQLi` | SQLi | sql_injection |
| `CMDi` | CMDi | command_injection |
| `DirTrav` | DirTrav | directory_traversal |
| `XXE` | XXE | xml_external_entity |
| `SSRF` | SSRF | server_side_request_forgery |
| `SSTI` | SSTI | server_side_template_injection |
| `NoSQLi` | NoSQLi | nosql_injection |
| `CORS` | CORS | cors_misconfiguration |
| `CSRF` | CSRF | cross-site_request_forgery |
| `OpenRedirect` | OpenRedirect | open_redirect |
| `InsecUpload` | InsecUpload | insecure_file_upload |
| `JWT` | JWT | jwt_vulnerabilities |
| `GraphQLi` | GraphQLi | graphql_injection |
| `LDAPi` | LDAPi | ldap_injection |
| `IDOR` | IDOR | insecure_direct_object_reference |
| `Prototype_Pollution` | Prototype_Pollution | prototype_pollution |
| `InsecDeser` | InsecDeser | insecure_deserialization |
| `RaceCondition` | RaceCondition | race_conditions |
| `HTTP_Request_Smuggling` | HTTP_Request_Smuggling | http_request_smuggling |
| `CRLF_Injection` | CRLF_Injection | http_header_injection |
| `XPATH_Injection` | XPATH_Injection | xpath_injection |
| `RateLimit` | RateLimit | rate_limiting_issues |
| `InfoDisc` | InfoDisc | information_disclosure |
| `InsecCrypto` | InsecCrypto | insecure_crypto |
| `CredsExpose` | CredsExpose | exposed_credentials |
| `BrokenAuth` | BrokenAuth | broken_authentication |
| `InsecPerm` | InsecPerm | insecure_permissions |
| `SessFix` | SessFix | session_fixation |
| `BufOvr` | BufOvr | buffer_overflow |

---

## 🔄 Correspondance des Fichiers

### Structure Type pour une Vulnérabilité

#### Dans `payloads.json`
```json
"SQLi": {
  "name_abbr": "SQLi",
  "name_full": "sql_injection",
  "severity": "critical",
  "payloads": [...],
  "detection": {...}
}
```

#### Dans `weights_v2.json`
```json
"SQLi": {
  "name_abbr": "SQLi",
  "name_full": "sql_injection",
  "weights": [0.50, 0.25, 0.15, 0.05, 0.05],
  "explanation": "...",
  "key_factor": "..."
}
```

#### Dans `html_signatures.json`
```json
{
  "id": "SQL-001",
  "name": "sql_injection",
  "severity": "élevé",
  "category": "injection",
  "patterns": [...]
}
```

---

## 🧩 Utilisation dans le Code

### Exemple Python : Chargement et Mapping

```python
import json

# Charger les fichiers
with open('html_signatures.json') as f:
    signatures = json.load(f)

with open('payloads.json') as f:
    payloads = json.load(f)

with open('weights_v2.json') as f:
    weights = json.load(f)

# Fonction de mapping
def get_vuln_info(vuln_key):
    """
    Récupère les informations d'une vulnérabilité à partir de sa clé
    (ex: "SQLi", "XSS", "CredsExpose")
    """
    info = {
        'key': vuln_key,
        'payloads': payloads['payloads'].get(vuln_key, {}),
        'weights': weights['vulnerability_weights'].get(vuln_key, {}),
        'signatures': []
    }
    
    # Chercher dans html_signatures.json
    vuln_name_full = info['payloads'].get('name_full')
    if vuln_name_full:
        for category in signatures['categories'].values():
            for sig in category['signatures']:
                if sig['name'] == vuln_name_full:
                    info['signatures'].append(sig)
    
    return info

# Exemple d'utilisation
sqli_info = get_vuln_info('SQLi')
print(f"Vuln: {sqli_info['key']}")
print(f"Poids: {sqli_info['weights'].get('weights')}")
print(f"Nombre de payloads: {len(sqli_info['payloads'].get('payloads', []))}")
print(f"Signatures trouvées: {len(sqli_info['signatures'])}")
```

---

## ✅ Validation du Mapping

Pour s'assurer que toutes les clés sont correctement mappées :

```python
def validate_mapping():
    """Vérifie la cohérence du mapping entre les fichiers"""
    errors = []
    
    # Clés dans payloads.json
    payload_keys = set(payloads['payloads'].keys())
    
    # Clés dans weights_v2.json
    weight_keys = set(weights['vulnerability_weights'].keys())
    
    # Vérifier que toutes les clés existent dans les deux fichiers
    missing_in_weights = payload_keys - weight_keys
    missing_in_payloads = weight_keys - payload_keys
    
    if missing_in_weights:
        errors.append(f"Clés présentes dans payloads mais absentes dans weights: {missing_in_weights}")
    
    if missing_in_payloads:
        errors.append(f"Clés présentes dans weights mais absentes dans payloads: {missing_in_payloads}")
    
    # Vérifier que name_full correspond
    for key in payload_keys.intersection(weight_keys):
        payload_full = payloads['payloads'][key].get('name_full')
        weight_full = weights['vulnerability_weights'][key].get('name_full')
        
        if payload_full != weight_full:
            errors.append(f"Incohérence name_full pour {key}: payload='{payload_full}', weight='{weight_full}'")
    
    return errors

# Lancer la validation
errors = validate_mapping()
if errors:
    for error in errors:
        print(f"❌ {error}")
else:
    print("✅ Mapping valide !")
```

---

## 📝 Notes Importantes

1. **Les clés sont sensibles à la casse** : `SQLi` ≠ `sqli`
2. **Toutes les vulnérabilités doivent avoir les mêmes `name_abbr` et `name_full`** dans les trois fichiers
3. **Les alias** (dans `weights_v2.json`) permettent de gérer les anciens noms

---

## 🔗 Liens Utiles

- [Documentation des Poids](weights_documentation_v2.md)
- [Matrice des Priorités](PRIORITY_MATRIX.md)
- [Guide des Encodages](ENCODING_GUIDE.md)

---

**Fin du document**
```
