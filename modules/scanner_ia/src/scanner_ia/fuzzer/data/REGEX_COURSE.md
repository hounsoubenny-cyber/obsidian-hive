# 📚 COURS COMPLET REGEX PYTHON POUR SCANNER WEB

## 🎯 PARTIE 1: BASES REGEX

### **Caractères spéciaux**
```python
import re

# . = n'importe quel caractère (sauf \n)
re.search(r'a.b', 'acb')     # Match: acb
re.search(r'a.b', 'a\nb')    # No match

# * = 0 ou plus
re.search(r'ab*c', 'ac')     # Match: ac
re.search(r'ab*c', 'abbc')   # Match: abbc

# + = 1 ou plus
re.search(r'ab+c', 'ac')     # No match
re.search(r'ab+c', 'abbc')   # Match: abbc

# ? = 0 ou 1 (optionnel)
re.search(r'ab?c', 'ac')     # Match: ac
re.search(r'ab?c', 'abc')    # Match: abc

# {n} = exactement n fois
re.search(r'a{3}', 'aaa')    # Match: aaa
re.search(r'a{3}', 'aa')     # No match

# {n,m} = entre n et m fois
re.search(r'a{2,4}', 'aaa')  # Match: aaa
re.search(r'a{2,4}', 'aaaaa')# Match: aaaa (max 4)

# ^ = début de ligne
re.search(r'^hello', 'hello world')   # Match
re.search(r'^hello', 'say hello')     # No match

# $ = fin de ligne
re.search(r'world$', 'hello world')   # Match
re.search(r'world$', 'world hello')   # No match

# | = OU logique
re.search(r'cat|dog', 'I have a cat') # Match: cat
re.search(r'cat|dog', 'I have a dog') # Match: dog

# [] = classe de caractères
re.search(r'[aeiou]', 'hello')        # Match: e
re.search(r'[0-9]', 'test123')        # Match: 1
re.search(r'[a-zA-Z]', 'Test')        # Match: T

# [^] = négation (PAS ces caractères)
re.search(r'[^0-9]', 'test123')       # Match: t (premier non-digit)

# () = groupe de capture
match = re.search(r'(\d+)-(\d+)', '123-456')
print(match.group(1))  # 123
print(match.group(2))  # 456

# \ = échappement (pour caractères spéciaux)
re.search(r'\(', 'test (hello)')      # Match: (
re.search(r'\.', 'test.txt')          # Match: .
```

---

## 🔧 PARTIE 2: FLAGS (MODIFICATEURS)

```python
import re

text = """Hello World
HELLO world
test 123"""

# ===== re.IGNORECASE (re.I) - Insensible à la casse =====
re.search(r'hello', text)              # No match (case-sensitive)
re.search(r'hello', text, re.I)        # Match: Hello

# ===== re.MULTILINE (re.M) - ^ et $ pour chaque ligne =====
re.findall(r'^hello', text)            # ['Hello'] (1 seule ligne)
re.findall(r'^hello', text, re.M | re.I)  # ['Hello', 'HELLO'] (2 lignes)

# ===== re.DOTALL (re.S) - . matche aussi \n =====
re.search(r'Hello.*world', text)       # No match (. ne passe pas \n)
re.search(r'Hello.*world', text, re.S | re.I)  # Match sur plusieurs lignes

# ===== re.VERBOSE (re.X) - Permet commentaires =====
pattern = re.compile(r"""
    \b                # Word boundary
    [A-Z]{2,}         # 2+ majuscules
    \d+               # Digits
    \b                # Word boundary
""", re.X)

# ===== Combiner plusieurs flags =====
pattern = re.compile(r'hello.*world', re.I | re.S | re.M)
# Équivalent à: (?ims)hello.*world
```

---

## 🎯 PARTIE 3: GROUPES ET CAPTURES

```python
import re

# ===== Groupes capturants () =====
match = re.search(r'(\d{3})-(\d{3})-(\d{4})', '555-123-4567')
print(match.group(0))   # 555-123-4567 (tout)
print(match.group(1))   # 555
print(match.group(2))   # 123
print(match.group(3))   # 4567

# ===== Groupes nommés (?P<name>) =====
match = re.search(r'(?P<area>\d{3})-(?P<prefix>\d{3})-(?P<line>\d{4})', 
                  '555-123-4567')
print(match.group('area'))    # 555
print(match.group('prefix'))  # 123
print(match.group('line'))    # 4567

# ===== Groupes non-capturants (?:) =====
# Utile pour grouper SANS capturer (performance)
match = re.search(r'(?:https?|ftp)://(\w+)', 'https://example.com')
print(match.group(1))   # example (1 seul groupe capturé)

# ===== Backreference \1 \2 etc =====
# Référence à un groupe précédent
re.search(r'(\w+)\s+\1', 'hello hello')    # Match (mot répété)
re.search(r'(\w+)\s+\1', 'hello world')    # No match

# Exemple: trouver balises HTML fermées
re.search(r'<(\w+)>.*?</\1>', '<div>text</div>')  # Match
re.search(r'<(\w+)>.*?</\1>', '<div>text</span>') # No match
```

---

## 🚀 PARTIE 4: LOOKAHEAD & LOOKBEHIND (ASSERTIONS)

```python
import re

# ===== Positive Lookahead (?=...) =====
# "Suivi de" mais ne capture PAS
re.search(r'test(?=\d)', 'test123')     # Match: test (si suivi de digit)
re.search(r'test(?=\d)', 'testABC')     # No match

# Exemple: Password avec conditions
re.search(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$', 'Password123')
# Vérifie: au moins 1 maj, 1 min, 1 digit, 8+ caractères

# ===== Negative Lookahead (?!...) =====
# "PAS suivi de"
re.search(r'test(?!\d)', 'testABC')     # Match: test (PAS suivi digit)
re.search(r'test(?!\d)', 'test123')     # No match

# Exemple: innerHTML sans = ""
r'\.innerHTML\s*=\s*(?![\'"`]\s*[\'"`])'  # innerHTML = (mais PAS = "")

# ===== Positive Lookbehind (?<=...) =====
# "Précédé de" mais ne capture PAS
re.search(r'(?<=\$)\d+', '$100')        # Match: 100 (précédé de $)
re.search(r'(?<=\$)\d+', '100')         # No match

# ===== Negative Lookbehind (?<!...) =====
# "PAS précédé de"
re.search(r'(?<!\$)\d+', '100')         # Match: 100 (PAS précédé $)
re.search(r'(?<!\$)\d+', '$100')        # No match
```

---

## 💎 PARTIE 5: FONCTIONS RE MODULE

```python
import re

text = "email: test@example.com, phone: 123-456-7890"

# ===== re.search() - Trouve PREMIÈRE occurrence =====
match = re.search(r'\d+', text)
print(match.group())  # 123

# ===== re.match() - Match au DÉBUT uniquement =====
re.match(r'email', text)      # Match
re.match(r'test', text)       # No match (pas au début)

# ===== re.findall() - Liste de TOUTES les occurrences =====
emails = re.findall(r'\b[\w.-]+@[\w.-]+\.\w+\b', text)
print(emails)  # ['test@example.com']

numbers = re.findall(r'\d+', text)
print(numbers) # ['123', '456', '7890']

# ===== re.finditer() - Itérateur sur tous les matches =====
for match in re.finditer(r'\d+', text):
    print(f"Found {match.group()} at position {match.start()}-{match.end()}")

# ===== re.sub() - Remplacer =====
clean = re.sub(r'\d+', 'XXX', text)
print(clean)  # email: test@example.com, phone: XXX-XXX-XXXX

# Avec fonction de callback
def upper_email(match):
    return match.group().upper()

result = re.sub(r'\b[\w.-]+@[\w.-]+\.\w+\b', upper_email, text)
print(result)  # email: TEST@EXAMPLE.COM, phone: 123-456-7890

# ===== re.split() - Découper =====
parts = re.split(r'[,:]', text)
print(parts)  # ['email', ' test@example.com', ' phone', ' 123-456-7890']

# ===== re.compile() - Précompiler (PERFORMANCE) =====
# Utiliser quand pattern réutilisé souvent
pattern = re.compile(r'\d+', re.IGNORECASE)
pattern.findall(text)      # Utiliser pattern compilé
pattern.search(text)
```

---

## 🔥 PARTIE 6: REGEX POUR SCANNER WEB (EXEMPLES RÉELS)

```python
import re

# ===== 1. Détecter eval() =====
# Simple
r'\beval\s*\('

# Avancé (évite faux positifs dans commentaires)
r'(?<!//.*)\beval\s*\('

# Ultra (gère window.eval, eval[ )
r'\b(?:window\.|globalThis\.)?eval\s*[\(\[]'

# ===== 2. Détecter innerHTML = (mais PAS innerHTML = "") =====
# Basique
r'\.innerHTML\s*='

# Optimisé (exclut innerHTML = "" et innerHTML = '')
r'\.innerHTML\s*=\s*(?![\'"`]\s*[\'"`])'

# Encore mieux (exclut aussi innerHTML = null)
r'\.innerHTML\s*=\s*(?![\'"`]\s*[\'"`]|null|undefined)'

# ===== 3. Détecter AWS Access Keys =====
# Format: AKIA + 16 caractères alphanumériques
r'\bAKIA[0-9A-Z]{16}\b'

# Avec word boundary pour éviter match partiel
r'\bAKIA[0-9A-Z]{16}\b'

# Avec contexte (dans assignment)
r'(?i)aws_access_key_id\s*[=:]\s*[\'"]?(AKIA[0-9A-Z]{16})[\'"]?'

# ===== 4. Détecter javascript: protocol =====
# Basique
r'javascript:'

# Case-insensitive + dans href/src
r'(?i)(?:href|src)\s*=\s*[\'"]?\s*javascript:'

# Éviter faux positifs (pas dans commentaires)
r'(?<!//\s*)(?i)(?:href|src)\s*=\s*[\'"]?\s*javascript:'

# ===== 5. Détecter SQL Injection patterns =====
# OR 1=1
r'[\'\"]\s*OR\s*[\'\""]?1[\'\""]?\s*=\s*[\'\""]?1'

# UNION SELECT
r'(?i)UNION\s+SELECT\s+'

# DROP TABLE
r'(?i)[\'\"]\s*;\s*DROP\s+TABLE'

# ===== 6. Détecter secrets génériques =====
# API key pattern
r'(?i)api[_-]?key\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{20,64})[\'"]'

# Password pattern
r'(?i)password\s*[=:]\s*[\'"]([^\'\"]{8,})[\'"]'

# Exclure faux positifs communs
r'(?i)password\s*[=:]\s*[\'"](?!password|changeme|secret|xxx)([^\'\"]{8,})[\'"]'

# ===== 7. Détecter event handlers inline =====
# Simple
r'\bon[a-z]+\s*='

# Précis (liste handlers communs)
r'\bon(?:load|error|click|mouseover|focus|blur|change|submit)\s*='

# Avec contexte HTML
r'<[^>]+\s+on[a-z]+\s*='

# ===== 8. Détecter JWT tokens =====
# Format: eyJ... (base64 header)
r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'

# ===== 9. Détecter ReDoS patterns =====
# Catastrophic backtracking (.*)* ou (.*)+
r'\(.*\)\*'
r'\(.*\)\+'
r'\(\.+\)\*'
r'\(\.+\)\+'

# Dans RegExp constructor
r'RegExp\s*\(\s*[\'"][^\'"]*\(.*\)\*'

# ===== 10. Détecter XSS dans attributes =====
# onerror avec alert
r'onerror\s*=\s*[\'"]?alert\s*\('

# javascript: dans href
r'href\s*=\s*[\'"]?\s*javascript:'

# <script> tag
r'<script[^>]*>.*?</script>'
```

---

## 📊 PARTIE 7: PERFORMANCE ET OPTIMISATION

```python
import re
import time

# ===== 1. Toujours précompiler si réutilisé =====
# ❌ LENT (recompile à chaque fois)
for text in texts:
    re.search(r'\beval\s*\(', text)

# ✅ RAPIDE (compile 1 fois)
pattern = re.compile(r'\beval\s*\(')
for text in texts:
    pattern.search(text)

# ===== 2. Utiliser raw strings r"..." =====
# ❌ MAUVAIS (double escaping)
pattern = "\\beval\\s*\\("

# ✅ BON (pas d'escaping)
pattern = r"\beval\s*\("

# ===== 3. Non-greedy quantifiers =====
# ❌ LENT (greedy - backtracking)
re.search(r'<script>.*</script>', long_html)

# ✅ RAPIDE (non-greedy)
re.search(r'<script>.*?</script>', long_html)

# ===== 4. Atomic groups (?>...) =====
# Empêche backtracking
re.search(r'(?>\d+)abc', '123456789')  # Fail rapide si pas 'abc'

# ===== 5. Éviter nested quantifiers =====
# ❌ TRÈS LENT (ReDoS)
re.search(r'(a+)+b', 'a' * 30)

# ✅ RAPIDE
re.search(r'a+b', 'a' * 30)

# ===== 6. Utiliser \b word boundaries =====
# ❌ Match partiel
re.search(r'test', 'testing')  # Match

# ✅ Mot complet uniquement
re.search(r'\btest\b', 'testing')  # No match
re.search(r'\btest\b', 'test')     # Match

# ===== 7. Benchmark exemple =====
def benchmark():
    text = "eval(userInput)" * 1000
    
    # Non-compilé
    start = time.time()
    for _ in range(1000):
        re.search(r'\beval\s*\(', text)
    print(f"Non-compiled: {time.time() - start:.3f}s")
    
    # Compilé
    pattern = re.compile(r'\beval\s*\(')
    start = time.time()
    for _ in range(1000):
        pattern.search(text)
    print(f"Compiled: {time.time() - start:.3f}s")

# Résultat typique:
# Non-compiled: 0.234s
# Compiled: 0.089s  (2.6x plus rapide!)
```

---

## 🎓 PARTIE 8: QUIZ & EXERCICES

```python
# ===== EXERCICE 1: Email validator =====
# Écrire regex pour valider email
# Format: nom@domaine.ext
# Exemples valides: test@example.com, user.name@sub.domain.co.uk
# Solution:
email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

# ===== EXERCICE 2: Extraire numéros de téléphone US =====
# Format: (123) 456-7890 ou 123-456-7890
# Solution:
phone_pattern = r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'

# ===== EXERCICE 3: Trouver innerHTML = user_input (dangereux) =====
# Mais IGNORER innerHTML = "" ou innerHTML = 'literal'
# Solution:
innerHTML_pattern = r'\.innerHTML\s*=\s*(?![\'"`][\'"`]|\w+\s*\()'

# ===== EXERCICE 4: Password strength validator =====
# Au moins 8 caractères, 1 majuscule, 1 minuscule, 1 chiffre
# Solution:
password_pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$'

# ===== EXERCICE 5: Extraire tous API keys format "api_key=XXXX" =====
# Solution:
api_key_pattern = r'(?i)api[_-]?key\s*[=:]\s*[\'"]?([A-Za-z0-9_\-]{20,})[\'"]?'
```

---

## 📖 RESSOURCES POUR APPROFONDIR

1. **Tester en ligne**: https://regex101.com (EXCELLENT!)
2. **Cheat sheet**: https://www.debuggex.com/cheatsheet/regex/python
3. **Documentation Python**: https://docs.python.org/3/library/re.html
4. **Livre**: "Mastering Regular Expressions" - Jeffrey Friedl

---

## 🎯 TIPS FINAUX

```python
# 1. Toujours utiliser raw strings
pattern = r"\d+"  # ✅

# 2. Nommer les groupes pour clarté
r'(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})'

# 3. Commenter regex complexes
pattern = re.compile(r"""
    ^                   # Début de ligne
    (?=.*[A-Z])         # Au moins 1 majuscule
    (?=.*[a-z])         # Au moins 1 minuscule
    (?=.*\d)            # Au moins 1 chiffre
    .{8,}               # 8 caractères minimum
    $                   # Fin de ligne
""", re.VERBOSE)

# 4. Préférer non-greedy
r'<script>.*?</script>'  # ✅ non-greedy
r'<script>.*</script>'   # ❌ greedy

# 5. Utiliser word boundaries
r'\beval\b'  # ✅ mot complet
r'eval'      # ❌ peut matcher "evaluation"
```
