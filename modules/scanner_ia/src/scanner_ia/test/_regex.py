#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jan  1 10:50:25 2026

@author: hounsousamuel
"""

import re
texte = "Le chat noir et le chien brun jouent dans le jardin. ch"
pattern = r'\bch\w*\b'
result = re.findall(pattern, texte)
print("1.1 Resultat:", result)
# Attendu : ['chat', 'chien']
pattern = r'\b\w{2}\b'
result = re.findall(pattern, texte)
print("1.2 Resultat:", result)
# Attendu : ['Le', 'et', 'le', 'dans', 'le']

texte = "Les numéros: 123, 4567, 89, 123456"
pattern = r'\b\d{3}\b'
result = re.findall(pattern, texte)
print("2.1 Resultat:", result)
# Attendu : ['123'] (4567 a 4 chiffres)

pattern = r'\b\d{2,4}\b'
result = re.findall(pattern, texte)
print("2.2 Resultat:", result)
# Attendu : ['123', '4567', '89']

pattern = r'\b\d{3,}\b'
result = re.findall(pattern, texte)
print("2.3 Resultat:", result)
# Attendu : ['123', '4567', '123456']

texte = """hello world
world hello
hello hello
world world"""
pattern = r'\bhello .*\b'
result = re.findall(pattern, texte, re.MULTILINE)
print("3.1 Resultat:", result)
# Attendu : ['hello world', 'hello hello']

pattern = r'.*hello$'
result = re.findall(pattern, texte, re.MULTILINE)
print("3.2 Resultat:", result)
# Attendu : ['world hello', 'hello hello']

pattern = r'\bhello\b'
result = re.findall(pattern, texte)
print("3.3 Resultat:", result)
# Attendu : ['hello', 'hello', 'hello'] (3 occurrences)

texte = "Prix: 50€, 100$, 75£, 200¥"

pattern = r'\b\d+[€$£¥]{1}'
result = re.findall(pattern, texte)
print("4.1 Resultat:", result)
# Attendu : ['50€', '100$', '75£', '200¥']

pattern = r'\b\d+[€$]{1}'
result = re.findall(pattern, texte)
print("4.2 Resultat:", result)
# Attendu : ['50€', '100$']

pattern = r'\b(\d+)([€$£¥]{1})'
result = re.findall(pattern, texte)
print("4.3 Resultat:", result)
# Attendu : [('50', '€'), ('100', '$'), ('75', '£'), ('200', '¥')]


html = """
<div class="error">SQL syntax error near line 1</div>
<!-- Warning: alert('test') is dangerous -->
.. <!-- Premier --> ... <!-- Deuxième --> ...
<script>alert('xss')</script>
data-info="User input: <script>alert(1)</script>"
{"error": "SQL failed: syntax error"}
"""

pattern = r'<!--.*?-->'
result = re.findall(pattern, html)
print("5.1 Resultat:", result)
# Attendu : [" Warning: alert('test') is dangerous "]

pattern = r'{"error"\s*:\s".*?"}'
result = re.findall(pattern, html)
print("5.2 Resultat:", result)
# Attendu : ["SQL failed: syntax error"]

pattern = r'data-.*=.*'
result = re.findall(pattern, html)
print("5.3 Resultat:", result)
# Attendu : ['User input: <script>alert(1)</script>']

