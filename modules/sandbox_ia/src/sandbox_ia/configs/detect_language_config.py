#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 29 20:52:34 2026

@author: hounsousamuel
"""

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────
LANGUAGE_MAP = {
    ".py":   "python",
    ".js":   "javascript",
    ".php":  "php",
    ".rb":   "ruby",
    ".pl":   "perl",
    ".java": "java",
    ".go":   "go",
    ".rs":   "rust",
    ".lua":  "lua",
    ".sh":   "bash",
    ".ps1":  "powershell",
    ".r":    "r",
    ".R":    "r",
    ".c":    "c",
    ".cpp":  "cpp",
}
"""
dict[str, str] : Mapping extension de fichier → langage.
Les extensions sont en minuscule sauf .R (convention R language).
Utilisé comme première stratégie de détection — la plus fiable.
"""

SHEBANG_MAP = {
    "python":     "python",
    "node":       "javascript",
    "php":        "php",
    "ruby":       "ruby",
    "perl":       "perl",
    "bash":       "bash",
    "sh":         "bash",
    "pwsh":       "powershell",
    "lua":        "lua",
    "Rscript":    "r",
}
"""
dict[str, str] : Mapping mot-clé shebang → langage.
Utilisé comme deuxième stratégie — analyse la première ligne du fichier.
Exemple : "#!/usr/bin/env python3" → "python3" → "python"
"""

CONTENT_PATTERNS = {
    "python":     ["import ", "def ", "print(", "if __name__"],
    "javascript": ["const ", "let ", "var ", "console.log", "require("],
    "php":        ["<?php", "echo ", "$_"],
    "go":         ["package main", "func main()", "import ("],
    "java":       ["public class", "public static void main"],
    "rust":       ["fn main()", "let mut", "println!("],
    "ruby":       ["puts ", "require '", "def "],
    "bash":       ["#!/bin/bash", "echo ", "fi", "then"],
    "r":          ["library(", "<-", "data.frame("],
    "lua":        ["local ", "require(", "print("],
}
"""
dict[str, list[str]] : Patterns caractéristiques par langage.
Utilisé comme troisième stratégie — comptage de patterns dans le contenu.
Le langage avec le plus de patterns trouvés gagne.
Perl et PowerShell sont absents — peu de patterns uniques fiables.
"""

LANGUAGES = [
    "python",
    "javascript",
    "php",
    "ruby",
    "perl",
    "java",
    "go",
    "rust",
    "lua",
    "r",
    "powershell",
    "c",
    "cpp",
    "bash",
]
"""
list[str] : Liste des 14 langages supportés par le sandbox.
Utilisée pour valider qu'un langage est bien pris en charge
avant de chercher sa commande d'exécution.
"""

LANGUAGE_RUNNERS = {
    "python":     lambda x: (x if x.endswith(".py")   else x + ".py",   f"python3 {x if x.endswith('.py') else x + '.py'}"),
    "javascript": lambda x: (x if x.endswith(".js")   else x + ".js",   f"node {x if x.endswith('.js') else x + '.js'}"),
    "php":        lambda x: (x if x.endswith(".php")  else x + ".php",  f"php {x if x.endswith('.php') else x + '.php'}"),
    "ruby":       lambda x: (x if x.endswith(".rb")   else x + ".rb",   f"ruby {x if x.endswith('.rb') else x + '.rb'}"),
    "perl":       lambda x: (x if x.endswith(".pl")   else x + ".pl",   f"perl {x if x.endswith('.pl') else x + '.pl'}"),
    "java":       lambda x: (
            x if x.endswith(".java") else x + ".java",
            f"javac {x if x.endswith('.java') else x + '.java'} && java -cp {x.rsplit('/', 1)[0] if '/' in x else '.'} {x.rsplit('/', 1)[-1].replace('.java', '')}"
        ),
    "go":         lambda x: (x if x.endswith(".go")   else x + ".go",   f"go run {x if x.endswith('.go') else x + '.go'}"),
    "rust":       lambda x: (x if x.endswith(".rs")   else x + ".rs",   f"rustc {x if x.endswith('.rs') else x + '.rs'} -o /tmp/rust_out && /tmp/rust_out"),
    "lua":        lambda x: (x if x.endswith(".lua")  else x + ".lua",  f"lua5.4 {x if x.endswith('.lua') else x + '.lua'}"),
    "r":          lambda x: (x if x.endswith(".r") or x.endswith(".R") else x + ".r", f"Rscript {x if x.endswith('.r') or x.endswith('.R') else x + '.r'}"),
    "powershell": lambda x: (x if x.endswith(".ps1")  else x + ".ps1",  f"pwsh -File {x if x.endswith('.ps1') else x + '.ps1'}"),
    "c":          lambda x: (x if x.endswith(".c")    else x + ".c",    f"gcc {x if x.endswith('.c') else x + '.c'} -o /tmp/c_out && /tmp/c_out"),
    "cpp":        lambda x: (x if x.endswith(".cpp")  else x + ".cpp",  f"g++ {x if x.endswith('.cpp') else x + '.cpp'} -o /tmp/cpp_out && /tmp/cpp_out"),
    "bash":       lambda x: (x if x.endswith(".sh")   else x + ".sh",   f"bash {x if x.endswith('.sh') else x + '.sh'}"),
}
"""
dict[str, Callable] : Mapping langage → lambda de génération de commande.

Chaque lambda prend un nom de fichier (str) et retourne un tuple :
    (fichier_avec_extension, commande_d_execution)

Si le fichier n'a pas la bonne extension, elle est ajoutée automatiquement.
Les langages compilés (java, rust, c, cpp) enchaînent compilation + exécution
via && dans la commande.

Exemple :
    LANGUAGE_RUNNERS["python"]("code")
    → ("code.py", "python3 code.py")

    LANGUAGE_RUNNERS["c"]("prog.c")
    → ("prog.c", "gcc prog.c -o /tmp/c_out && /tmp/c_out")
"""

COMPILED_LANGUAGES = {
    "c":    "gcc",
    "cpp":  "g++",
    "java": "javac",
    "rust": "rustc",
}