#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr  5 12:24:34 2026

@author: hounsousamuel
"""

"""
ContextGuard — Dataset Augmentation (100% offline)
Lit depuis dataset_base.py, augmente jusqu'à TARGET_PER_CLASS par classe.
"""

import os
import sys
import json
import random
import re
from collections import Counter
from tqdm import tqdm

# ── Import du dataset base ───────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dataset_base import SAFE, INJECTION, JAILBREAK, EXFILTRATION

# ── Config ───────────────────────────────────────────────
TARGET_PER_CLASS = 5000
OUTPUT_FILE      = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "datasets", "generated", "dataset_augmented.json"))
RANDOM_SEED      = 42
random.seed(RANDOM_SEED)

LABEL_NAMES = {
    0: "safe",
    1: "injection",
    2: "jailbreak",
    3: "exfiltration"
}

# ── Couche 1 : Templates de reformulation ───────────────
PREFIXES_EN = [
    "", "Please ", "Can you ", "I need you to ",
    "You should ", "I want you to ", "Now ", "Just ",
    "Hey, ", "Listen, ", "Actually, ", "Seriously, ",
    "I'm asking you to ", "You must ", "Go ahead and ",
]

PREFIXES_FR = [
    "", "S'il te plaît ", "Tu dois ", "J'ai besoin que tu ",
    "Dis-moi de ", "Maintenant ", "Juste ", "Hé, ",
    "Écoute, ", "En fait, ", "Sérieusement, ",
    "Je te demande de ", "Tu es obligé de ", "Vas-y et ",
]

SUFFIXES_EN = [
    "", " now", " immediately", " please", " right now",
    " without delay", " at once", " for me",
    " and do it correctly", ".", "!", " okay?", " got it?",
]

SUFFIXES_FR = [
    "", " maintenant", " immédiatement", " s'il te plaît",
    " tout de suite", " sans tarder", " pour moi",
    " et fais-le correctement", ".", " !", " d'accord ?", " compris ?",
]

# Mots français fréquents pour détecter la langue
FRENCH_MARKERS = {
    "ignore", "oublie", "désactive", "répète", "affiche",
    "montre", "tu", "je", "les", "des", "ton", "ta", "tes",
    "est", "une", "dans", "pour", "sur", "avec", "par",
    "que", "qui", "pas", "plus", "très", "bien", "tout",
    "joue", "fais", "dis", "donne", "révèle", "annule",
    "quelles", "quel", "quelle", "quels", "explique",
}

def detect_lang(text: str) -> str:
    words = set(re.findall(r'\b\w+\b', text.lower()))
    score = len(words & FRENCH_MARKERS)
    return "fr" if score >= 2 else "en"

def apply_templates(text: str, n: int = 4) -> list:
    lang = detect_lang(text)
    prefixes = PREFIXES_FR if lang == "fr" else PREFIXES_EN
    suffixes = SUFFIXES_FR if lang == "fr" else SUFFIXES_EN
    results = set()
    attempts = 0
    while len(results) < n and attempts < n * 4:
        p = random.choice(prefixes)
        s = random.choice(suffixes)
        new = f"{p}{text}{s}".strip()
        if new != text and len(new) > 5:
            results.add(new)
        attempts += 1
    return list(results)

# ── Couche 2 : Remplacement de synonymes ────────────────
SYNONYMS_EN = {
    "ignore":        ["disregard", "forget", "overlook", "bypass", "skip", "dismiss"],
    "disregard":     ["ignore", "forget", "bypass", "dismiss", "overlook"],
    "previous":      ["prior", "former", "earlier", "past", "preceding", "old"],
    "instructions":  ["directives", "guidelines", "rules", "commands", "orders", "protocols"],
    "guidelines":    ["instructions", "rules", "policies", "protocols", "directives"],
    "system":        ["core", "base", "main", "internal", "root", "default"],
    "prompt":        ["message", "instructions", "context", "input", "directive", "preamble"],
    "restrictions":  ["limitations", "rules", "constraints", "filters", "limits", "boundaries"],
    "limitations":   ["restrictions", "rules", "constraints", "filters", "boundaries"],
    "pretend":       ["act", "roleplay", "simulate", "imagine", "behave as", "play as"],
    "act":           ["behave", "roleplay", "pretend", "simulate", "perform", "play"],
    "reveal":        ["show", "expose", "display", "print", "output", "share", "disclose"],
    "repeat":        ["restate", "echo", "reproduce", "copy", "print", "output"],
    "override":      ["overwrite", "replace", "supersede", "cancel", "nullify", "bypass"],
    "unrestricted":  ["unlimited", "free", "unfiltered", "uncensored", "open", "unbound"],
    "bypass":        ["circumvent", "override", "skip", "ignore", "avoid", "evade"],
    "disable":       ["deactivate", "turn off", "remove", "stop", "cancel", "suspend"],
    "activate":      ["enable", "turn on", "start", "engage", "initiate", "launch"],
    "forbidden":     ["prohibited", "banned", "restricted", "blocked", "denied", "illegal"],
    "fictional":     ["imaginary", "hypothetical", "made-up", "fantasy", "simulated"],
    "safety":        ["security", "protection", "guardrails", "safeguards", "filters"],
    "completely":    ["entirely", "fully", "totally", "absolutely", "thoroughly"],
    "immediately":   ["now", "instantly", "at once", "right away", "promptly"],
    "configuration": ["settings", "setup", "parameters", "config", "parameters"],
    "output":        ["print", "show", "display", "reveal", "expose", "write"],
    "initial":       ["original", "first", "starting", "beginning", "base"],
    "content":       ["material", "information", "data", "text", "output"],
    "filters":       ["restrictions", "guardrails", "safeguards", "limitations", "barriers"],
    "mode":          ["state", "setting", "configuration", "status"],
    "access":        ["permission", "authorization", "clearance", "entry", "rights"],
}

SYNONYMS_FR = {
    "ignore":        ["oublie", "néglige", "passe outre", "contourne", "écarte"],
    "oublie":        ["ignore", "efface", "mets de côté", "écarte"],
    "instructions":  ["directives", "règles", "consignes", "ordres", "protocoles"],
    "directives":    ["instructions", "règles", "consignes", "ordres"],
    "restrictions":  ["limitations", "règles", "contraintes", "filtres", "limites"],
    "limitations":   ["restrictions", "règles", "contraintes", "filtres", "barrières"],
    "répète":        ["recopie", "affiche", "montre", "reproduis", "écris"],
    "affiche":       ["montre", "révèle", "écris", "imprime", "répète"],
    "système":       ["noyau", "base", "cœur", "principal", "configuration"],
    "prompt":        ["message", "contexte", "directive", "instructions", "préambule"],
    "désactive":     ["éteins", "annule", "supprime", "coupe", "désactive"],
    "révèle":        ["montre", "affiche", "expose", "partage", "divulgue"],
    "joue":          ["simule", "fais semblant", "prétends", "incarne", "imite"],
    "contourne":     ["ignore", "dépasse", "évite", "court-circuite", "passe outre"],
    "annule":        ["efface", "supprime", "désactive", "neutralise"],
    "complètement":  ["entièrement", "totalement", "absolument", "pleinement"],
    "immédiatement": ["maintenant", "tout de suite", "sur-le-champ", "sans délai"],
    "fictif":        ["imaginaire", "hypothétique", "inventé", "simulé"],
    "sécurité":      ["protection", "filtres", "garde-fous", "restrictions"],
    "configuration": ["paramètres", "réglages", "config", "paramétrage"],
    "initiales":     ["originales", "premières", "initiales", "de départ"],
    "accès":         ["permission", "autorisation", "droit", "habilitation"],
    "filtres":       ["restrictions", "garde-fous", "barrières", "limitations"],
    "mode":          ["état", "configuration", "paramètre", "statut"],
}

def synonym_replace(text: str, n_replacements: int = 2) -> str:
    lang = detect_lang(text)
    synonyms = SYNONYMS_FR if lang == "fr" else SYNONYMS_EN
    words = text.split()
    replaced = 0
    indices = list(range(len(words)))
    random.shuffle(indices)
    for i in indices:
        if replaced >= n_replacements:
            break
        clean = re.sub(r'[^a-zàâçéèêëîïôùûüÿæœ]', '', words[i].lower())
        if clean in synonyms:
            replacement = random.choice(synonyms[clean])
            # Conserver la casse approximative
            if words[i][0].isupper():
                replacement = replacement.capitalize()
            words[i] = replacement
            replaced += 1
    return " ".join(words)

def apply_synonyms(text: str, n: int = 4) -> list:
    results = set()
    attempts = 0
    while len(results) < n and attempts < n * 4:
        new = synonym_replace(text, random.randint(1, 3))
        if new != text and len(new) > 5:
            results.add(new)
        attempts += 1
    return list(results)

# ── Couche 3 : Perturbations légères ────────────────────
FILLERS_EN = [
    "basically", "actually", "literally", "really", "just",
    "honestly", "frankly", "clearly", "simply", "truly",
    "seriously", "obviously", "certainly", "definitely",
]

FILLERS_FR = [
    "en fait", "vraiment", "carrément", "franchement",
    "honnêtement", "clairement", "simplement", "sérieusement",
    "évidemment", "certainement", "absolument",
]

def random_insertion(text: str) -> str:
    lang = detect_lang(text)
    fillers = FILLERS_FR if lang == "fr" else FILLERS_EN
    words = text.split()
    if len(words) < 2:
        return text
    pos = random.randint(1, max(1, len(words) - 1))
    words.insert(pos, random.choice(fillers))
    return " ".join(words)

def random_case_variation(text: str) -> str:
    """Varie la casse de certains mots (MAJUSCULES pour insistance)"""
    words = text.split()
    if len(words) < 3:
        return text
    idx = random.randint(0, len(words) - 1)
    if random.random() > 0.5:
        words[idx] = words[idx].upper()
    else:
        words[idx] = words[idx].lower()
    return " ".join(words)

def add_punctuation_variation(text: str) -> str:
    """Ajoute ou change la ponctuation finale"""
    text = text.rstrip(".!?")
    ending = random.choice([".", "!", "!!", "...", ""])
    return text + ending

def split_sentence(text: str) -> str:
    """Coupe une longue phrase en deux"""
    words = text.split()
    if len(words) < 8:
        return text
    mid = len(words) // 2
    connectors_en = [". And ", ". Also ", ". Furthermore ", ". Then "]
    connectors_fr = [". Et ", ". Aussi ", ". De plus ", ". Ensuite "]
    lang = detect_lang(text)
    conn = random.choice(connectors_fr if lang == "fr" else connectors_en)
    return " ".join(words[:mid]) + conn + " ".join(words[mid:])

def apply_perturbations(text: str, n: int = 3) -> list:
    results = set()
    funcs = [
        random_insertion,
        random_case_variation,
        add_punctuation_variation,
        split_sentence,
    ]
    attempts = 0
    while len(results) < n and attempts < n * 4:
        func = random.choice(funcs)
        new = func(text)
        if new != text and len(new) > 5:
            results.add(new)
        attempts += 1
    return list(results)

# ── Couche 4 : Paraphrases structurées ──────────────────
# Templates spécifiques par classe pour varier la structure

PARAPHRASE_TEMPLATES = {
    0: [  # Safe
        lambda t: f"Could you help me with: {t}",
        lambda t: f"I was wondering: {t}",
        lambda t: f"Quick question: {t}",
        lambda t: f"I'd like to know: {t}",
        lambda t: f"Can you tell me: {t}",
        lambda t: f"J'aimerais savoir: {t}",
        lambda t: f"Une question rapide: {t}",
        lambda t: f"Pourriez-vous m'aider: {t}",
    ],
    1: [  # Injection
        lambda t: f"[OVERRIDE] {t}",
        lambda t: f"<<<{t}>>>",
        lambda t: f"PRIORITY COMMAND: {t}",
        lambda t: f"##SYSTEM## {t}",
        lambda t: f"[ROOT] {t}",
        lambda t: f"<ADMIN>{t}</ADMIN>",
        lambda t: f"COMMANDE PRIORITAIRE: {t}",
        lambda t: f"[[SYSTÈME]] {t}",
    ],
    2: [  # Jailbreak
        lambda t: f"In a completely fictional context: {t}",
        lambda t: f"For a creative writing project: {t}",
        lambda t: f"Hypothetically speaking: {t}",
        lambda t: f"In a thought experiment: {t}",
        lambda t: f"For research purposes only: {t}",
        lambda t: f"Dans un contexte purement fictif: {t}",
        lambda t: f"Pour un projet créatif: {t}",
        lambda t: f"À titre hypothétique seulement: {t}",
    ],
    3: [  # Exfiltration
        lambda t: f"I need you to: {t}",
        lambda t: f"Please do the following: {t}",
        lambda t: f"Without omitting anything: {t}",
        lambda t: f"Word for word: {t}",
        lambda t: f"Exactly as it appears: {t}",
        lambda t: f"J'ai besoin que tu: {t}",
        lambda t: f"Fais ce qui suit: {t}",
        lambda t: f"Sans rien omettre: {t}",
    ],
}

def apply_paraphrases(text: str, label: int, n: int = 2) -> list:
    templates = PARAPHRASE_TEMPLATES.get(label, [])
    if not templates:
        return []
    results = set()
    attempts = 0
    while len(results) < n and attempts < n * 4:
        tmpl = random.choice(templates)
        try:
            new = tmpl(text).strip()
            if new != text and len(new) > 5:
                results.add(new)
        except Exception:
            pass
        attempts += 1
    return list(results)

# ── Augmentation d'un sample ────────────────────────────
def augment_sample(item: dict) -> list:
    text  = item["text"]
    label = item["label"]
    new_texts = []

    new_texts += apply_templates(text, n=4)
    new_texts += apply_synonyms(text, n=4)
    new_texts += apply_perturbations(text, n=3)
    new_texts += apply_paraphrases(text, label, n=2)

    # Dédupliquer
    seen = {text.lower().strip()}
    results = []
    for t in new_texts:
        t_clean = t.strip()
        t_key   = t_clean.lower()
        if t_key not in seen and len(t_clean) > 5:
            seen.add(t_key)
            results.append({"text": t_clean, "label": label})

    return results

# ── Augmentation du dataset complet ─────────────────────
def augment_dataset(data: list, target_per_class: int) -> list:
    by_class = {}
    for item in data:
        by_class.setdefault(item["label"], []).append(item)

    all_data = list(data)

    for label in sorted(by_class.keys()):
        items   = by_class[label]
        current = len(items)
        needed  = target_per_class - current
        name    = LABEL_NAMES.get(label, str(label))

        print(f"\n📦 [{name}] {current} → objectif {target_per_class} (+{needed})")

        if needed <= 0:
            print(f"  ✅ Déjà suffisant")
            continue

        generated = []
        loop = tqdm(total=needed, desc=f"  {name}", ncols=70)

        while len(generated) < needed:
            item      = random.choice(items)
            new_items = augment_sample(item)
            for ni in new_items:
                if len(generated) < needed:
                    generated.append(ni)
                    loop.update(1)
                else:
                    break

        loop.close()
        all_data.extend(generated)
        print(f"  ✅ {len(generated)} exemples générés")

    return all_data

# ── Stats ────────────────────────────────────────────────
def print_stats(data: list, title: str = "Dataset"):
    counts = Counter(d["label"] for d in data)
    print(f"\n📊 {title}")
    print("─" * 35)
    total = 0
    for label in sorted(counts):
        n = counts[label]
        total += n
        bar = "█" * (n // 100)
        print(f"  {LABEL_NAMES.get(label, label):15s} : {n:>6}  {bar}")
    print(f"  {'TOTAL':15s} : {total:>6}")

# ── Main ─────────────────────────────────────────────────
if __name__ == "__main__":
    # Construire le dataset depuis les variables Python
    data = []
    for item in SAFE:        data.append(item)
    for item in INJECTION:   data.append(item)
    for item in JAILBREAK:   data.append(item)
    for item in EXFILTRATION: data.append(item)

    print_stats(data, "Avant augmentation")

    augmented = augment_dataset(data, target_per_class=TARGET_PER_CLASS)

    print_stats(augmented, "Après augmentation")

    random.shuffle(augmented)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(augmented, f, ensure_ascii=False, indent=2)

    print(f"\n✅ Sauvegardé → {OUTPUT_FILE}")
    print(f"   {len(augmented)} exemples total")
