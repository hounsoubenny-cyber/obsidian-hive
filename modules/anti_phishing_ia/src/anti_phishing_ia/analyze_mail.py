#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyse complète d'un email pour la détection de phishing.

Ce module fournit :
- _compute_mail_passive_score() : agrège les signaux URLs + headers
- final_decision_mail()         : cascade de décision inspirée de final_decision()
- analyze_mail()                : orchestration complète (BERT + URLs + headers)
- keep_history_mail()           : historique métadonnées uniquement (sans contenu mail)

Flow :
    .eml / texte brut
        │
        ├── parse_mail_and_build_bert_input() ──► MailPhishingPredict.predict()
        │
        └── extract_urls() ──► predict_url() × N
                │
                ▼
        final_decision_mail(bert_prob, urls_results, headers)
                │
                ▼
        verdict + breakdown + historique

Auteur: HOUNSOU Samuel
Version: 1.0.0
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", '..'))
import json
import time
import asyncio
from datetime import datetime
from typing import Optional
from anti_phishing_ia.phishing_utils.mail_extractor_utils import (
    parse_email,
    build_bert_input,
    extract_urls,
)

# ============================================================================
# CONSTANTES DE DÉCISION
# ============================================================================

# Seuils BERT
BERT_SAFE_HIGH       = 0.85   # BERT très confiant safe
BERT_PHISH_HIGH      = 0.80   # BERT très confiant phishing
BERT_PHISH_MEDIUM    = 0.60   # BERT modérément confiant phishing

# Seuils passive score
PASSIVE_HIGH         = 0.60   # Risque passif élevé
PASSIVE_MEDIUM       = 0.30   # Risque passif moyen

# Seuil URL critique (une seule URL à ce niveau = condamnatoire)
URL_CRITICAL_SCORE   = 0.90

# Poids pour mail_passive_score
W_RATIO_PHISH        = 0.35
W_MAX_URL            = 0.35
W_HEADER             = 0.30

# Poids header_risk
HEADER_SPF_FAIL      = 0.30
HEADER_DKIM_ABSENT   = 0.20
HEADER_REPLY_MISMATCH = 0.20


# ============================================================================
# CALCUL DU SCORE PASSIF MAIL
# ============================================================================

def _compute_header_risk(headers: dict) -> float:
    """
    Calcule le score de risque basé sur les headers d'authentification.

    Args:
        headers: dict retourné par parse_email() — clés : spf, dkim, from, reply_to

    Returns:
        float: Score entre 0.0 et 1.0
    """
    risk = 0.0

    if headers.get("spf") in ("fail", "absent"):
        risk += HEADER_SPF_FAIL

    if headers.get("dkim") == "absent":
        risk += HEADER_DKIM_ABSENT

    # Reply-To différent du From → technique de spoofing courante
    from_ = headers.get("from", "")
    reply_to = headers.get("reply_to", "")
    if reply_to and from_:
        # Extraire le domaine brut
        import re
        dom_from    = re.search(r'@([\w.\-]+)', from_)
        dom_reply   = re.search(r'@([\w.\-]+)', reply_to)
        if dom_from and dom_reply:
            if dom_from.group(1).lower() != dom_reply.group(1).lower():
                risk += HEADER_REPLY_MISMATCH

    return min(risk, 1.0)


def _compute_mail_passive_score(urls_results: list, headers: dict) -> dict:
    """
    Agrège les signaux URLs et headers en un score passif global.

    Args:
        urls_results: Liste de dict retournés par predict_url() pour chaque URL
        headers:      Dict retourné par parse_email() — section headers

    Returns:
        dict: {
            'score': float,              # Score global 0.0-1.0
            'ratio_phish': float,        # Proportion URLs phishing
            'max_url_score': float,      # Score max parmi les URLs phishing
            'header_risk': float,        # Score risque headers
            'critical_url': str | None,  # URL critique si score > URL_CRITICAL_SCORE
            'nb_urls_total': int,
            'nb_urls_phishing': int,
            'urls_summary': list         # Résumé léger par URL
        }
    """
    total_urls    = len(urls_results)
    phishing_urls = [r for r in urls_results if r.get("final_decision") == "phishing"]
    risky_urls = [r for r in urls_results if r.get("final_decision") in ("phishing", "suspicious")]

    nb_phishing = len(phishing_urls)
    ratio_phish = nb_phishing / total_urls if total_urls > 0 else 0.0

    url_scores = [r.get("confidence", 0.0) for r in risky_urls]
    max_url_score = max(url_scores) if url_scores else 0.0

    critical_url = None
    for r in risky_urls:
        if r.get("confidence", 0.0) >= URL_CRITICAL_SCORE:
            critical_url = r.get("url")
            break

    header_risk = _compute_header_risk(headers)
    
    score = (
        W_RATIO_PHISH * ratio_phish +
        W_MAX_URL     * max_url_score +
        W_HEADER      * header_risk
    )

    urls_summary = [
        {
            "url":      r.get("url", ""),
            "decision": r.get("final_decision", "unknown"),
            "confidence": round(r.get("confidence", 0.0), 3)
        }
        for r in urls_results
    ]

    return {
        "score":           round(score, 4),
        "ratio_phish":     round(ratio_phish, 3),
        "max_url_score":   round(max_url_score, 3),
        "header_risk":     round(header_risk, 3),
        "critical_url":    critical_url,
        "nb_urls_total":   total_urls,
        "nb_urls_phishing": nb_phishing,
        "urls_summary":    urls_summary,
    }


# ============================================================================
# DÉCISION FINALE MAIL
# ============================================================================

def final_decision_mail(
    bert_prob: Optional[dict],
    passive: dict,
    headers: dict
) -> dict:
    """
    Cascade de décision pour un email, inspirée de final_decision() URL.

    Logique à 7 cas par ordre de priorité :
        CAS 0 : URL critique (score > 90%) → phishing direct
        CAS 1 : BERT très confiant safe + passive faible → safe
        CAS 2 : BERT très confiant phishing → phishing ou suspicious selon passive
        CAS 3 : SPF fail + DKIM absent + BERT modéré → phishing (spoofing)
        CAS 4 : Passive élevé + BERT incertain → phishing
        CAS 5 : Passive moyen → suspicious ou safe selon BERT
        CAS 6 : Passive faible + BERT safe → safe
        FALLBACK → suspicious

    Args:
        bert_prob: {'phishing': float, 'safe': float} ou None si modèle absent
        passive:   dict retourné par _compute_mail_passive_score()
        headers:   dict headers du mail (spf, dkim, from, reply_to)

    Returns:
        dict: {
            'final_decision': 'phishing' | 'suspicious' | 'safe',
            'confidence': float,
            'source': str,
            'breakdown': dict
        }
    """
    passive_score  = passive["score"]
    ratio_phish    = passive["ratio_phish"]
    max_url_score  = passive["max_url_score"]
    header_risk    = passive["header_risk"]
    critical_url   = passive["critical_url"]

    # Fallback bert si modèle absent
    _DEFAULT_BERT = {"phishing": 0.5, "safe": 0.5}
    bert = bert_prob if isinstance(bert_prob, dict) and \
        "phishing" in bert_prob and "safe" in bert_prob \
        else _DEFAULT_BERT
    bert_available = bert_prob is not None and bert_prob is not _DEFAULT_BERT

    def _breakdown(extra: dict = None) -> dict:
        base = {
            "bert_prob":          bert if bert_available else None,
            "mail_passive_score": passive_score,
            "ratio_urls_phishing": ratio_phish,
            "max_url_score":       max_url_score,
            "header_risk":         header_risk,
            "urls_summary":        passive["urls_summary"],
            "nb_urls_total":       passive["nb_urls_total"],
            "nb_urls_phishing":    passive["nb_urls_phishing"],
            "headers": {
                "spf":         headers.get("spf"),
                "dkim":        headers.get("dkim"),
                "from":        headers.get("from"),
                "reply_to":    headers.get("reply_to"),
            }
        }
        if extra:
            base.update(extra)
        return base

    # ── CAS 0 : URL à très haut risque ───────────────────────────────────────
    if critical_url is not None:
        return {
            "final_decision": "phishing",
            "confidence":     round(max_url_score, 3),
            "source":         "url_critique",
            "advice":         f"URL malveillante confirmée détectée : {critical_url}",
            "breakdown":      _breakdown({"critical_url": critical_url})
        }

    # ── CAS 1 : BERT très confiant SAFE + passive faible ─────────────────────
    if bert["safe"] >= BERT_SAFE_HIGH and passive_score < PASSIVE_MEDIUM:
        return {
            "final_decision": "safe",
            "confidence":     round(bert["safe"], 3),
            "source":         "bert_haut_confiance",
            "breakdown":      _breakdown()
        }

    # ── CAS 2 : BERT très confiant PHISHING ──────────────────────────────────
    if bert["phishing"] >= BERT_PHISH_HIGH:
        if passive_score >= PASSIVE_HIGH:
            conf = round(0.6 * bert["phishing"] + 0.4 * passive_score, 3)
            return {
                "final_decision": "phishing",
                "confidence":     conf,
                "source":         "bert_haut_confiance && passive_eleve",
                "breakdown":      _breakdown()
            }
        if passive_score < PASSIVE_MEDIUM:
            conf = round(max(bert["phishing"], passive_score), 3)
            return {
                "final_decision": "suspicious",
                "confidence":     conf,
                "source":         "bert_haut_confiance && passive_faible",
                "advice":         "BERT détecte un mail suspect mais les URLs semblent sûres. Restez vigilant.",
                "breakdown":      _breakdown()
            }
        # Passive moyen → phishing prudent
        conf = round(0.6 * bert["phishing"] + 0.4 * passive_score, 3)
        return {
            "final_decision": "phishing",
            "confidence":     conf,
            "source":         "bert_haut_confiance && passive_moyen",
            "breakdown":      _breakdown()
        }

    # ── CAS 3 : Spoofing headers (SPF fail + DKIM absent + BERT modéré) ──────
    spf_fail   = headers.get("spf") in ("fail", "absent")
    dkim_absent = headers.get("dkim") == "absent"
    if spf_fail and dkim_absent and bert["phishing"] >= BERT_PHISH_MEDIUM:
        conf = round(0.5 * bert["phishing"] + 0.5 * header_risk, 3)
        return {
            "final_decision": "phishing",
            "confidence":     conf,
            "source":         "headers_compromis (SPF fail + DKIM absent)",
            "advice":         "Authentification email échouée — possible tentative de spoofing.",
            "breakdown":      _breakdown()
        }

    # ── CAS 4 : Passive élevé + BERT incertain ───────────────────────────────
    if passive_score >= PASSIVE_HIGH and 0.40 <= bert["phishing"] <= 0.80:
        conf = round(0.5 * bert["phishing"] + 0.5 * passive_score, 3)
        return {
            "final_decision": "phishing",
            "confidence":     conf,
            "source":         "passive_eleve && bert_incertain",
            "breakdown":      _breakdown()
        }

    # ── CAS 5 : Passive moyen ────────────────────────────────────────────────
    if PASSIVE_MEDIUM <= passive_score < PASSIVE_HIGH:
        if bert["phishing"] >= 0.50:
            conf = round(max(bert["phishing"], passive_score), 3)
            return {
                "final_decision": "suspicious",
                "confidence":     conf,
                "source":         "passive_moyen && bert_incertain",
                "advice":         "Mail suspect — ne communiquez pas d'informations sensibles.",
                "breakdown":      _breakdown()
            }
        else:
            conf = round(0.6 * bert["safe"] + 0.4 * (1 - passive_score), 3)
            return {
                "final_decision": "safe",
                "confidence":     conf,
                "source":         "passive_moyen && bert_safe",
                "breakdown":      _breakdown()
            }

    # ── CAS 6 : Passive faible + BERT safe ───────────────────────────────────
    if passive_score < PASSIVE_MEDIUM and bert["safe"] >= 0.60:
        conf = round(0.6 * bert["safe"] + 0.4 * (1 - passive_score), 3)
        return {
            "final_decision": "safe",
            "confidence":     conf,
            "source":         "passive_faible && bert_safe",
            "breakdown":      _breakdown()
        }

    # ── FALLBACK ─────────────────────────────────────────────────────────────
    conf = round((bert["phishing"] + passive_score) / 2, 3)
    return {
        "final_decision": "suspicious",
        "confidence":     conf,
        "source":         "fallback_suspicious",
        "advice":         "Analyse incertaine — traitez ce mail avec précaution.",
        "breakdown":      _breakdown()
    }


# ============================================================================
# HISTORIQUE MAIL (métadonnées uniquement)
# ============================================================================

def keep_history_mail(result: dict, history_dir: str) -> dict:
    """
    Sauvegarde les métadonnées d'une analyse mail (sans le contenu).

    Suit le même pattern que keep_history() pour les URLs.
    Sauvegarde dans history_mail.json et history_mail.txt

    Args:
        result:      Dict retourné par analyze_mail()
        history_dir: Dossier où écrire les fichiers

    Returns:
        dict: {'json': chemin, 'txt': chemin}
    """
    os.makedirs(history_dir, exist_ok=True)
    json_file = os.path.join(history_dir, "history_mail.json")
    txt_file  = os.path.join(history_dir, "history_mail.txt")

    # ── Chargement existant ───────────────────────────────────────────────────
    current_json = []
    current_txt  = ""

    if os.path.exists(json_file):
        with open(json_file, "r", encoding="utf-8") as f:
            try:
                current_json = json.load(f)
            except Exception as e:
                print("Erreur lecture history_mail.json :", e)

    if os.path.exists(txt_file):
        with open(txt_file, "r", encoding="utf-8") as f:
            try:
                current_txt = f.read()
            except Exception as e:
                print("Erreur lecture history_mail.txt :", e)

    # ── Métadonnées à sauvegarder (sans contenu mail) ─────────────────────────
    meta = {
        "date":           result.get("date", ""),
        "final_decision": result.get("final_decision", ""),
        "confidence":     result.get("confidence", 0.0),
        "source":         result.get("source", ""),
        "elapsed":        result.get("elapsed", 0.0),
        "sender":         result.get("sender", ""),
        "subject":        result.get("subject", ""),
        "nb_urls_total":  result.get("nb_urls_total", 0),
        "nb_urls_phishing": result.get("nb_urls_phishing", 0),
        "spf":            result.get("spf", ""),
        "dkim":           result.get("dkim", ""),
    }
    current_json.append(meta)

    # ── Texte lisible ─────────────────────────────────────────────────────────
    decision = meta["final_decision"]
    txt_lines = [
        "=" * 100,
        f"DATE           : {meta['date']}",
        f"EXPÉDITEUR     : {meta['sender']}",
        f"SUJET          : {meta['subject']}",
        f"DÉCISION       : {decision.upper()}",
        f"CONFIANCE      : {meta['confidence']}",
        f"SOURCE         : {meta['source']}",
        f"URLs totales   : {meta['nb_urls_total']}  |  URLs phishing : {meta['nb_urls_phishing']}",
        f"SPF            : {meta['spf']}  |  DKIM : {meta['dkim']}",
        f"DURÉE          : {meta['elapsed']}s",
        "",
    ]
    new_entry = "\n".join(txt_lines)

    count = current_txt.count("DATE") + 1
    mot_total = f"TOTAL : {count}\n"
    new_txt = mot_total + current_txt.replace(
        current_txt[:current_txt.find("\n") + 1] if current_txt.startswith("TOTAL") else "",
        ""
    ) + new_entry

    # ── Sauvegarde ────────────────────────────────────────────────────────────
    js_ok = False
    with open(json_file, "w", encoding="utf-8") as f:
        try:
            json.dump(current_json, f, indent=2, ensure_ascii=False)
            js_ok = True
        except Exception as e:
            print("Erreur sauvegarde history_mail.json :", e)

    with open(txt_file, "w", encoding="utf-8") as f:
        try:
            f.write(new_txt)
        except Exception as e:
            print("Erreur sauvegarde history_mail.txt :", e)

    return {
        "json": json_file if js_ok else "",
        "txt":  txt_file,
    }


# ============================================================================
# ORCHESTRATION PRINCIPALE
# ============================================================================

async def analyze_mail(
    raw_mail: str,
    anti_phishing_instance,
    history_dir: str,
    check_blacklist: bool = False,
) -> dict:
    """
    Analyse complète d'un email pour la détection de phishing.

    Orchestration :
        1. Parse le mail (headers + body + URLs)
        2. Construit l'input BERT et appelle MailPhishingPredict si disponible
        3. Analyse chaque URL avec predict_url()
        4. Calcule le score passif mail
        5. Prend la décision finale via final_decision_mail()
        6. Sauvegarde les métadonnées dans l'historique

    Args:
        raw_mail:              Contenu brut du mail (.eml ou texte)
        anti_phishing_instance: Instance d'AntiPhishing (pour predict_url + MailPhishingPredict)
        history_dir:           Dossier pour l'historique
        check_blacklist:       Passer aux vérifications blacklist sur les URLs

    Returns:
        dict: {
            'final_decision': str,
            'confidence': float,
            'source': str,
            'breakdown': dict,
            'date': str,
            'elapsed': float,
            'sender': str,
            'subject': str,
            'nb_urls_total': int,
            'nb_urls_phishing': int,
            'spf': str,
            'dkim': str,
            'advice': str (optionnel),
            'history': dict
        }
    """
    start = time.time()

    # ── 1. Parse du mail ──────────────────────────────────────────────────────
    try:
        parsed = parse_email(raw_mail)
    except Exception as e:
        return {
            "final_decision": "suspicious",
            "confidence":     0.5,
            "source":         "parse_error",
            "error":          str(e),
            "date":           datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
            "elapsed":        round(time.time() - start, 2),
        }

    headers  = parsed["headers"]
    urls     = parsed["urls"]

    # ── 2. BERT (si MailPhishingPredict disponible) ───────────────────────────
    bert_prob = None
    try:
        if anti_phishing_instance.MailPhishingPredict is not None:
            bert_input = build_bert_input(parsed)
            bert_result = anti_phishing_instance.MailPhishingPredict.predict(bert_input)
            bert_prob = {
                "phishing": bert_result["proba_phishing"],
                "safe":     bert_result["proba_safe"]
            }
    except Exception as e:
        print(f"MailPhishingPredict indisponible : {e}")
        bert_prob = None

    # ── 3. Analyse des URLs ───────────────────────────────────────────────────
    urls_results = []
    if urls:
        tasks = [
            asyncio.to_thread(
                anti_phishing_instance.predict_url,
                url=url,
                check_blacklist=check_blacklist,
                explain=False
            )
            for url in urls
        ]
        try:
            urls_results = await asyncio.gather(*tasks, return_exceptions=False)
            urls_results = [r for r in urls_results if isinstance(r, dict)]
        except Exception as e:
            print(f"Erreur analyse URLs : {e}")
            urls_results = []

    # ── 4. Score passif mail ──────────────────────────────────────────────────
    passive = _compute_mail_passive_score(urls_results, headers)

    # ── 5. Décision finale ────────────────────────────────────────────────────
    decision = final_decision_mail(bert_prob, passive, headers)

    elapsed = round(time.time() - start, 2)

    # ── 6. Résultat complet ───────────────────────────────────────────────────
    result = {
        **decision,
        "date":             datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
        "elapsed":          elapsed,
        "sender":           headers.get("from", ""),
        "subject":          headers.get("subject", ""),
        "nb_urls_total":    passive["nb_urls_total"],
        "nb_urls_phishing": passive["nb_urls_phishing"],
        "spf":              headers.get("spf", "absent"),
        "dkim":             headers.get("dkim", "absent"),
        "bert_available":   bert_prob is not None,
    }

    # ── 7. Historique ─────────────────────────────────────────────────────────
    history = keep_history_mail(result, history_dir)
    result["history"] = history

    return result