#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 28 17:04:20 2026

@author: hounsousamuel

Changelog v2:
  - _extract_fuzzer_vulns  : plus de dédup (url,vuln) — toutes occurrences conservées
                             + champ confidence depuis stats.vuln_confidence
  - _extract_passive_vulns : dédup (url,tag) + labels lisibles (plus de "a", "form"...)
  - _extract_code_vulns    : dédup (url,name)
  - _extract_pages         : fuzzer_vulns / ml_vulns séparés, vuln_details allégé,
                             source fuzzer/ml distinguée
  - build()                : chart_confidence + vuln_confidence dans fuzzer_stats
  - _build_ml_section      : is_safe (dérivé de predict), top3, threshold flag par vuln
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from scanner_ia.base_class.fuzzer_base_class             import FuzzerResult
from scanner_ia.base_class.passive_analyzer_base_class   import PassiveAnalyzerResult
from scanner_ia.base_class.code_analyse_base_class       import CodeAnalyzerResult
from scanner_ia.base_class.analyser_helper_base_class    import AnalyzerHelperResult


# ── Mapping CVSS → sévérité ──────────────────────────────────────────────────
def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:   return "critique"
    if cvss >= 7.0:   return "élevé"
    if cvss >= 4.0:   return "moyen"
    if cvss > 0:      return "faible"
    return "info"

def _severity_color(sev: str) -> str:
    return {
        "critique": "#ff3b5c",
        "élevé":    "#ff8c42",
        "moyen":    "#ffd166",
        "faible":   "#06d6a0",
        "info":     "#8ecae6",
    }.get(sev, "#8ecae6")

def _severity_order(sev: str) -> int:
    return {"critique": 0, "élevé": 1, "moyen": 2, "faible": 3, "info": 4}.get(sev, 5)

def _risk_score(vulns: list) -> float:
    """Score de risque global 0-100 basé sur CVSS des vulnérabilités."""
    if not vulns:
        return 0.0
    total = sum(v.get("cvss", 0) * (1 + 0.1 * (v.get("score", 0) / 100)) for v in vulns)
    return min(100.0, round(total / max(len(vulns), 1) * 10, 1))

def _risk_label(score: float) -> str:
    if score >= 80: return "CRITIQUE"
    if score >= 60: return "ÉLEVÉ"
    if score >= 40: return "MOYEN"
    if score >= 20: return "FAIBLE"
    return "MINIMAL"

def _risk_color(score: float) -> str:
    if score >= 80: return "#ff3b5c"
    if score >= 60: return "#ff8c42"
    if score >= 40: return "#ffd166"
    if score >= 20: return "#06d6a0"
    return "#8ecae6"

def _format_elapsed(seconds: float) -> str:
    if seconds < 1:   return f"{seconds*1000:.0f}ms"
    if seconds < 60:  return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m {s}s"

# ── Labels lisibles pour les tags passifs ─────────────────────────────────────
_PASSIVE_TAG_LABELS = {
    "a":          "Liens externes non sécurisés",
    "form":       "Formulaires non protégés",
    "meta":       "Métadonnées de sécurité manquantes",
    "script":     "Scripts potentiellement dangereux",
    "cookie":     "Cookies non sécurisés",
    "header":     "Header de sécurité manquant",
    "input":      "Champs de saisie non sécurisés",
    "iframe":     "iFrames non sécurisées",
    "link":       "Ressources externes non vérifiées",
    "img":        "Images chargées en HTTP",
    "password":   "Champ mot de passe non protégé",
    "autocomplete": "Autocomplétion activée sur champ sensible",
    "comment":     "Commentaires dans le code HTML"
}

def _passive_label(tag: str) -> str:
    """Retourne un label lisible pour un tag passif."""
    return _PASSIVE_TAG_LABELS.get(tag.lower(), tag.replace("_", " ").title())


class ReportBuilder:
    """
    Construit le dictionnaire de données pour les templates Jinja2.

    Usage :
        builder = ReportBuilder()
        data = builder.build(
            url                    = "https://target.com",
            scan_id                = "scan-001",
            date                   = "27/03/2026 à 14:32:10",
            timings                = {...},
            analyzer_helper_result = ah_result,
            passive_result         = passive_result,
            code_result            = code_result,
            fuzzer_result          = fuzzer_result,
            ml_predictions         = {'url': {"proba": {"XSS": 0.92, ...}, "predict": ["XSS"]}, ...},
        )
        report.save_html(data)
    """

    def build(
        self,
        url:                    str,
        scan_id:                str,
        date:                   str,
        timings:                Dict[str, float],
        analyzer_helper_result: AnalyzerHelperResult,
        passive_result:         PassiveAnalyzerResult,
        code_result:            CodeAnalyzerResult,
        fuzzer_result:          FuzzerResult,
        ml_predictions:         Optional[Dict[str, Dict[str, Any]]] = None,
        scanner_version:        str = "2.0.0",
        theme:                  str = "dark",
    ) -> Dict[str, Any]:

        ml_predictions = ml_predictions or {}

        # ── 1. Extraction des vulnérabilités ──────────────────────────────────
        fuzzer_vulns  = self._extract_fuzzer_vulns(fuzzer_result)
        passive_vulns = self._extract_passive_vulns(passive_result)
        code_vulns    = self._extract_code_vulns(code_result)
        all_vulns     = fuzzer_vulns + passive_vulns + code_vulns

        risk_score  = _risk_score(fuzzer_vulns)
        total_pages = len(analyzer_helper_result.elements)

        # Comptages par sévérité
        sev_counts = {"critique": 0, "élevé": 0, "moyen": 0, "faible": 0, "info": 0}
        for v in all_vulns:
            sev = v.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        total_time = sum(timings.values()) if timings else 0.0

        summary = {
            "url":             url,
            "scan_id":         scan_id,
            "date":            date,
            "scanner_version": scanner_version,
            "total_vulns":     len(all_vulns),
            "total_pages":     total_pages,
            "total_time":      _format_elapsed(total_time),
            "risk_score":      risk_score,
            "risk_label":      _risk_label(risk_score),
            "risk_color":      _risk_color(risk_score),
            "sev_critique":    sev_counts["critique"],
            "sev_eleve":       sev_counts["élevé"],
            "sev_moyen":       sev_counts["moyen"],
            "sev_faible":      sev_counts["faible"],
            "sev_info":        sev_counts["info"],
            "active_scan":     not getattr(fuzzer_result.stats, "get", lambda k, d: d)("mock", False),
            "is_mock":         fuzzer_result.stats.get("mock", False) if fuzzer_result.stats else False,
        }

        # ── 2. Tri des vulnérabilités ─────────────────────────────────────────
        active_vulns_sorted = sorted(
            fuzzer_vulns,
            key=lambda v: (_severity_order(v["severity"]), -v.get("prob", 0))
        )
        passive_vulns_sorted = sorted(passive_vulns, key=lambda v: _severity_order(v["severity"]))
        code_vulns_sorted    = sorted(code_vulns,    key=lambda v: _severity_order(v["severity"]))

        # ── 3. Pages crawlées ─────────────────────────────────────────────────
        pages = self._extract_pages(analyzer_helper_result, fuzzer_result, ml_predictions)

        # ── 4. Timings ────────────────────────────────────────────────────────
        phases = [
            {"name": k.replace("_", " ").title(), "elapsed": _format_elapsed(v), "elapsed_raw": v}
            for k, v in (timings or {}).items()
        ]

        # ── 5. Stats fuzzer ───────────────────────────────────────────────────
        fstats          = fuzzer_result.stats or {}
        vuln_confidence = fstats.get("vuln_confidence", {})

        fuzzer_stats = {
            "total_tests":      fstats.get("total_tests", 0),
            "total_responses":  fstats.get("total_responses", 0),
            "total_urls":       fstats.get("total_urls", 0),
            "total_vulns":      fstats.get("total_vulns", 0),
            "vuln_rate":        round(fstats.get("vuln_rate", 0) * 100, 2),
            "success_rate":     round(fstats.get("success_rate", 0) * 100, 1),
            "elapsed":          _format_elapsed(fuzzer_result.elapsed),
            "vuln_count":       fstats.get("vuln_count", {}),
            "vuln_by_url":      fstats.get("vuln_by_url", {}),
            "vuln_confidence":  vuln_confidence,
            "is_mock":          fstats.get("mock", False),
        }

        # Top vulns par occurrences pour le bar chart
        vuln_count  = fstats.get("vuln_count", {})
        chart_vulns = sorted([[k, v] for k, v in vuln_count.items()], key=lambda x: -x[1])[:8]
        if not chart_vulns:
            from collections import Counter
            ctr = Counter(v["vuln_name"] for v in fuzzer_vulns)
            chart_vulns = [[k, v] for k, v in ctr.most_common(8)]

        # Top vulns par prob_max pour le confidence chart
        # Structure: [[vuln_name, prob_max_global], ...]
        global_confidence: Dict[str, float] = {}
        for url_conf in vuln_confidence.values():
            for vuln, data in url_conf.items():
                pm = data.get("prob_max", 0)
                if pm > global_confidence.get(vuln, 0):
                    global_confidence[vuln] = pm

        chart_confidence = sorted(
            [[k, round(v * 100, 1)] for k, v in global_confidence.items()],
            key=lambda x: -x[1]
        )[:8]

        # ── 6. ML ─────────────────────────────────────────────────────────────
        ml_section = self._build_ml_section(ml_predictions)

        # ── 7. Analyse passive résumé ─────────────────────────────────────────
        passive_summary = passive_result.summary if passive_result else {}

        # ── 8. Headers de sécurité ────────────────────────────────────────────
        security_headers = self._extract_security_headers(analyzer_helper_result)

        # ── 9. Technologies ───────────────────────────────────────────────────
        technologies = self._extract_technologies(analyzer_helper_result)

        return {
            # Méta
            "theme":            theme,
            "generated_at":     datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
            "scanner_version":  scanner_version,

            # Sections principales
            "summary":          summary,
            "active_vulns":     active_vulns_sorted,
            "passive_vulns":    passive_vulns_sorted,
            "code_vulns":       code_vulns_sorted,
            "all_vulns":        all_vulns,
            "pages":            pages,
            "phases":           phases,
            "fuzzer_stats":     fuzzer_stats,
            "chart_vulns":      chart_vulns,
            "chart_confidence": chart_confidence,
            "ml":               ml_section,
            "passive_summary":  passive_summary,
            "security_headers": security_headers,
            "technologies":     technologies,

            # Helpers Jinja2
            "severity_color":   _severity_color,
            "format_elapsed":   _format_elapsed,
        }

    # ── Extracteurs privés ────────────────────────────────────────────────────

    def _extract_fuzzer_vulns(self, fuzzer_result: FuzzerResult) -> List[Dict]:
        """
        Extrait TOUTES les occurrences de vulns (pas de dédup par url+vuln).
        Enrichit avec les données de confiance depuis stats.vuln_confidence.
        """
        vulns = []
        if not fuzzer_result or not fuzzer_result.results:
            return vulns

        vuln_confidence = (fuzzer_result.stats or {}).get("vuln_confidence", {})

        for w in fuzzer_result.results:
            rar = w.response_analyzer_result
            if not rar or not rar.is_vulnerable:
                continue

            sev  = _cvss_to_severity(w.cvss or 0)
            conf = vuln_confidence.get(w.url, {}).get(w.vuln_name, {})

            vulns.append({
                "source":        "fuzzer",
                "type":          "active",
                "vuln_name":     w.vuln_name,
                "vuln_full":     w.vuln_full_name or w.vuln_name,
                "url":           w.url,
                "base_url":      w.base_url,
                "cvss":          w.cvss or 0,
                "severity":      sev,
                "sev_color":     _severity_color(sev),
                "score":         round(rar.score, 1),
                "prob":          round(rar.prob * 100, 1),
                "payload":       w.payload.payload_injected if w.payload else "",
                "payload_type":  w.payload_type,
                "payload_encoding": getattr(w.payload, "encoding", "") if w.payload else "",
                "indicators":    list(rar.found_indicators.keys()) if rar.found_indicators else [],
                "status_changed":    rar.status_changed,
                "delay_detected":    rar.delay_detected,
                "body_changed":      rar.body_length_changed,
                "headers_changed":   rar.headers_changed,
                "response_status":   w.payload_result.status_code if w.payload_result else 0,
                "response_delay":    w.payload_result.delay if w.payload_result else 0,
                # Données de confiance globale pour ce (url, vuln)
                "confidence": {
                    "count":        conf.get("count", 1),
                    "prob_max":     round(conf.get("prob_max", rar.prob) * 100, 1) if conf else round(rar.prob * 100, 1),
                    "prob_avg":     round(conf.get("prob_avg", rar.prob) * 100, 1) if conf else round(rar.prob * 100, 1),
                    "best_payload": conf.get("best_payload", ""),
                    "best_type":    conf.get("best_type", w.payload_type or ""),
                },
            })

        return vulns

    def _extract_passive_vulns(self, passive_result: PassiveAnalyzerResult) -> List[Dict]:
        """
        Extrait les vulns passives avec déduplication (url, tag)
        et labels lisibles pour les tags techniques.
        """
        vulns = []
        if not passive_result or not passive_result.pages:
            return vulns

        seen = set()
        for url, page in passive_result.pages.items():
            all_page_vulns = page._all_vulns() if hasattr(page, "_all_vulns") else []
            for v in all_page_vulns:
                tag = getattr(v, "tag", "")
                key = (url, tag)
                if key in seen:
                    continue
                seen.add(key)

                sev = getattr(v, "severity", "info")
                vulns.append({
                    "source":         "passive",
                    "type":           "passive",
                    "vuln_name":      _passive_label(tag),   # label lisible
                    "vuln_tag":       tag,                   # tag original conservé
                    "vuln_full":      getattr(v, "message", ""),
                    "url":            url,
                    "cvss":           0,
                    "severity":       sev,
                    "sev_color":      _severity_color(sev),
                    "score":          0,
                    "prob":           0,
                    "evidence":       getattr(v, "evidence", ""),
                    "recommendation": getattr(v, "recommendation", ""),
                })

        return vulns

    def _extract_code_vulns(self, code_result: CodeAnalyzerResult) -> List[Dict]:
        vulns = []
        if not code_result or not code_result.results:
            return vulns
    
        seen = set()
    
        def _add(url, v, check_context: str = ""):
            name = v.get("name", "")
            key  = (url, name, v.get("line_number", ""))  # line_number pour éviter dédup trop agressive
            if key in seen:
                return
            seen.add(key)
            sev = v.get("severity", "info")
            vulns.append({
                "source":         "code",
                "type":           "code",
                "vuln_name":      name,
                "vuln_full":      v.get("description", ""),
                "url":            url,
                "cvss":           v.get("cvss", 0),
                "severity":       sev,
                "sev_color":      _severity_color(sev),
                "score":          v.get("score", 0),
                "prob":           0,
                "evidence":       v.get("evidence", ""),
                "recommendation": v.get("recommendation", ""),
                "line_number":    v.get("line_number", ""),
                "code":           v.get("code", ""),
                "context":        check_context,  # ← depuis le CheckResult, pas la vuln
                "find":           v.get("find", ""),
            })
    
        for url, checks in code_result.results.items():
            if not isinstance(checks, dict):
                continue
    
            # Body
            body_check = checks.get("body")
            if body_check:
                for v in getattr(body_check, "vulns", []):
                    _add(url, v, check_context=body_check.context)  # "body"
    
            # Scripts
            for _, sub_check in checks.get("balises_script", {}).items():
                for v in getattr(sub_check, "vulns", []):
                    _add(url, v, check_context=sub_check.context)  # "balise_script_interne" etc.
    
        return vulns

    def _extract_pages(
        self,
        ah:              AnalyzerHelperResult,
        fuzzer:          FuzzerResult,
        ml_predictions:  Dict = None,
    ) -> List[Dict]:
        """
        Extrait les pages avec séparation claire fuzzer_vulns / ml_vulns.
        Les détails de vuln sont allégés dans le panneau page.
        """
        ml_predictions = ml_predictions or {}
        pages          = []
        vuln_urls      = set()

        if fuzzer and fuzzer.stats:
            vuln_urls = set(fuzzer.stats.get("vulns_url", []))

        # Index des workers vulnérables par URL
        workers_by_url: Dict[str, List] = {}
        if fuzzer and fuzzer.results:
            for w in fuzzer.results:
                rar = getattr(w, "response_analyzer_result", None)
                if rar and getattr(rar, "is_vulnerable", False):
                    workers_by_url.setdefault(w.url, []).append(w)

        for url, page in (ah.elements or {}).items():
            fetched = page.fetched if page.fetched else None
            parsed  = page.parsed  if page.parsed  else None

            # ── Vulns fuzzer pour cette page ─────────────────────────────────
            fuzzer_vuln_names = fuzzer.stats.get("vuln_by_url", {}).get(url, []) if fuzzer and fuzzer.stats else []

            vuln_details = []
            for w in workers_by_url.get(url, []):
                rar = w.response_analyzer_result
                sev = _cvss_to_severity(w.cvss or 0)
                vuln_details.append({
                    "vuln_source":    "fuzzer",
                    "vuln_name":      w.vuln_name,
                    "vuln_full":      w.vuln_full_name or w.vuln_name,
                    "cvss":           w.cvss or 0,
                    "severity":       sev,
                    "sev_color":      _severity_color(sev),
                    "payload":        str(getattr(w.payload, "payload_injected", "") or ""),
                    "payload_type":   w.payload_type or "",
                    "score":          round(rar.score, 1),
                    "prob":           round(rar.prob * 100, 1),
                    "indicators":     list(rar.found_indicators.keys()) if rar.found_indicators else [],
                    "status_changed":   rar.status_changed,
                    "delay_detected":   rar.delay_detected,
                    "body_changed":     rar.body_length_changed,
                    "headers_changed":  rar.headers_changed,
                    "response_status":  w.payload_result.status_code if w.payload_result else 0,
                    "response_delay":   round(w.payload_result.delay, 3) if w.payload_result else 0,
                    "headers_diff":     self._diff_headers(
                        getattr(w.baseline,       "headers", {}),
                        getattr(w.payload_result, "headers", {})
                    ),
                })

            # ── Vulns ML pour cette page ──────────────────────────────────────
            # ml_predictions[url] = {"proba": {...}, "predict": [...], "is_safe": bool}
            # (format construit par main_scanner._combine_ml_predictions).
            # "predict" et "is_safe" sont la vraie décision du modèle (seuil
            # déjà appliqué) — calculée UNE SEULE FOIS dans
            # ScannerIA.scanner_predict, jamais réinventée ici.
            ml_entry      = ml_predictions.get(url, {})
            ml_proba      = ml_entry.get("proba", {})
            ml_predict    = ml_entry.get("predict", [])
            is_safe_ml    = ml_entry.get("is_safe", len(ml_predict) == 0)
            ml_vuln_list  = sorted(
                [{"vuln": k, "prob": round(ml_proba.get(k, 0.0) * 100, 1)} for k in ml_predict],
                key=lambda x: -x["prob"]
            )
            ml_vuln_names = [x["vuln"] for x in ml_vuln_list]

            is_vuln_ml = bool(ml_vuln_names)

            pages.append({
                "url":            url,
                "status":         fetched.status_code if fetched else 0,
                "body_length":    fetched.body_length() if fetched and hasattr(fetched, "body_length") else 0,
                "delay":          fetched.delay if fetched else 0,
                "n_forms":        getattr(getattr(parsed, "form", None), "n_element", 0) if parsed else 0,
                "n_links":        len(getattr(parsed, "a", {}) or {}) if parsed else 0,
                "n_scripts":      len(getattr(parsed, "script", {}) or {}) if parsed else 0,
                "is_vuln":        url in vuln_urls,
                "is_vuln_ml":     is_vuln_ml,
                # Badges séparés fuzzer / ML
                "fuzzer_vulns":   fuzzer_vuln_names,
                "ml_vulns":       ml_vuln_names,
                "ml_vuln_list":   ml_vuln_list,     # avec probs pour le tooltip
                # Détails complets pour le panneau dépliable
                "vuln_details":   vuln_details,
            })

        return pages

    def _diff_headers(self, baseline: dict, payload: dict) -> List[Dict]:
        """Retourne les headers qui ont changé entre baseline et réponse payload."""
        diff     = []
        baseline = {k.lower(): v for k, v in (baseline or {}).items()}
        payload  = {k.lower(): v for k, v in (payload  or {}).items()}
        for k in sorted(set(baseline) | set(payload)):
            v_base = baseline.get(k)
            v_pay  = payload.get(k)
            if v_base != v_pay:
                diff.append({
                    "header":   k,
                    "baseline": v_base or "—",
                    "payload":  v_pay  or "—",
                    "added":    v_base is None,
                    "removed":  v_pay  is None,
                })
        return diff

    def _build_ml_section(self, predictions: Dict) -> Dict:
        """
        `predictions` attendu : {url: {"proba": {vuln: proba, ...}, "predict": [...]}}
        où "predict" est la décision RÉELLE du modèle (quel que soit le seuil
        utilisé à l'inférence — flat ou calibré par classe). "detected" est
        dérivé de l'appartenance à "predict", jamais recalculé ici via un
        seuil réinventé (sinon rapport et modèle peuvent se contredire dès
        qu'un seuil par classe diffère de 0.5).
        """
        if not predictions:
            return {"available": False, "predictions": [], "by_url": {}}

        try:
            first_val = predictions[list(predictions.keys())[0]]
        except (AttributeError, KeyError, IndexError):
            return {"available": False, "predictions": [], "by_url": {}}

        if not isinstance(first_val, dict) or "proba" not in first_val:
            return {"available": False, "predictions": [], "by_url": {}}

        by_url           = {}
        all_vulns_global = {}

        for url, entry in predictions.items():
            vuln_probs   = entry.get("proba", {})
            predict_list = entry.get("predict", [])

            vuln_list = sorted(
                [{"vuln": k, "prob": round(v * 100, 1), "detected": k in predict_list}
                 for k, v in vuln_probs.items()],
                key=lambda x: -x["prob"]
            )
            detected = [v for v in vuln_list if v["detected"]]

            # is_safe : source de vérité unique, calculée UNE SEULE FOIS dans
            # ScannerIA.scanner_predict (len(predict) == 0) et transmise
            # jusqu'ici via main_scanner._combine_ml_predictions. Jamais
            # recalculée à partir d'un seuil réinventé côté rapport — ça
            # évite justement les incohérences ("safe" affiché à côté d'une
            # vuln détectée) qu'on cherche à éliminer.
            is_safe = entry.get("is_safe", len(detected) == 0)

            by_url[url] = {
                "vulns":     vuln_list,
                "is_safe":   is_safe,
                "count":     len(detected),
                "top3":      vuln_list[:3],
            }


            # "SAFE" n'existe plus dans vuln_probs (plus une classe entraînée),
            # donc plus besoin de le filtrer ici.
            for v, p in vuln_probs.items():
                if v not in all_vulns_global or p > all_vulns_global[v]:
                    all_vulns_global[v] = p

        global_preds = sorted(
            [{"vuln": k, "prob": round(v * 100, 1)} for k, v in all_vulns_global.items()],
            key=lambda x: -x["prob"]
        )

        return {
            "available":   True,
            "predictions": global_preds,
            "by_url":      by_url,
            "top_vuln":    global_preds[0]["vuln"] if global_preds else "",
            "top_prob":    global_preds[0]["prob"]  if global_preds else 0,
            "format":      "multi_url",
        }
    
    def _extract_security_headers(self, ah: AnalyzerHelperResult) -> List[Dict]:
        """Vérifie les headers de sécurité sur la première page."""
        expected = [
            ("Strict-Transport-Security",  "critique", "Activer HSTS"),
            ("Content-Security-Policy",    "élevé",    "Définir une CSP stricte"),
            ("X-Frame-Options",            "moyen",    "Ajouter X-Frame-Options: DENY"),
            ("X-Content-Type-Options",     "faible",   "Ajouter X-Content-Type-Options: nosniff"),
            ("Referrer-Policy",            "faible",   "Définir Referrer-Policy"),
            ("Permissions-Policy",         "faible",   "Ajouter Permissions-Policy"),
            ("X-XSS-Protection",           "info",     "Ajouter X-XSS-Protection"),
        ]
        if not ah or not ah.elements:
            return []

        first_page = next(iter(ah.elements.values()), None)
        headers    = {}
        if first_page and first_page.fetched:
            headers = {k.lower(): v for k, v in (first_page.fetched.headers or {}).items()}

        results = []
        for h, sev, rec in expected:
            present = h.lower() in headers
            results.append({
                "header":         h,
                "present":        present,
                "value":          headers.get(h.lower(), "") if present else "",
                "severity":       sev if not present else "ok",
                "sev_color":      _severity_color(sev) if not present else "#06d6a0",
                "recommendation": "" if present else rec,
            })
        return results

    def _extract_technologies(self, ah: AnalyzerHelperResult) -> List[str]:
        """Détecte les technologies depuis les headers et body."""
        techs = set()
        for page in (ah.elements or {}).values():
            if not page.fetched:
                continue
            headers = page.fetched.headers or {}
            server  = headers.get("Server",       headers.get("server", ""))
            powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
            if server:  techs.add(server.split("/")[0])
            if powered: techs.add(powered.split("/")[0])
            body = page.fetched.body or ""
            for sig, name in [
                ("wp-content",  "WordPress"),
                ("joomla",      "Joomla"),
                ("drupal",      "Drupal"),
                ("laravel",     "Laravel"),
                ("django",      "Django"),
                ("react",       "React"),
                ("angular",     "Angular"),
                ("vue.js",      "Vue.js"),
                ("bootstrap",   "Bootstrap"),
                ("jquery",      "jQuery"),
            ]:
                if sig.lower() in body.lower():
                    techs.add(name)
        return sorted(techs)