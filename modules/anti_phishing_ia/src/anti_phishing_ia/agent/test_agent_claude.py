#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jun 10 08:44:46 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShieldAI — Agent Anti-Phishing (CrewAI)
Auteur: hounsousamuel
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Optional
from crewai import Agent, Task, Crew
from crewai.tools import tool

# ── Import direct des fonctions du module (pas de HTTP) ──────────────────────
from anti_phishing_ia.core.features_extractor import _features_extractor_from_url
from anti_phishing_ia.ml_model.phishing_ia import PhishingModel  # adapter selon ton import réel
from anti_phishing_ia.config import DATA

logger = logging.getLogger("shieldai.agent.antiphishing")

# ── État partagé de l'agent ──────────────────────────────────────────────────
_model: Optional[PhishingModel] = None
_analysis_history: list[dict] = []

def _get_model() -> PhishingModel:
    global _model
    if _model is None:
        _model = PhishingModel(DATA)
        _model.load()
    return _model


# ── Tools ────────────────────────────────────────────────────────────────────

@tool("analyze_url")
def analyze_url(url: str) -> str:
    """
    Analyse une URL et retourne un score de phishing avec les features extraites.
    Retourne un JSON avec: url, label (safe/phishing), score, features principales.
    """
    try:
        # 1 — extraction features
        features = asyncio.run(_features_extractor_from_url(url))

        # 2 — prédiction modèle
        model = _get_model()
        result = model.predict(features)  # adapter selon ton API réelle

        # 3 — log historique
        entry = {
            "timestamp": datetime.now().isoformat(),
            "url": url,
            "label": result.get("label", "unknown"),
            "score": result.get("score", -1),
            "suspicious_signals": _extract_suspicious_signals(features),
        }
        _analysis_history.append(entry)
        logger.info(f"[analyze_url] {url} → {entry['label']} (score={entry['score']})")

        return json.dumps(entry, ensure_ascii=False)

    except Exception as e:
        logger.error(f"[analyze_url] Erreur: {e}")
        return json.dumps({"url": url, "label": "error", "error": str(e)})


@tool("analyze_batch")
def analyze_batch(urls_json: str) -> str:
    """
    Analyse une liste d'URLs en parallèle.
    Paramètre: JSON string d'une liste d'URLs ex: '["http://a.com", "http://b.com"]'
    Retourne: JSON liste de résultats.
    """
    try:
        urls = json.loads(urls_json)
        if not isinstance(urls, list):
            return json.dumps({"error": "urls_json doit être une liste JSON"})

        async def _run_all():
            tasks = [_features_extractor_from_url(u) for u in urls]
            return await asyncio.gather(*tasks, return_exceptions=True)

        features_list = asyncio.run(_run_all())
        model = _get_model()
        results = []

        for url, features in zip(urls, features_list):
            if isinstance(features, Exception):
                results.append({"url": url, "label": "error", "error": str(features)})
                continue
            result = model.predict(features)
            results.append({
                "url": url,
                "label": result.get("label", "unknown"),
                "score": result.get("score", -1),
                "suspicious_signals": _extract_suspicious_signals(features),
            })

        phishing_count = sum(1 for r in results if r.get("label") == "phishing")
        logger.info(f"[analyze_batch] {len(urls)} URLs analysées — {phishing_count} phishing détectés")
        return json.dumps({"total": len(urls), "phishing": phishing_count, "results": results}, ensure_ascii=False)

    except Exception as e:
        logger.error(f"[analyze_batch] Erreur: {e}")
        return json.dumps({"error": str(e)})


@tool("get_analysis_history")
def get_analysis_history(limit: int = 20) -> str:
    """
    Retourne l'historique des dernières analyses effectuées.
    Paramètre limit: nombre max d'entrées à retourner (défaut 20).
    """
    history = _analysis_history[-limit:]
    phishing = [h for h in history if h.get("label") == "phishing"]
    return json.dumps({
        "total_analyzed": len(_analysis_history),
        "last_entries": history,
        "phishing_in_last": len(phishing),
    }, ensure_ascii=False)


@tool("get_model_status")
def get_model_status() -> str:
    """
    Retourne l'état actuel du modèle anti-phishing.
    Inclut: modèle chargé, dernier refit, nombre d'analyses effectuées.
    """
    try:
        model = _get_model()
        status = {
            "loaded": model is not None,
            "total_analyses": len(_analysis_history),
            "model_path": DATA.get("model_path"),
            "n_features": DATA.get("n_features"),
            "refit_time": DATA.get("refit_time"),
        }
        # ajouter les infos du modèle si disponibles
        if hasattr(model, "last_refit"):
            status["last_refit"] = str(model.last_refit)
        if hasattr(model, "accuracy"):
            status["accuracy"] = model.accuracy

        return json.dumps(status, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"loaded": False, "error": str(e)})


@tool("trigger_refit")
def trigger_refit() -> str:
    """
    Force un refit du modèle anti-phishing sur les nouvelles données disponibles.
    À utiliser quand de nouveaux patterns de phishing ont été détectés.
    """
    try:
        model = _get_model()
        if hasattr(model, "refit"):
            model.refit()
            logger.info("[trigger_refit] Refit déclenché avec succès")
            return json.dumps({"status": "success", "message": "Refit déclenché", "timestamp": datetime.now().isoformat()})
        return json.dumps({"status": "skipped", "message": "Méthode refit non disponible"})
    except Exception as e:
        logger.error(f"[trigger_refit] Erreur: {e}")
        return json.dumps({"status": "error", "error": str(e)})


# ── Helper privé ─────────────────────────────────────────────────────────────

def _extract_suspicious_signals(features: dict) -> list[str]:
    """Extrait les signaux suspects d'un dict de features pour le rapport."""
    signals = []
    if features.get("has_ip"):           signals.append("IP dans URL")
    if features.get("has_punycode"):     signals.append("Punycode détecté")
    if features.get("suspicious_tld"):   signals.append("TLD suspect")
    if features.get("brand_in_subdomain"): signals.append("Brand dans subdomain")
    if features.get("has_at_sign"):      signals.append("@ dans URL")
    if features.get("n_redirects", 0) > 2: signals.append(f"{features['n_redirects']} redirections")
    if features.get("num_suspicious_words", 0) > 2:
        signals.append(f"{features['num_suspicious_words']} mots suspects")
    if features.get("domain_entropy", 0) > 4.0:
        signals.append(f"Entropie domaine élevée ({features['domain_entropy']:.2f})")
    if features.get("has_nonstandard_port"):
        signals.append("Port non standard")
    return signals


# ── Création de l'agent ──────────────────────────────────────────────────────

def create_anti_phishing_agent(llm) -> Agent:
    """
    Crée et retourne l'agent Anti-Phishing ShieldAI.
    Paramètre llm: instance LLM CrewAI (Groq/Mistral 7B recommandé).
    """
    return Agent(
        role="Anti-Phishing Specialist",
        goal=(
            "Détecter et analyser les URLs et emails de phishing avec précision maximale. "
            "Identifier les patterns suspects, scorer les menaces et alerter l'orchestrateur "
            "en cas de détection confirmée."
        ),
        backstory=(
            "Tu es un expert en cybersécurité spécialisé dans la détection de phishing. "
            "Tu analyses les URLs avec un modèle ML entraîné sur 2M+ URLs et 33 features. "
            "Tu travailles au sein de ShieldAI, plateforme de cybersécurité autonome. "
            "Tu reportes uniquement les faits — score, signaux suspects, label — sans interprétation excessive."
        ),
        tools=[
            analyze_url,
            analyze_batch,
            get_analysis_history,
            get_model_status,
            trigger_refit,
        ],
        llm=llm,
        verbose=True,
        allow_delegation=False,  # agent spécialisé, ne délègue pas
    )


# ── Tasks prédéfinies ────────────────────────────────────────────────────────

def task_analyze_single(agent: Agent, url: str) -> Task:
    return Task(
        description=f"Analyse l'URL suivante et détermine si elle est du phishing: {url}",
        expected_output=(
            "Un rapport JSON avec: label (safe/phishing), score, signaux suspects détectés, "
            "et une recommandation (bloquer / surveiller / autoriser)."
        ),
        agent=agent,
    )


def task_analyze_email_links(agent: Agent, urls: list[str]) -> Task:
    urls_json = json.dumps(urls)
    return Task(
        description=(
            f"Un email intercepté contient {len(urls)} liens. "
            f"Analyse tous ces liens et détermine si l'email est une tentative de phishing: {urls_json}"
        ),
        expected_output=(
            "Un rapport complet: nombre de liens phishing détectés, liste des URLs dangereuses "
            "avec leurs scores, verdict final sur l'email (phishing / suspect / safe), "
            "et action recommandée à l'orchestrateur."
        ),
        agent=agent,
    )


def task_monitor_report(agent: Agent) -> Task:
    return Task(
        description="Génère un rapport de monitoring sur les dernières analyses anti-phishing effectuées.",
        expected_output=(
            "Rapport incluant: nombre total d'analyses, taux de phishing détecté, "
            "patterns récurrents observés, état du modèle, recommandation de refit si nécessaire."
        ),
        agent=agent,
    )


# ── Utilisation standalone (test) ────────────────────────────────────────────

if __name__ == "__main__":
    from langchain_groq import ChatGroq  # adapter selon ton setup

    llm = ChatGroq(model="mistral-7b-instruct", temperature=0)
    agent = create_anti_phishing_agent(llm)

    # Test analyse simple
    task = task_analyze_single(agent, "http://paypal-secure-verify.tk/login?ref=paypal")
    crew = Crew(agents=[agent], tasks=[task], verbose=True)
    result = crew.kickoff()
    print(result)