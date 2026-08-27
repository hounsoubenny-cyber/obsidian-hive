#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Générateur de rapports IA avec Groq
"""

import os
import json
from pprint import pformat
from groq import Groq
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()


def generate_report(entry: str | dict, save_path: str) -> str:
    client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
    
    if isinstance(entry, dict):
        try:
            data_str = json.dumps(entry, indent=2, ensure_ascii=False, default=str)
        except Exception:
            data_str = pformat(entry, indent=2)
    else:
        data_str = entry
    
    prompt = f"""Voici les résultats d'un scan de sécurité.

            {data_str}
            
            Explique ces résultats à l'utilisateur de façon détaillée, professionnelle et simple.
            Si des vulnérabilités sont présentes, explique-les lui clairement.
            
            Rédige en Markdown.
            """
    
    try:
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "Tu es un expert cybersécurité. Tu expliques les résultats de scan simplement et professionnellement."},
                {"role": "user", "content": prompt}
            ],
            model="openai/gpt-oss-20b",
            temperature=0.3,
            max_tokens=4096,
        )
        
        report = response.choices[0].message.content
        
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, "w", encoding="utf-8") as f:
            f.write("# Rapport de scan\n\n")
            f.write(f"*Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}*\n\n")
            f.write(report)
        
        return report
    
    except Exception as e:
        fallback = f"""# Fallback LLM indisponible
        # Rapport de scan
        
        *Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}*
        
        ```json
        {data_str[:8000]}
        ⚠️ Erreur lors de la génération du rapport IA: {e}
        """
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(fallback)
        
        return fallback


