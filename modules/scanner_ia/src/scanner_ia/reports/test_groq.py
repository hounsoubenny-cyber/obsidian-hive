#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Groq - Chatbot dans le terminal
"""

import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

# Initialiser le client
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# Modèles disponibles
MODELS = {
    "1": "llama-3.3-70b-versatile",
    "2": "llama-3.1-8b-instant",
    "3": "mixtral-8x7b-32768",
    "4": "gemma2-9b-it",
}

print("\n" + "=" * 50)
print("🤖 CHATBOT GROQ - Test")
print("=" * 50)

# Choix du modèle
print("\nModèles disponibles:")
for k, v in MODELS.items():
    print(f"  {k}. {v}")

choice = input("\nChoisis un modèle (1-4, défaut=1): ").strip() or "1"
model = MODELS.get(choice, MODELS["1"])
print(f"\n✅ Modèle: {model}")

# Système prompt
system_prompt = input("\nPrompt système (défaut: 'Tu es un assistant utile'): ").strip()
if not system_prompt:
    system_prompt = "Tu es un assistant utile et concis."

print("\n" + "=" * 50)
print("💬 Conversation (tapez 'quit', 'exit' ou Ctrl+C pour quitter)")
print("=" * 50)

# Historique
messages = [{"role": "system", "content": system_prompt}]

while True:
    try:
        user_input = input("\n🧑 Toi: ").strip()
        
        if user_input.lower() in ["quit", "exit", "q"]:
            print("\n👋 Au revoir !")
            break
        
        if not user_input:
            continue
        
        # Ajouter le message
        messages.append({"role": "user", "content": user_input})
        
        # Appel API
        response = client.chat.completions.create(
            messages=messages,
            model=model,
            temperature=0.7,
            max_tokens=1024,
        )
        
        # Récupérer la réponse
        reply = response.choices[0].message.content
        messages.append({"role": "assistant", "content": reply})
        
        print(f"\n🤖 Groq: {reply}")
        
    except KeyboardInterrupt:
        print("\n\n👋 Au revoir !")
        break
    except Exception as e:
        print(f"\n❌ Erreur: {e}")