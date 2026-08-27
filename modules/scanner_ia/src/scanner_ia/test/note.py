#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar  5 16:47:58 2026

@author: hounsousamuel
"""

"""
Toujour fais un petit fecth_head pour voir i l'url est atteignable'

Penser a verifier pourcentag de http dans https
"""

import speech_recognition as sr
import pyttsx3

class VoiceController:
    """
    Contrôle le scanner par la voix
    """
    
    def __init__(self):
        self.recognizer = sr.Recognizer()
        self.engine = pyttsx3.init()
        self.commands = {
            'scan': self._handle_scan,
            'report': self._handle_report,
            'stop': self._handle_stop,
            'status': self._handle_status,
            'vulnerabilities': self._handle_vulns_list
        }
    
    def listen(self):
        """Écoute les commandes vocales"""
        with sr.Microphone() as source:
            print("🎤 Écoute...")
            audio = self.recognizer.listen(source)
        
        try:
            command = self.recognizer.recognize_google(audio, language='fr-FR')
            print(f"📢 Commande: {command}")
            return command.lower()
        except Exception:
            return ""
    
    def speak(self, text: str):
        """Parle le texte"""
        print(f"🗣️ {text}")
        self.engine.say(text)
        self.engine.runAndWait()
    
    def _handle_scan(self, command: str):
        """Scan mon domaine example.com"""
        import re
        domain = re.search(r'scan (?:mon )?(?:domaine )?([a-zA-Z0-9.-]+)', command)
        
        if domain:
            url = domain.group(1)
            if not url.startswith('http'):
                url = 'http://' + url
            
            self.speak(f"Lancement du scan sur {url}")
            asyncio.create_task(self.scanner.scan(url))
        else:
            self.speak("Veuillez spécifier un domaine")
    
    def _handle_report(self, command: str):
        """Génère un rapport"""
        if 'détaillé' in command:
            self.speak("Génération du rapport détaillé")
            self.scanner.generate_report(detailed=True)
        else:
            self.speak("Génération du rapport résumé")
            self.scanner.generate_report()
    
    def _handle_vulns_list(self, command: str):
        """Liste les vulnérabilités"""
        vulns = self.scanner.get_vulnerabilities()
        self.speak(f"J'ai trouvé {len(vulns)} vulnérabilités")
        
        critical = [v for v in vulns if v.severity == 'critique']
        if critical:
            self.speak(f"Dont {len(critical)} critiques")

# Intégration
async def main():
    scanner = ShieldAI()  # Ton scanner
    voice = VoiceController()
    voice.scanner = scanner
    
    while True:
        command = voice.listen()
        if command:
            for cmd, handler in voice.commands.items():
                if cmd in command:
                    await handler(command)
                    break