# Obsidian Hive — Reste à faire (détaillé)

> État au 22 août 2026. Deadline MVP : 21 octobre 2026 (anniversaire de Sam).
> MVP global estimé à ~76-80%.

---

## 🧪 Immédiat
- [ ] **Tester le workflow Scanner ↔ Alex** maintenant qu'Alex y est branché — priorité du jour, quick win sur un flux déjà en prod

---

## 🖥️ ServerAsset & agent distant
Le cœur de l'agent est codé et **validé de bout en bout sur VM réelle** (install → register → tools → self-destruct). Reste :
- [ ] Ajouter encore plus de tools ServerAsset (au-delà des 12 actuels)
- [ ] Binariser IDS/IPS et Simulateur (capabilities lourdes) pour téléchargement à la demande par l'agent
- [ ] Route de téléchargement à la demande pour ces modules binarisés + gestion des événements associés
- [ ] `tool_engine.py` à compiler/binariser aussi (décision déjà actée, pas encore fait)
- [ ] Trancher : durée exacte d'expiration de l'`install_token` (1h proposé, pas confirmé)
- [ ] Trancher : format exact du binaire (Nuitka proposé, PyArmor envisagé aussi, pas testé)
- [ ] Détail Pydantic exact du modèle `ServerAsset` à valider ligne par ligne (`install_token_expires_at`, `agent_credential_hash`, `capabilities`, `last_heartbeat`)
- [ ] Système de licence/paiement pour les modules installés localement — **rien construit à ce jour**, y compris le cas d'une licence qui expire pendant la phase d'apprentissage ML de l'IDS (recommandation existante : mettre la capture en pause, pas la perdre)
- [ ] mTLS agent↔central (durcissement, pas urgent — remplacerait le secret+hash actuel)
- [ ] Nettoyage des bridges réseau orphelins en cas de changement de `deployment_mode` à chaud (concerne NetworkAsset, pertinent le jour où ServerAsset gère aussi du réseau local via IDS)

---

## 🛰️ Scanner (module de base, ML en reprise)
- [ ] Modèle ML encore "fake" — **données d'entraînement manquantes**, trouver un moyen d'en obtenir
- [ ] Ré-auditer la détection de vulnérabilités et le scoring
- [ ] Continuer la revue des règles (`html_signatures.json`, `weights_v3_v2_semantic_equilibre.json`) — plusieurs bugs déjà corrigés (XXE, LDAP injection, XSS, règles redondantes fusionnées 157→154), possible qu'il en reste

---

## 🧫 Sandbox
- [ ] Même situation que le Scanner : modèle ML pas prêt, données d'entraînement manquantes

---

## 🕵️ TrustSignal (Deepfake / détection contenu IA)
- [ ] **Bloqué par la puissance machine** — plan : entraînement sur Google Colab
- [ ] Upload des Go de data collectées vers Colab (recommandé : passer par Google Drive + `drive.mount()` plutôt qu'upload direct, compresser avant transfert)
- [ ] Data actuellement collectée = texte anglais uniquement (3 Go) — diversification linguistique à prévoir si le marché cible est francophone

---

## 🧠 ContextGuard
- [ ] Modèle à améliorer
- [ ] Intégration SDK à simplifier pour se brancher plus facilement sur Coralie/Alex

---

## 🤖 Agents (Alex & Coralie)
- [ ] Amélioration continue des deux agents (pas de liste de tâches précise en mémoire — à définir avec Sam)
- [ ] Alex : ~95% — reste la marge des derniers % (nature exacte non précisée)
- [ ] Coralie : ~85% — reste la marge des derniers % (nature exacte non précisée)

---

## 📧 Proxy email (nouveau module, pas démarré)
- [ ] Intercepter les emails et les analyser contre le phishing **avant** qu'ils atteignent la cible
- [ ] Rapprochement à faire avec le concept déjà posé d'`EmailMonitorAsset` (design existant : IMAP IDLE + forward/BCC, mais rien codé) — à voir si c'est le même chantier ou un module distinct
- [ ] Design complet à faire : architecture, points d'intégration avec Anti-Phishing existant (`PassiveAnalyzer`)

---

## 🧩 Extension navigateur (nouveau module, pas démarré)
- [ ] Analyse temps réel des liens contre le phishing
- [ ] Design complet à faire : navigateurs cibles, mode de communication avec le backend (probablement réutilisation de l'API Anti-Phishing existante), UX

---

## 🎨 Frontend
Le plus gros chantier restant en volume. Sam code lui-même, Claude + DeepSeek en supervision.
- [ ] Poursuivre le développement du dashboard (scope V1 : assets, chat Coralie, rapports Alex, jobs planifiés, conversations)
- [ ] Système de thèmes multiples (au-delà de light/dark)
- [ ] Mode démo avec données mockées (zéro requête réseau)
- [ ] Protection des routes en mode non-démo
- [ ] UX chat "à la Claude" (thinking + tool calls en temps réel, rejouable depuis les `steps` en DB)
- [ ] Bouton "Analyser avec Alex" sur les résultats de modules

---

## 🔴 Simulator (AegisRed) — branchement
- [ ] Brancher le Simulator sur l'ensemble — actuellement **en pause**, en attendant que l'API du Simulateur et le module Sandbox soient solidifiés davantage

---

## 📋 Autres points ouverts (roadmap générale)
- [ ] Vérification de licence périodique pour les installations locales avec abonnement (lié au point licence de ServerAsset ci-dessus)
- [ ] Éventuellement : réécriture ciblée de parties critiques (boucle de capture réseau) en Rust/C — décision à prendre ensemble, pas urgent
- [ ] Trancher le renommage éventuel "HiveMind" (toujours en suspens, pas urgent)

---

## Résumé visuel — où sont les efforts restants

| Chantier | Ampleur restante | Bloqué par |
|---|---|---|
| Frontend | Gros | Rien, en cours actif |
| ServerAsset (finitions) | Moyen | Rien, cœur validé |
| Scanner ML | Moyen | Données d'entraînement |
| Sandbox ML | Moyen | Données d'entraînement |
| TrustSignal (Deepfake) | Moyen | Puissance machine → Colab |
| ContextGuard | Petit-Moyen | Rien identifié |
| Proxy email | Gros (0%) | Design pas commencé |
| Extension navigateur | Gros (0%) | Design pas commencé |
| Simulator (branchement) | Petit | Sandbox/API Simulator à solidifier |
| Licence/paiement | Non commencé | Décisions produit à prendre |
