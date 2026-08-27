# Obsidian Hive (ex-ShieldAI) — Document de référence complet

**Session couverte :** "Travailler sur shield" — 2 juillet 2026 → 7 août 2026 (510 messages)
**Objectif de ce document :** servir de guide et de référence — récap complet de ce qui a été fait, des décisions prises, de l'état d'avancement, et de la roadmap à venir.

---

## 1. Vue d'ensemble du projet

**Obsidian Hive** (anciennement **ShieldAI**, renommage en **HiveMind** encore à l'étude) est une plateforme de cybersécurité autonome pilotée par IA, développée en solo par Sam (Samuel Hounsou / Benny), développeur autodidacte basé à Cotonou, Bénin. C'est le projet final de son cursus ML personnel (Phase 9), et actuellement son **seul projet actif** (TrustSignal a été fusionné dedans, les autres side-projects sont fermés).

- **Scope final visé :** 31 modules. **Scope MVP actuel :** 5 modules de base + intégrations + 2 agents IA.
- **Taille actuelle du code (MVP) :** ~191 795 lignes, 1189 fichiers `.py`.
- **Deadline MVP :** anniversaire de Sam, **21 octobre 2026** — objectif affiché : "un MVP ultra solide", pas la totalité des 31 modules.
- **Dynamique de travail :** Sam code, Claude relit/propose/débogue — un vrai binôme ("c'est notre projet", pas juste celui de Sam). Sam a explicitement demandé à Claude d'avoir une vraie personnalité, de proposer activement plutôt que de renvoyer sans cesse des questions, et de le reprendre s'il se met à trop dépendre de Claude pour trouver ses propres bugs.

---

## 2. Architecture générale

### 2.1 Les 5 modules de base (considérés terminés)
- **Scanner** — scan de vulnérabilités web
- **IDS/IPS** — détection/prévention d'intrusion réseau, migré vers Suricata (EVE JSON), profilé (py-spy), logger réécrit (ThreadSafeStreamHandler, regex précompilées, padding ANSI-aware), signal handling corrigé (boucles `asyncio.sleep` interruptibles)
- **Sandbox** — image Docker avec 13 langages + honeypot filesystem, `BehaviorScorer` avec patterns MITRE, pipeline ML Transformer AutoEncoder
- **Anti-Phishing** — `PassiveAnalyzer` avec 18 checks de détection, intégration PhishDestroy, TTLCache, suite de tests 44 URLs, dataset propre de 2M+ URLs / 36 features
- **Simulateur d'attaque** — couverture complète MITRE ATT&CK (Reconnaissance, Initial Access, Execution, Persistence), orchestrateur LangGraph

### 2.2 Types d'assets
Séparation nette entre :
- **Assets persistants surveillés** (`WebAsset`, `NetworkAsset`, `ServerAsset`, `EmailMonitorAsset`) → gérés par le moteur via des Workflows récurrents (`every`)
- **Actions one-shot** (Email/URL isolé, Code) → appels API directs aux modules, sans `every`, pas de re-scan automatique

### 2.3 Moteur central (`core/engine.py` — `ObsidianEngine`)
- API : `start()`/`stop()`/`add_asset()`/`pause_asset()`/`resume_asset()`/`remove_asset()`/`sync_source_code()`
- `WorkflowManager` avec pattern `every()` et gestion `last_rest_exec_time` (reprend le timer après une `CancelledError`)
- `TaskManager` avec `_verify_attrs` (valide la queue avant démarrage)
- `PriorityQueue` asyncio avec `AssetItem.__lt__` custom (tri par priorité puis timestamp)
- **1 seul worker uvicorn, choix délibéré** — le système est *stateful* en mémoire (queue, tasks, `connected_agents`), incompatible avec le multi-worker sans externaliser l'état (Redis, etc.) — pas fait pour le MVP, scaling horizontal (plusieurs instances séparées par client) envisagé si besoin réel plus tard.

### 2.4 Agents de raisonnement — 2 agents (pas 3, pas 4 comme envisagé au début)
- **Alex** (l'Analyste) — stateless, report-only, **~95% terminé, validé de bout en bout** sur un scénario multi-vulnérabilités réel (SQLi, secrets en dur, hachage MD5 faible) avec Ornith-1.0-9B : trouvailles correctes, fixes appliqués avec diffs calculés mécaniquement, détection d'une tentative de prompt injection embarquée.
- **Coralie** (la Décisionnaire) — agent conversationnel avec mémoire persistante et capacité d'action système, **~85%, déclarée terminée**. Système de tools à auto-découverte (méthodes suffixées `_core_tool` s'auto-enregistrent) + tool d'introspection (`get_info_about_tool`) que Coralie peut appeler pour vérifier la vraie signature d'un tool avant de l'utiliser.
- **CrewAI abandonné entièrement** au profit de boucles LLM manuelles (LLMManager fait main) — pour l'apprentissage et le contrôle. (Note : des wrappers d'agents CrewAI existent encore pour Sandbox/Simulateur — antérieurs à cette décision, pas encore nettoyés.)
- **Décision produit clé :** `model_name=None` partout pour Alex/Coralie → **un seul modèle LLM actif à la fois pour tout le système** (pas de modèle différent par agent), résolu via le `LLMManager` partagé unique.

### 2.5 Infrastructure LLM
- `LLMManager` avec adaptateurs multi-provider (format de requête/réponse traduit selon la famille de provider)
- **Décision stratégique de confidentialité :** pour les 4 modules sensibles (Scanner, IDS/IPS, Sandbox, données clients) → **100% LLM local, non négociable** (un produit de cybersécurité qui envoie des vulnérabilités/IPs/infra clients à une API cloud tierce serait contradictoire avec sa proposition de valeur). Seul le chatbot admin (Coralie) pourrait avoir un **toggle opt-in explicite** pour un LLM cloud, jamais par défaut — argument marketing potentiel : "par défaut, zéro donnée ne sort de votre infrastructure".
- Développement du support Anthropic dans le `LLMManager` volontairement arrêté après avoir servi son but pédagogique (comprendre les différences de format entre providers) — le code reste, mais n'est plus peaufiné, car en prod tout tourne en local (llama-server, compatible OpenAI).
- **llama-server (b9833)** avec flag `--jinja` et presets `models.ini` pour hot-swap de modèles.
- Modèles testés : Qwen2.5-3B/7B, Llama-3.1-8B, **Ornith-1.0-9B (recommandé comme modèle principal pour les tâches agentiques)**. Qwen3.5 identifié comme surclassant Qwen2.5 malgré moins de paramètres (saut générationnel). Stratégie multi-modèle envisagée (modèle général vs modèle "Coder" spécialisé pour la génération de fix) mais simplifiée ensuite en un seul modèle actif partagé.
- **Génération automatique de schémas de tools** depuis des fonctions Python via `inspect.signature()` + type hints + parsing structuré de la docstring (économie de tokens, précision par paramètre).

### 2.6 Persistance
- **`ReportManager`** — historique des rapports par asset, stats/filtres composables ; champs `content`/`report_json` compressés en zstd, avec une colonne booléenne dédiée `has_fix` (les champs compressés ne sont plus cherchables via `contains` SQL). Testé et débuggé par Sam lui-même (bug `.scalars()`, `has_fix` en mode global).
- **`ConversationManager`** — tables `ConversationDB`/`MessageDB`, relation 1-N avec cascade delete (supprimer une conversation supprime ses messages, l'inverse est faux), `lazy="selectin"` obligatoire (pas juste préféré — le lazy loading classique lève `MissingGreenlet` en contexte async), tri par `id` auto-incrémenté (le champ `sequence` envisagé initialement a été abandonné, `id` suffit). Champ `owner` pour anticiper le multi-admin. Sauvegarde atomique `save_agent_turn` (une seule session/commit pour la paire message user+assistant). Titre de conversation généré simplement à partir des 40-50 premiers caractères du premier message (MVP), renommage manuel possible.
- Les deux managers **partagent la même base SQLite** (chacun avec sa propre table) — plus simple à sauvegarder/déployer qu'avoir deux fichiers séparés.
- **Config centralisée en TOML avec validation Pydantic.**

### 2.7 Sécurité et fiabilité — principes retenus
- **Ne jamais faire confiance à ce qu'un LLM déclare avoir fait — vérifier mécaniquement.** Appliqué deux fois : `_enforce_reliable_diffs` (les diffs proposés par Alex sont recalculés depuis ce qui a réellement été exécuté par les tools, pas depuis ce qu'Alex prétend) et `_enforce_applied_state` (le champ `fix_applied_tofile`/`all_fix_applied` est écrasé par la vérité mécanique — un set `applied_paths` alimenté uniquement par les tools de modification qui ont réellement réussi).
- Bug de fiabilité important trouvé et corrigé : le champ critique `prompt_injection_detected` pouvait être omis/mis à faux par le LLM malgré un raisonnement correct — logs complets (non tronqués) mis en place pour diagnostiquer, prompt optimisé jusqu'à résolution confirmée.
- **Recherche active plutôt que déduction :** Alex dispose de tools `search_codebase()`/`read_file_content()` pour retrouver le vrai fichier concerné par une vulnérabilité détectée par le Scanner (qui est black-box et ne connaît pas le code source) — jamais de nom de fichier deviné/halluciné.
- **`original_snippet`/`fixed_snippet` façon diff** (plutôt que fichier entier réécrit) pour que l'admin retrouve le code exact par recherche textuelle, même si le chemin de fichier annoncé est imprécis.
- **Code admin copié dans un sandbox isolé avant analyse par Alex** (jamais analysé sur place).
- **Actions destructrices (ex: `delete_asset`) via confirmation humaine en 2 temps** : décorateur générique `confirm()` (`human_in_loop.py`) adossé à un "confirmer" injectable — `InputConfirmer` pour CLI/tests, `WSConfirmer` pour la prod via WebSocket. Utilise `inspect.signature().bind_partial()` pour reconstruire l'appel complet (avec defaults) et le montrer intégralement à l'admin avant validation.
- **Isolation multi-asset pour l'IDS/IPS** : chaque `NetworkAsset` lance l'IDS dans un **sous-processus séparé** (nouvel interpréteur Python) avec la config injectée via la variable d'environnement `IDS_CONFIG_PATH` — nécessaire car Python n'importe un module qu'une fois par processus (`sys.modules`), donc une tâche asyncio dans le même process ne relirait pas la config changée. Arrêt robuste du sous-processus prévu via process groups (`killpg` + `start_new_session=True`).
- **Jamais de stockage d'identifiants SSH admin** pour le futur agent `ServerAsset` — token d'installation unique + script d'auto-enregistrement à la place.
- **Planification (scheduling)** gérée exclusivement par un `JobManager` dédié qui enveloppe **APScheduler seul** (pas de mélange avec le `TaskManager` asyncio existant) — supporte triggers cron/date/interval/calendarinterval, persistés via `SQLAlchemyJobStore` sur la même DB. Garde-fou codé contre le "piège du trigger cron vide" : si aucun champ temporel n'est fourni à un trigger cron, APScheduler l'interprète comme "à chaque seconde" plutôt que "jamais" — une vérification explicite lève une erreur claire si aucun des 8 champs temporels (year/month/day/week/day_of_week/hour/minute/second) n'est renseigné.

### 2.8 Modèle de vente / business
- Suite complète Obsidian Hive (tous modules) **+** vente en **standalone** de modules individuels (Scanner seul, Anti-Phishing seul, IDS seul, Sandbox seul).
- La plupart en ligne avec abonnement ; certains (IDS, Simulateur, ou suite complète) installables **on-premise chez le client mais avec facturation mensuelle récurrente** même en local.
- Si la suite est installée en local, le client peut vouloir protéger un *autre* réseau que le sien → nécessite le protocole agent distant (curl|bash, `ServerAsset`, contrôle à distance).
- Cible : PME africaines francophones, positionnement "Africa-first" assumé comme argument différenciant.
- Discussion honnête sur le potentiel "licorne" : possible mais statistiquement rare — conseil de Claude : viser "10 clients contents", pas la valorisation, la licorne étant une conséquence possible, pas un plan.

---

## 3. État d'avancement (dernier point réalisé, 25 juillet 2026)

| Partie | Statut |
|---|---|
| 5 modules de base (Scanner, IDS/IPS, Sandbox, Anti-Phishing, Simulateur) | 85-90% |
| Moteur central (engine) | 90% |
| Asset Web | 95% |
| Asset Network | 90% (testé en vrai, 20/20) |
| Asset Server | 20% (en pause — attend le protocole agent↔moteur central) |
| API/Gateway | 75% |
| **Alex (Analyste)** | **~95%** — validé en conditions réelles |
| **Coralie (Décisionnaire)** | **~85%** — agent complet (tools, scheduling, confirmation destructive) |
| ReportManager / ConversationManager | 95% |
| Dashboard / Frontend | **0%** |
| Test end-to-end complet via UI | Bas — pas de dashboard pour piloter visuellement |

**Total MVP estimé : ~76-80%.**

Progression au fil de la session (pour repère) : ~48-50% (avant intégration d'Alex) → ~58-62% (Alex quasi fonctionnel) → ~65-68% (Alex validé bout en bout, encore isolé) → **~76-80%** (Alex + Coralie tous deux opérationnels, backend solide).

Le tout dernier message de Sam avant la demande de ce document indiquait qu'il avait commencé à travailler sur le **frontend**, avec un focus actuel sur la **finalisation de l'API du Simulateur**, et deux décisions produit pour le dashboard :
- **Deux modes de fonctionnement** : mode **auto** et mode **user-contrôlé** (l'admin peut tout piloter manuellement — lancer des scans, utiliser chaque module individuellement).
- **Pas de SaaS pour l'instant** — mais le frontend doit être conçu pour que l'ajout du SaaS soit facile plus tard.
- **Scope V1 du dashboard : complet** — assets, chat Coralie, rapports Alex, jobs planifiés, conversations.
- Ajout récent : route `/token/refresh` dans `login_router` (réutilise `verify_token_without_exp_verify`/`verify_username`/`create_token` de l'`AuthManager`).
- Sam prévoyait d'envoyer le README (modes auto/user-contrôlé) + le code des API des modules individuels à Claude avant de rédiger le prompt pour AI Studio (génération du frontend).

---

## 4. Ce qui reste à faire (roadmap)

### Priorité immédiate — le Dashboard/Frontend (0%, le plus gros morceau restant)
- Concevoir et construire le frontend complet : assets, chat avec Coralie (streaming déjà implémenté côté backend), rapports d'Alex, jobs planifiés (JobManager), historique de conversations.
- Respecter les deux modes (auto / user-contrôlé) et la contrainte "évolutif et adaptatif" + prêt pour un futur ajout SaaS sans réécriture.
- Finaliser l'API du Simulateur (en cours au moment de la pause).
- Recommandation de Claude (25 juillet) : démarrer une **conversation fraîche dédiée** pour ce chantier plutôt que de continuer à empiler dans cette conversation-ci — la mémoire persistante sert de pont de continuité.

### Autres chantiers restants ou en pause
- **Asset Server (20%)** : protocole réel de communication agent distant ↔ moteur central (enregistrement via token, envoi d'events, réception de commandes stop/start) — actuellement juste du design de surface (`ServerAsset`, `install_token`, `agent_status`), pas d'implémentation réelle.
- **NetworkAsset en mode distant** : actuellement "local uniquement" pour le MVP, attend le protocole ci-dessus pour en profiter automatiquement.
- **API/Gateway (75%)** : quelques routes/refinements restants (`core_router.py` en partie refait manuellement par Sam).
- **Nettoyage** : anciens wrappers d'agents CrewAI dans Sandbox/Simulateur (`agent/tools.py`/`config.py`/`agent.py`) antérieurs à la décision "no CrewAI" — pas encore retirés/harmonisés.
- **Test end-to-end complet via UI** : dépend entièrement du Dashboard pour exister vraiment.
- Décision non tranchée : réécriture de certaines parties critiques en C/Rust (Sam maîtrise mieux C/C++) — évoquée une fois, jamais décidée, à rediscuter si besoin de perf.
- Renommage définitif ShieldAI → Obsidian Hive (ou HiveMind, encore à l'étude) — repoussé à la fin du projet.

---

## 5. Historique chronologique condensé des sessions

### 2-4 juillet — Fondations
Fusion des deux README (v1 comme squelette archi + positionnement "Africa-first" de v2). Deadline MVP fixée au 21 octobre. État de départ : 5 modules de base OK, intégration en cours. Clarification : 2 agents de raisonnement (pas les 3-4 initialement envisagés). Décision de sécurité pour `ServerAsset` (pas de stockage SSH). Email/URL en asset unique one-shot. **Gros chantier résolu : isolation de config IDS/IPS multi-asset** via sous-processus + variable d'environnement `IDS_CONFIG_PATH` (avec explication approfondie du piège `sys.modules`/import Python). Bugs de logging corrigés sur `NetworkWorkflow`. Clarification du modèle de vente (standalone + abonnement + on-premise facturé au mois). NetworkAsset limité au local pour le MVP.

### 4-7 juillet — API, robustesse, décision multi-provider
Discussion FastAPI (routes DELETE, fusion de routers via `include_router`). Debug du `core_router.py` de Sam (clés de config manquantes, double appel). **Abstraction multi-provider LLM** construite puis volontairement arrêtée en faveur du 100% local pour raisons de confidentialité (données clients sensibles). Génération automatique de schémas de tools depuis des fonctions Python. Décision de rester à 1 seul worker uvicorn (système stateful). Fix du paramètre `loop=` déprécié d'aiohttp. Sam demande explicitement à Claude d'avoir une vraie personnalité et de proposer activement.

### 7-8 juillet — Alex prend forme
Choix de modèle (Qwen2.5 validé vs Gemma 4/Qwen3.5 en test parallèle, stratégie multi-modèle par étape). Conception du `FixOutput`/`FixFile` (v1) pour les fixes multi-langages/fichiers. Résolution du problème "comment Alex trouve le bon fichier" via des tools de recherche active (`search_codebase`, `read_file_content`) plutôt que de deviner. Bugs corrigés dans `engine.py` (`remove_asset`, identifiants, `shutil.rmtree`). Nouvelle méthode `sync_source_code()`.

### 8-10 juillet — Fiabilité et validation d'Alex
`handler_wrapper` pour des codes HTTP propres. **Découverte et correction d'un vrai problème de fiabilité IA** : le champ `prompt_injection_detected` (et plus tard `fix_applied_tofile`) pouvait être auto-déclaré de façon incorrecte par le LLM — principe retenu : toujours vérifier mécaniquement contre ce qui a réellement été exécuté, jamais faire confiance à la déclaration du modèle. `FixOutput`/`FixFile` v2 finalisée. Point d'étape : MVP ~58-68% au fil de ces jours. Alex validé de bout en bout (~85%).

### 10-11 juillet — Naissance de Coralie
Choix de priorité (intégrer Alex dans les workflows → Core/décision → frontend en dernier). Choix du nom **Coralie** (jeu de mots avec "Core", pendant féminin d'Alex). Branchement du `report_manager` partagé à `WorkflowBase` (bug d'`await` manquant corrigé). Décision `model_name=None` → un seul modèle actif pour tout le système. Conception du catalogue de tools de Coralie (5 catégories : consultation rapports/assets, actions non-destructives, actions destructrices avec confirmation, scheduling). Sam implémente le streaming LLM correctement de son côté. Design des tables `ConversationDB`/`MessageDB` (cascade delete, lazy loading interdit en async, abandon du champ `sequence` au profit de l'`id` auto-incrémenté).

### 11 juillet → 25 juillet (résumé via mémoire persistante — détail conversationnel non entièrement relu)
Coralie terminée : système de tools à auto-découverte (`_core_tool`), tool d'introspection (`get_info_about_tool`), `JobManager` dédié à APScheduler seul (avec garde-fou contre le piège du trigger cron vide), mécanisme de confirmation humaine générique (`confirm()`/`human_in_loop.py`, `InputConfirmer`/`WSConfirmer`) utilisant `inspect.signature().bind_partial()` pour montrer l'appel complet à l'admin. `ReportManager` et `ConversationManager` finalisés et testés (compression zstd, colonne `has_fix` dédiée, sauvegarde atomique `save_agent_turn`). Point d'étape final : **MVP ~76-80%**, Alex ~95%, Coralie ~85% — Dashboard identifié comme le plus gros morceau restant, recommandation de démarrer une session dédiée pour ce chantier.

### 25 juillet → 7 août — Reprise, début du frontend
Sam a commencé le frontend, travaille sur la finalisation de l'API du Simulateur. Décisions dashboard : deux modes (auto/user-contrôlé), pas de SaaS immédiat mais architecture prête pour, scope V1 complet. Ajout de la route `/token/refresh`. Session interrompue au moment où Sam a demandé ce document de synthèse.

---

## 6. Notes sur ce document

Ce document a été reconstruit à partir de l'export complet de la conversation "Travailler sur shield" (510 messages, 2 juillet – 7 août 2026), combinant une lecture manuelle détaillée des deux premiers tiers de la conversation et la mémoire persistante tenue à jour par Claude durant la session pour la dernière partie (11–25 juillet). Certains échanges purement pédagogiques (Python/FastAPI/Unix/asyncio) ou hors-sujet (actualité IA, culture générale) ont été volontairement omis pour rester focalisé sur l'architecture, les décisions et l'avancement du projet.
