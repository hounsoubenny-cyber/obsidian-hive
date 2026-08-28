# Obsidian Hive — Document de référence

> Plateforme de cybersécurité autonome pilotée par IA. Document vivant — mis à jour au fur et à mesure.
> Anciennement nommé ShieldAI. Renommage en "HiveMind" toujours envisagé, pas tranché.

---

## 1. Vue d'ensemble

**Ce que c'est** : une plateforme complète de cybersécurité — scan de vulnérabilités, IDS/IPS,
sandbox d'exécution, anti-phishing, simulation d'attaque — pilotée par deux agents IA (Alex et
Coralie) qui interprètent les résultats et agissent dessus.

**Portée finale visée** : 31 modules. **MVP actuel** : 5 modules de base + moteur + agents IA + API.
**Taille actuelle** : ~192 000 lignes, ~1189 fichiers `.py` (hors dossiers de sauvegarde/résumé).

**Statut global estimé : ~76-80% du MVP.** Le morceau restant le plus important est le **frontend**
(0% avant la session frontend, en cours depuis).

**Cible de marché** : PME africaines francophones en priorité, avec ambition internationale ensuite.
Modèle économique : modules vendables en standalone (scan, anti-phishing, sandbox...) OU suite
complète ; abonnement mensuel même en installation locale, avec vérification périodique de licence.

---

## 2. Les 5 modules de base (considérés terminés)

| Module | État | Détail |
|---|---|---|
| **Scanner** | ✅ | SQLi/XSS/OWASP, ML embarqué (`ScannerIA`), singleton thread-safe |
| **IDS/IPS** | ✅ | Migration vers Suricata (EVE JSON), scoring temps réel avec détection de beaconing C2, décision autonome (log/rate-limit/block), audité et profilé (py-spy) |
| **Sandbox** | ✅ | Exécution Docker isolée (13 langages), `BehaviorScorer` avec patterns MITRE ATT&CK, pipeline ML (AutoEncoder Transformer) |
| **Anti-Phishing** | ✅ | `PassiveAnalyzer` (18 checks), dataset 2M+ URLs / 36 features, intégration PhishDestroy |
| **Simulator** | ✅ | Couverture MITRE ATT&CK complète (Reconnaissance → Persistence), orchestrateur LangGraph, **déjà son propre agent intelligent** (pas besoin d'un agent central dessus) |

**Décision actée** : pas de CrewAI nulle part dans le projet — boucles d'agents manuelles pour garder
le contrôle et l'apprentissage (les anciens wrappers CrewAI pour Sandbox/Simulator sont obsolètes,
gardés comme trace historique).

---

## 3. Les Assets et le moteur

### Deux catégories d'assets

- **Surveillés dans la durée** (via `AssetItem` + `Workflow` + `Queue` du moteur) : `WebAsset`/`WebAppAsset`,
  `NetworkAsset`, `ServerAsset` (design posé, pas implémenté), `EmailMonitorAsset` (design posé, pas implémenté)
- **Actions ponctuelles** (appel direct à l'API du module, pas de moteur) : Email/URL check, Code check —
  chaque module (Anti-Phishing, Sandbox) expose déjà ses propres routes

⚠️ **Seuls 3 types d'assets sont réellement utilisables aujourd'hui** : `web_site`, `web_app`, `network`.
Server/Email/Code restent des concepts de design, pas des assets fonctionnels.

### `WebAsset` / `WebWorkflow`
- Scan → **Alex analyse automatiquement** → persistance via `ReportManager`
- Sandbox de code source : le code fourni par l'admin est **copié** (jamais utilisé en place) dans
  `OBSIDIAN_SANDBOX_ROOTS/<asset_id>/` — même principe que "le Simulator attaque un clone, jamais l'asset réel"
- `fix_allowed` recalculé automatiquement (`validate_assignment=True`) selon la présence d'un `source_code_dir` valide
- `engine.sync_source_code()` permet de rafraîchir la copie sans changer le chemin (stable, basé sur `asset_id`)

### `NetworkAsset` / `NetworkWorkflow`
- 3 modes de déploiement : **Gateway** (Obsidian = routeur), **SPAN/Mirroring** (mode promiscuous), **Bridge transparent**
- IDS/IPS lancé en **sous-processus isolé** (pas un thread) — nécessaire pour l'isolation des variables
  globales de config (`SEUIL`, `CRITICAL_PORT`...), transmises via variable d'environnement (`IDS_CONFIG_PATH`)
- Arrêt "ultra solide" : SIGTERM → attente → SIGKILL en dernier recours, `killpg` pour tuer tout le
  groupe de processus (protège aussi les `mp.Process` enfants du refit system)
- **Alex n'est PAS branché sur Network** (décision explicite — IDS/IPS a déjà sa propre intelligence
  de décision temps réel, un agent LLM serait trop lent et redondant)

### Moteur central (`ObsidianEngine`)
- `AssetManager`, `TaskManager`, `WorkflowManager`, `ObsidianManager` (queue asyncio.PriorityQueue)
- `update_asset()` avec `restart_workflow` conditionnel selon les champs modifiés (`run_fields` par classe d'asset)
- Config entièrement centralisée en **TOML + validation Pydantic** (`ConfigManager`), plus `.env` pour les secrets

---

## 4. Les agents IA

### 🔍 Alex — l'Analyste (statut : ✅ validé en conditions réelles)

- **Stateless**, conclut toujours par `create_report` (jamais de texte libre, sauf conversation
  anodine légitime sans tool utilisé)
- **10 politiques conditionnelles** dans le system prompt (prompt injection, secrets, gravité,
  incertitude, faux positifs...)
- **Tools** : `search_pattern`, `read_file`, `create_file`, `replace_file_content`,
  `modify_file_content`, `create_report` — tous confinés (fail-closed si pas de sandbox configuré)
- **"Vérité mécanique, jamais déclarative"** : `_enforce_reliable_diffs` et `_enforce_applied_state`
  écrasent après-coup ce qu'Alex *dit* avoir fait par ce qui s'est *réellement* passé (diff calculé
  par `difflib`, `fix_applied_tofile` recalculé depuis les tools réellement exécutés)
- **Validé de bout en bout** sur un vrai scénario multi-vulnérabilités (SQLi, secrets codés en dur,
  MD5 sans sel) avec **Ornith-1.0-9B** — a trouvé les 3 failles, appliqué des fixes corrects, détecté
  une tentative de prompt injection cachée dans le code analysé

### 🧠 Coralie — la Décisionnaire (statut : ✅ terminée)

- **Conversationnelle**, mémoire persistée (`ConversationManager`), personnalité chaleureuse/enjouée
- **Système de tools auto-découverts** : toute méthode suffixée `_core_tool` devient automatiquement
  un tool exposé au LLM
- **Auto-introspection** : `get_info_about_tool` — Coralie peut vérifier la vraie signature d'un tool
  avant de l'utiliser, réduit les hallucinations de paramètres
- **Catégories de tools** : lecture de code (partagée avec Alex), consultation rapports/assets,
  actions non-destructives (pause/resume/create/update asset), actions destructrices (confirmation
  humaine obligatoire), planification de tâches
- **Politique anti-hallucination notable** : ne jamais réutiliser un `item_id` mémorisé sans le
  revérifier auprès du système
- **Actions destructrices** : décorateur générique `@confirm()` (dans `human_in_loop.py`), backend
  interchangeable — `InputConfirmer` (CLI/test) ou `WSConfirmer` (prod, via WebSocket)
- **Planification** : `JobManager` dédié, basé **uniquement sur APScheduler** (pas de mélange avec le
  `TaskManager` asyncio existant), persistant (`SQLAlchemyJobStore` sur la même DB), garde-fou contre
  les triggers cron "vides" (qui se déclencheraient sinon toutes les secondes)
- **"En savoir plus"** sur un rapport d'Alex → ouvre le chat Coralie avec le rapport injecté en contexte

### Répartition des rôles

| | Alex | Coralie |
|---|---|---|
| Mémoire | Aucune | Conversation persistée |
| Sortie | Toujours un rapport structuré | Texte libre + tool calls |
| Portée | UN événement | Vue d'ensemble, cross-module, dans le temps |
| Action | Jamais (analyse/propose seulement) | Exécute réellement |

---

## 5. Infrastructure LLM

- **`LLMManager` unique et partagé** pour tout le système (Alex, Coralie, workflows) — cohérent avec
  `models_max=1` de `llama-server` (un seul modèle chargé à la fois sur le hardware disponible)
- **Adaptateur multi-provider** (`build_request_kwargs`) : gère les différences OpenAI-compatible vs
  Anthropic (system prompt séparé, `max_tokens` obligatoire, format des tools, `tool_choice`, format
  des tool_results dans l'historique)
- **Streaming** via un `EventBus` générique — les réponses streamées sont reconstruites en objets
  ayant exactement la même forme qu'une réponse non-streaming, donc le reste du code (tool calling,
  retry) ne sait jamais si ça vient d'un stream ou non
- **Serveur local** : `llama-server` (build b9833) avec `--jinja`, presets via `models.ini`
- **Modèles testés** : Qwen2.5-3B/7B, Llama-3.1-8B, Qwen3.5-4B, **Ornith-1.0-9B (recommandé comme
  modèle principal agentic)** — spécialisé coding/agentic, entraîné par RL, nécessite une température
  plus haute (0.6-1.0) que les modèles instruct classiques

---

## 6. Persistance

- **`ReportManager`** : historique complet des rapports d'Alex par asset, filtres avancés (sévérité,
  source, date), stats agrégées. `content`/`report_json` compressés en **zstd** ; `has_fix` en colonne
  dédiée (nécessaire car un champ compressé n'est plus recherchable par `LIKE`/`contains`)
- **`ConversationManager`** : conversations/messages pour Coralie, cascade delete (conversation →
  messages, jamais l'inverse), `lazy="selectin"` obligatoire (pas de lazy load classique, incompatible
  avec `AsyncSession`), `save_agent_turn()` **atomique** (un seul commit pour la paire user+assistant)

---

## 7. API / Gateway

- Auth JWT centralisée (`AuthManager`), routes CRUD assets complètes
- Route `POST /agent/alex/analyze` — usage manuel/standalone, mapping `Source → PromptMapping` /
  `Source → FixId` pour les sources sans asset réel
- Gestion d'erreurs propre (`handler_wrapper` — erreurs de validation → 4xx, pas des 500 génériques)
- Route `/token/refresh` (utilise `verify_token_without_exp_verify`)
- 20/20 tests d'intégration passés (login, CRUD assets, auth qui bloque bien sans token)

---

## 8. Frontend (en cours, démarré)

### Décisions actées
- **Deux modes** : automatique et **utilisateur-contrôlé** (l'admin peut tout piloter manuellement)
- Pas de SaaS pour l'instant, mais architecture pensée pour ne pas bloquer son ajout plus tard
- **Scope V1 complet** : assets, chat Coralie, rapports Alex, jobs planifiés, conversations
- Config runtime via `config.json` dans `public/` (URL API, **nom du produit** — actuellement
  "Obsidian Hive", changeable sans rebuild)
- Style voulu : **beau, professionnel, marquant** — explicitement PAS un style terminal/hacker
- Logo façon "lockup de marque" (nom + wordmark + icône, à la Google/Claude)
- Couleurs en variables CSS, pensées multi-thèmes dès le départ (pas juste light/dark, sélecteur
  évolutif, pas un simple bouton soleil/lune)
- Chaque module a sa propre interface épurée, nav bar intuitive
- Bouton **"Analyser avec Alex"** sur les résultats de modules (Scanner, Anti-Phishing...) → déclenche
  la route d'analyse WS, affiche le résultat en direct
- UX de chat "à la Claude" : thinking + tool calls affichés en temps réel, rejouable à l'identique
  pour les anciens messages depuis les `steps` stockés en DB
- Mode démo (données mockées, zéro requête réseau) exigé pour visualiser le rendu sans backend actif
- Protection des routes (pas d'accès sans connexion) en mode non-démo

### Historique de la démarche
- Premier essai via **Google AI Studio** jugé raté (rendu générique, chat pas dans l'esprit voulu)
- Prompt v2 (français, tokens exacts, code de référence du chat) livré, avec ajouts (masquage dans
  le chat, protection des routes)
- **Décision finale : Sam code le frontend lui-même**, avec Claude + DeepSeek en supervision/aide
  ciblée — plus de génération complète via un outil externe

---

## 9. Décisions d'architecture clés (le "pourquoi")

- **2 agents, pas 3 ni 4** : le Simulator a déjà sa propre intelligence (LangGraph), pas besoin d'un
  agent central dessus — évite la duplication et les appels LLM inutiles
- **Reporter n'est pas un agent** : génération déterministe (template), zéro LLM, pour la fiabilité
  des rapports envoyés à des clients
- **Confinement fail-closed** : sans `OBSIDIAN_SANDBOX_ROOTS` configuré, aucun accès fichier — jamais
  de confiance aveugle envers un LLM sur des chemins de fichiers
- **Agent distant toujours en connexion sortante** (jamais entrante) — évite le port forwarding côté
  client, plus sûr et plus simple à déployer
- **Vérité mécanique > déclarative** : partout où c'est possible, le code vérifie/recalcule ce qu'un
  LLM prétend avoir fait, plutôt que de lui faire confiance sur parole
- **Actions destructrices = confirmation humaine obligatoire**, jamais d'exécution directe

---

## 10. Bugs mémorables (pour ne pas les refaire)

- `.scalars()` au lieu de `.all()` sur une requête multi-colonnes → résultats corrompus silencieusement
- Boucles `await` manquants sur des coroutines (`engine.start()`, `_get_report_manager()`) → composant
  jamais vraiment démarré, aucune erreur visible
- `os.path.exits` (typo) au lieu de `exists` → `AttributeError` immédiate
- `session.get_running_loop()` appelé dans un thread sans event loop (aiohttp créé dans
  `asyncio.to_thread`) → nécessite `run_coroutine_threadsafe`, jamais passer `loop=` (déprécié dans aiohttp 4.0)
- `pause_all_jobs`/`resume_all_jobs` n'existent PAS dans l'API d'APScheduler (seulement `pause_job`/`resume_job`)
- Trigger cron sans aucun champ temporel → se déclenche toutes les secondes (garde-fou ajouté)

---

## 11. Roadmap / reste à faire

1. **Frontend** — le plus gros chantier restant, en cours (Sam + Claude/DeepSeek)
2. **ServerAsset** — protocole agent distant (WebSocket contrôle, connexion sortante, `curl | bash`) —
   design posé, rien codé
3. **EmailMonitorAsset** — IMAP IDLE + forward/BCC — design posé, rien codé
4. **Brancher le Simulator (AegisRed)** — en pause en attendant que l'API du Simulator et le module
   Sandbox soient solidifiés davantage
5. Vérification de licence périodique pour les installations locales avec abonnement
6. Éventuellement : réécriture ciblée de parties critiques (boucle de capture réseau) en Rust/C — décision à prendre ensemble, pas urgent

---

*Document généré à partir de l'historique complet du projet. À remettre à jour à chaque étape majeure.*
