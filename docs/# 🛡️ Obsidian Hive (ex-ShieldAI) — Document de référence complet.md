# 🛡️ Obsidian Hive (ex-ShieldAI) — Document de référence complet

> Récap de la conversation "Travailler sur shield" — **02 juillet 2026 → 07 août 2026** (510 messages, plusieurs sessions longues).
> Sam & Claude, co-associés : Sam code, Claude review/propose/debug. Style direct, franco-anglais, emojis, zéro flatterie gratuite.

---

## 1. 🎯 Vision & contexte du projet

**Obsidian Hive** (anciennement ShieldAI) est une plateforme de cybersécurité **autonome pilotée par IA**, pensée pour un marché **Africa-first** (PME africaines sous-protégées).

- **Objectif MVP** : au départ visé pour le 21 octobre (anniversaire de Sam), deadline ensuite **relâchée volontairement** — priorité à un MVP solide plutôt que rushé.
- **Modèle business posé** :
  - Vente en **modules standalone** (Scanner, Anti-Phishing, IDS/IPS, Sandbox) **ou** suite complète.
  - **Abonnement mensuel même en déploiement on-premise** (avec vérification périodique de licence).
  - Agent distant (Server) = **connexion sortante uniquement**, jamais de port forwarding chez le client.
  - Ambition long terme : creuser en expertise reconnue (papers, talks, contributions open-source) une fois le produit stable, + certifications IA/cyber pour Sam.
- **README** : fusion décidée entre deux versions — squelette **v1** (3 agents : AegisCore/Analyst/Red, plus proche de l'archi réelle) + positionnement **"Africa-first"** de v2 injecté dans la vision.

---

## 2. 🏗️ Architecture globale

### 2.1 Modules "métier" (Phase 1 — considérés déjà solides ~85-90% dès le début)
| Module | Rôle |
|---|---|
| **Scanner** | Scan de vulnérabilités web (ML + fuzzer + crawler, FastAPI/WebSocket) |
| **IDS/IPS** | Détection/prévention d'intrusion réseau, basé LSTM, refactoré en pattern `router` / `router_no_auth` / `_do_*` |
| **Sandbox** | Analyse comportementale de code (strace, FSMonitor, BehaviorScorer, AutoEncoder) |
| **Anti-Phishing** | Détection de phishing, 99.3% de précision annoncée |
| **Simulateur d'attaque** | Kill chain MITRE ATT&CK sur clones Docker, orchestré via **LangGraph StateGraph**, **déjà doté de sa propre IA** (mode auto + mode interactif) |

### 2.2 Décision d'architecture agents — le plus gros virage de la conversation

**Avant** : idée initiale de 3 agents CrewAI (CorrelationAgent, DecisionAgent, FixerAgent, ReporterAgent) + CrewAI comme moteur.

**Décidé pendant la conversation** :
- ❌ **CrewAI abandonné entièrement** → remplacé par des **boucles LLM manuelles** via un `LLMManager` custom (plus de contrôle, moins de magie cachée).
- ❌ Le **Simulateur n'est pas un agent central** — il a déjà sa propre intelligence (LangGraph), il est juste **appelé comme un outil** par les autres.
- ✅ **2 agents de raisonnement**, pas 3 :
  - **Alex — l'Analyste** 🔍 : comprend **UN événement à sens unique** (scan → rapport). Sans mémoire persistante, structuré (`AnalystReport`, `FixOutput`), rapport JSON + fix proposé, resistant à la prompt injection (`ContextGuard` en option).
  - **Coralie — la Décisionnaire** 🧠 (ex-"Core") : vue d'ensemble, corrèle plusieurs événements/modules, **discute avec l'admin**, planifie (JobManager/APScheduler), agit via tools, **human-in-the-loop** pour les actions destructives.
- ✅ **Reporter n'est pas un agent** — juste une fonction déterministe (JSON → HTML/PDF), zéro LLM, pour la fiabilité.
- ✅ **Alex sans mémoire → Coralie a ses propres tools de fichiers**, elle ne passe pas par Alex pour lire du code.

> Petit clin d'œil : le nom "Coralie" a été choisi en jeu de mots avec "Alex/Analyste" → prénoms contenant "Cor" (Cora, Corentin, **Coralie** retenu).

### 2.3 Le modèle des "Assets" — clarification majeure

Confusion initiale corrigée en profondeur : **"Asset" = ce qui est surveillé dans la durée**, pas n'importe quelle action.

| Catégorie | Type | Détail |
|---|---|---|
| **Asset persistant** | `WebAsset` (Site/App) | `WebWorkflow`, singleton thread-safe, scan périodique |
| **Asset persistant** | `NetworkAsset` | 3 modes de déploiement (gateway/SPAN-mirroring/bridge transparent), config isolée par asset |
| **Asset persistant** | `ServerAsset` | Agent distant installé chez le client (design posé, code en pause) |
| **Action ponctuelle** (PAS un Asset) | Email / URL / Code check | Appel API **one-shot** direct vers Anti-Phishing/Sandbox — pas besoin d'`AssetItem`/`Workflow` |
| **Design discuté, pas encore codé** | `EmailMonitor` | Surveillance continue de boîte mail — 3 approches évaluées : proxy SMTP/IMAP réel (`aiosmtpd`), connecteur API OAuth (Gmail/Outlook), règle de transfert/BCC + **IMAP IDLE** pour le temps réel |

**Règle posée et notée explicitement** : *"Asset" = surveillance dans la durée ; tout le reste passe par des routes API directes, sans complexifier inutilement le système.*

### 2.4 Moteur central (`engine.py` / `ObsidianEngine`)
- `asyncio.PriorityQueue` pour le worker principal (`main_manager.py`).
- `TaskManager` : gestion async propre avec cancel/join.
- `WorkflowManager` : scheduling périodique **avec récupération des runs interrompus**.
- `AssetManager` : SQLModel/SQLite async, mapping `AssetItem ↔ AssetItemDB` via `ASSET_CLASS_MAPPING`, sérialisation JSON des `special_fields`/`extra_fields`.
- `ObsidianEngine` : point d'entrée, async context manager.
- Bug bloquant trouvé et corrigé : **le moteur ne démarrait jamais vraiment** (§ session API/Gateway).

### 2.5 Config & robustesse système (points techniques forts)
- **`ConfigManager`** centralisé, TOML + validation Pydantic par section.
- **Isolation multi-asset pour l'IDS/IPS** : injection de la config via variable d'environnement `IDS_CONFIG_PATH`, un subprocess dédié par asset réseau.
- **Terminaison robuste des sous-process** : `start_new_session=True` + `killpg` sur le **groupe de process**, séquence `SIGTERM → (timeout) → SIGKILL`, plutôt qu'un simple `.terminate()`. Un point de fragilité identifié : la combinaison `sudo` + `killpg` (le PID vu par Python n'est pas toujours celui du process réel si lancé via `sudo`).
- Discussion approfondie **Threads vs Process vs GIL** (PEP 703 mentionné) pour justifier ces choix.
- Bug subtil trouvé : fichier de log jamais fermé, `f-string` oublié (bug silencieux), race condition dans `_graceful_stop()`.

---

## 3. 🔐 API / Gateway (`main_api.py` + `core_router.py`)

- **Auth JWT centralisée** via `AuthManager` (singleton), réellement branchée (`Depends(require_auth)`).
- Chaque module garde un router standalone **avec auth** + expose un `router_no_auth` réutilisable par la gateway (pattern factory).
- Routes CRUD assets complètes (create/list/get/delete/pause/resume) avec système de **merge de config** (`conf_str` + `validate_and_merge_config`).
- Bugs bloquants trouvés et corrigés au fil de l'eau :
  - Mauvais modèle Pydantic sur la route Network.
  - `verify_keys()` appelée sans son argument obligatoire.
  - `basename` utilisé à la place de `dirname`.
  - Mauvaise exception attrapée à plusieurs endroits.
  - Auth pas réellement branchée à un moment donné (faille de sécurité), + bug de sécurité dans `AuthManager` lui-même.
  - `"WS"` invalide dans `allow_methods` de `CORSMiddleware`.
  - Le moteur qui ne démarrait jamais réellement.
- `handler_wrapper` ajouté : gestion d'erreurs centralisée et propre (bien accueilli — "vraie bonne trouvaille").
- **20/20 tests passés** sur `NetworkAsset` en conditions réelles à un moment donné de la session.
- Discussion sur le **port dynamique de `NetworkAsset`** côté frontend : piège des variables `REACT_APP_*` (statiques au build), solution retenue = petit fichier de config **chargé au runtime**.

---

## 4. 🤖 Alex (Analyste) — décisions & implémentation

### 4.1 Design
- Tools sécurisés avec **confinement fail-closed** : un seul validateur de chemin partagé et réutilisé partout (empêchait initialement d'échapper à `source_code_dir`).
- `CreateReportEntry` / `FixOutput` : sorties structurées Pydantic.
- **Diff calculé mécaniquement** (jamais par le LLM lui-même) — jugé bien plus fiable qu'un `full_replacement` : le fix s'ancre sur le **vrai code**, pas sur une position devinée par le modèle.
- Sandbox de code **copié** (pas de modification directe des fichiers source) — approche "copie" préférée à l'ajout dynamique de racines.
- Recherche de code : `grep -E` avec restrictions strictes — jamais de `shell=True`, dossier de recherche restreint, `--binary-files=text`.
- `agent.py` avec **injection de dépendance** propre.

### 4.2 Bugs trouvés pendant le dev d'Alex
- `natural_explanition` jamais transmis (typo + bug de transmission).
- `fix_applied_tofile` **auto-déclaré par Alex** plutôt que vérifié mécaniquement → corrigé pour vérifier réellement.
- `os.path.exits` → typo cassant tout (`exists`).
- `asset.source_code_dir` jamais mis à jour vers le dossier copié.
- Risque de crash sur `shutil.rmtree`.
- `get_by_id` recevait un identifiant du mauvais type.
- Deux bugs dans `update_by_identifier`.
- `prompt_injection_detected` : incohérence où le raisonnement du modèle disait "oui" mais le champ final disait "non" — creusé en détail.
- Alex appelait `create_report` **deux fois** dans un run — comportement à surveiller.

### 4.3 Validation réelle
- **Test end-to-end réussi** : faux projet FastAPI/Flask avec injection SQL évidente → Alex a **trouvé 3 vraies vulnérabilités**, appliqué des diffs calculés mécaniquement, et **détecté une tentative de prompt injection embarquée** dans les données de test.
- Modèle local principal utilisé : **Ornith-1.0-9B** (GGUF, Q4_K_M) — validé en conditions réelles.
- Autres modèles dispo via `llama-server` + `models.ini` : Qwen2.5-3B/7B, Llama-3.1-8B, Qwen3.5-4B.
- Recherche comparative Qwen2.5 vs Gemma 4 12B pour Alex spécifiquement (recommandations données selon usage).
- **Alex validé à ~95%** en fin de conversation, "en conditions réelles, pas juste en théorie".

---

## 5. 🧠 Coralie (Décisionnaire) — décisions & implémentation

### 5.1 Rôle (posé en détail, distinct d'Alex)
- Vue d'ensemble, pas un événement isolé.
- Peut **discuter avec l'admin en chat**.
- Peut lancer une action "comme si l'admin l'avait fait" (ex : lancer un scan), avec un principe retenu : ouvrir une fenêtre à côté plutôt que d'agir totalement en silence.
- **Planification** via un vrai scheduler, pas du bricolage.

### 5.2 Persistance — `ReportManager` & `ConversationManager`
- **`ReportManager`** : même pattern que `AssetManager` (SQLModel), table dédiée (préférée à un simple champ sur l'asset) — permet des requêtes/filtres/stats propres.
- **`ConversationManager`** : 2 tables en relation 1-N (conversation → messages), avec :
  - Décision : **abandon du champ `sequence`** au profit de l'`id` auto-incrémenté directement (plus simple, plus fiable — `created_at` seul jugé trop risqué en cas de messages quasi-simultanés).
  - **Sauvegarde atomique** (`save_agent_turn`) pour ne jamais perdre la structure d'un tour d'agent (bug trouvé : `step["tool_calls"]` perdait sa structure).
  - Compression **zstd** pour les rapports/contenus volumineux.
  - Cascade de suppression à sens unique, réfléchi pour éviter les orphelins.

### 5.3 Scheduling — `JobManager`
- Décision : **APScheduler directement**, pas de réinvention, mais **combiné avec le `TaskManager` existant** plutôt que l'un contre l'autre.
- `TriggerKind` (enum) + `build_trigger` (static method) pour unifier les 4 types de triggers.
- `_resolve_trigger` : helper unifiant les inputs dict/instance.
- **Bug corrigé** : `pause_all_jobs`/`resume_all_jobs` avec `jobstore=` n'existent pas réellement dans APScheduler — fix en réutilisant le pattern qui marchait déjà ailleurs.
- **Piège pédagogique important, expliqué en détail à Sam** : un `CronTrigger()` sans aucun champ précisé n'est **pas** "jamais" — APScheduler interprète les champs non précisés comme "à chaque fois" (chaque année/mois/jour...). Un garde-fou a été codé pour éviter ce piège.
- 10 CoreTools ajoutés pour Coralie : `list_jobs`, `get_job`, `pause_job`, `resume_job`, `modify_job`, `remove_job`, etc. avec `TriggerSpec` (union discriminée Pydantic) et documentation `Field(description=...)` complète.

### 5.4 Human-in-the-loop — décorateur `@confirm`
- Pattern : décorateur qui intercepte un tool "à risque", envoie une demande de confirmation à l'admin (`Confirmer` injectable), timeout configurable.
- **Rendu robuste aux arguments positionnels** : utilisation de `inspect.signature().bind_partial()` + `apply_defaults()` pour que l'admin voie **tous** les arguments correctement nommés, peu importe comment le tool a été appelé en interne.

```python
import inspect

def confirm(confirmer: Confirmer, risk: str = "medium", timeout: int = 120):
    def decorator(fn):
        sig = inspect.signature(fn)

        @wraps(fn)
        async def wrapper(self, *args, **kwargs):
            req_id = str(uuid4())
            bound = sig.bind_partial(self, *args, **kwargs)
            bound.apply_defaults()
            all_args = dict(bound.arguments)
            all_args.pop("self", None)

            try:
                decision = await asyncio.wait_for(
                    confirmer(req_id=req_id, tool_name=fn.__name__, risk=risk, args=all_args),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                raise ConfirmationTimeout(fn.__name__, req_id)

            if not decision.approved:
                raise ConfirmationDenied(fn.__name__, decision.reason)

            return await fn(self, *args, **kwargs)
        return wrapper
    return decorator
```

### 5.5 État final Coralie
- **Déclarée complète à ~85%** en fin de conversation (tools, JobManager/APScheduler, confirmation destructive via pattern injectable).
- WebSocket : architecture formalisée avec un `core_router.py` **multiplexé** supportant chat streaming, analyse streaming, et confirmation humaine, plus `WSConfirmer` avec fix de race condition sur le check d'identité, et routage via `ContextVar`.

---

## 6. 🔌 LLMManager — refactor & streaming

- `api_keys` passé en **liste de tuples `(model_name, api_key)`** pour garder modèle/provider synchronisés pendant la rotation de clés.
- `asyncio.Lock` ajouté autour de `_rotate()`.
- Bugs corrigés : unpacking de tuple inversé, itération async de `AsyncPaginator`, `base_url` requis, `kwargs` qui masquait des valeurs, ordre des préfixes dans `api_key_client_mapper.py`.
- **Streaming + tool calling** — recherche menée en profondeur (Anthropic/OpenAI/Groq) :
  - Le principe est **le même chez tous les providers** : le texte arrive en deltas simples ; les tool calls arrivent en **fragments de string liés à un index**, à accumuler et ne parser en JSON complet **qu'une fois le bloc fermé**.
  - **Piège identifié** : seul le premier chunk contient l'`id`/nom de fonction — les chunks suivants ont `id=None` et ne comptent que sur l'`index`. Ignorer ces chunks = perdre silencieusement 90% des arguments.
  - Toujours entourer le parsing final d'un `try/except json.JSONDecodeError` (le JSON peut être tronqué si `max_tokens` est atteint en plein milieu).
  - **Approche recommandée et retenue** : streamer le **texte** (fluidité UX), mais garder les **tool calls en mode classique** (non streamé) — 90% du bénéfice pour 20% de la complexité. Le vrai streaming d'arguments de tools reporté à plus tard si besoin réel.
- `model_name=None` conservé volontairement partout dans les workflows → utilise le modèle courant du `LLMManager` partagé, cohérent avec `models_max=1`.

---

## 7. 🖥️ Autres sujets techniques traités en profondeur

- **`WebWorkflow` / `NetworkWorkflow`** : plusieurs bugs bloquants corrigés (mauvais type de champ, `field_validator` disparu puis réintroduit en surcharge dans `NetworkAssetModel`, incohérences string vs liste sur `interface`).
- **`asyncio` cross-thread / cross-loop** : plusieurs sessions dédiées à comprendre et corriger des bugs de "mauvaise boucle" (`loop=` déprécié, usage correct de `run_coroutine_threadsafe`, différence claire entre lancer une coroutine depuis le bon thread vs depuis un thread externe) — expliqué avec analogie visuelle à la demande de Sam.
- **Packaging du projet** : `~/PROJET/obsidian_hive`, installation en **mode éditable** (`pip install -e`) via `pyproject.toml`, retrait progressif des `sys.path.insert` codés en dur, fix de la résolution d'imports dans Spyder (Jedi).
- **Sécurité outillage Alex** : validateur de chemin partagé unique réutilisé partout (au lieu de checks épars), pour empêcher toute sortie du `source_code_dir` autorisé — qualifié de bug le plus important trouvé sur cette portion.
- **`count_by_severity()`** dans les stats de rapports : bug trouvé (résultats incohérents) et corrigé sur le modèle de `count_by_source` qui lui fonctionnait.
- Environnement de dev : **Spyder** pour le Python, **VSCode/Codium** pour le frontend.
- Modèles locaux disponibles en test : Ornith-1.0-9B (principal), Qwen2.5-3B/7B, Llama-3.1-8B, Qwen3.5-4B, routés via `llama-server` + presets `models.ini`.

---

## 8. 📌 Décisions & corrections explicites de Sam (à ne pas oublier)

Sam a corrigé Claude plusieurs fois — ces points font désormais **référence** :

1. Les dossiers `agent/module` avec du code CrewAI = **legacy**, à ignorer.
2. Le Simulateur a **déjà** sa propre intelligence — ce n'est **pas** un agent central séparé.
3. Email/URL/Code = **appels API one-shot**, pas des Assets.
4. Alex ne doit **pas** être intégré directement dans `NetworkWorkflow`.
5. `model_name` doit rester `None` (modèle courant du `LLMManager` partagé, cohérent avec `models_max=1`).
6. **APScheduler seul** doit gérer le scheduling, mais **combiné** (pas opposé) au `TaskManager` existant.
7. Ne pas proposer de solutions sur-complexifiées quand une solution simple suffit ("*tu vas toujours trop loin*").
8. Pacte explicite : Sam a demandé à être **chambré gentiment** si il relâche sa discipline de relecture de code — pour ne pas perdre l'instinct de repérer ses propres bugs.

---

## 9. 📊 Historique de l'avancement du MVP (snapshots successifs)

| Date / moment | % MVP global | Points marquants |
|---|---|---|
| Début conversation | non chiffré | 5 modules de base considérés OK par Sam |
| Session ~4 juillet | **40-45%** | 5 modules ~85-90%, moteur ~85%, Analyst/Dashboard à 0% |
| Sam propose 60%, Claude corrige | **~48-50%** | API bien avancée, mais Analyst (0%) et Dashboard (0%) toujours devant |
| Après tools Alex sécurisés | **65-68% (implicite)**, détail : | Analyst **0% → ~70%** (plus gros bond de la conv), API **55% → 75%** |
| Après validation Alex end-to-end | **~65-68%** | Analyst **70% → ~85%**, validé sur cas réel (3 vulns + prompt injection détectée) |
| **Dernier état (25 juillet)** | **~76-80%** | Alex **~95%** (validé bout en bout), Coralie **~85%** (déclarée complète), Dashboard toujours **0%** |

### Détail du dernier tableau de statut connu
| Partie | Statut |
|---|---|
| 5 modules de base | 85-90% |
| Moteur central | 90% |
| Asset Web | 95% |
| Asset Network | 90% |
| Asset Server | 20% (en pause) |
| API/Gateway | 75% |
| **Alex** | **~95%** 🎉 |
| **Coralie** | **~85%** 🎉 |
| ReportManager/ConversationManager | 95% |
| Dashboard/Frontend | **0%** |
| Test end-to-end complet (via UI) | Bas — pas de dashboard pour piloter visuellement |

---

## 10. 🗺️ Roadmap — ce qu'il reste à faire

### Priorité 1 — Dashboard / Frontend (0%, le plus gros morceau restant)
- Toute la partie React/TypeScript de pilotage visuel : rien commencé au niveau architecture (le chat Coralie mentionné dans les mémoires vient d'une phase **postérieure** à cette conversation).
- Recommandation actée en fin de session : démarrer ce chantier dans une **conversation fraîche dédiée**, vu l'ampleur — la mémoire persistante de Claude sert de pont de continuité entre les sessions.

### Priorité 2 — Finitions Coralie (si besoin avant le Dashboard)
- Quelques ajustements possibles évoqués juste avant la fin de la conversation captée ici (Sam venait de "corriger et terminer Coralie").

### Priorité 3 — Chantiers mis en pause consciemment
- **`ServerAsset`** (agent distant) — 20%, design de surface posé (script d'install `base64 | python3`, connexion sortante uniquement, WebSocket de contrôle), mais volontairement **pas rushé** ("il doit être solide").
- **`EmailMonitor`** — 10%, design détaillé (3 options évaluées : proxy SMTP/IMAP, connecteur OAuth, forward/BCC + IMAP IDLE), zéro code.

### Priorité 4 — Le reste
- Streaming réel du texte dans le chat Coralie (tool calls restent non-streamés pour l'instant — décision assumée).
- Test end-to-end complet du système entier une fois le Dashboard prêt pour piloter/observer visuellement.
- Stratégie business/valeur client + certifications IA/cyber pour Sam (évoqué, à creuser plus tard).

---

## 11. 💡 Bonnes pratiques & conventions retenues pour le projet

- Diff de fix **toujours calculé mécaniquement**, jamais laissé au LLM (fiabilité).
- Un seul validateur de chemin partagé pour tous les tools sensibles à la sécurité (fail-closed).
- `killpg` + `start_new_session=True` + séquence `SIGTERM → SIGKILL` pour tuer un groupe de process proprement.
- Config injectée aux subprocess via variable d'environnement (`IDS_CONFIG_PATH`) plutôt que fichiers dispersés.
- `id` auto-incrémenté plutôt que `sequence` ou `created_at` seul pour l'ordre des messages en DB.
- Pattern `router` (avec auth) + `router_no_auth` (factory) répété sur chaque module, agrégé par la gateway.
- `handler_wrapper` pour une gestion d'erreurs API uniforme.
- Sauvegardes DB critiques faites de façon **atomique** (ex : `save_agent_turn`).

---

## 12. ✅ TL;DR — état au 25 juillet 2026 (dernier point d'étape connu)

- **MVP global : ~76-80%.**
- **Backend quasi complet et solide** : 5 modules de base, moteur, gateway/API, Alex (~95%), Coralie (~85%), persistance (Report/Conversation) à 95%.
- **Le vrai gros morceau qui reste : le Dashboard (0%)** — tout le backend est prêt à être piloté visuellement, mais rien n'existe encore côté React pour ça.
- Server asset et EmailMonitor restent volontairement en pause (pas critiques pour un MVP minimal).
- Prochaine étape suggérée : attaquer le Dashboard, probablement dans une conversation dédiée fraîche.

---

*Document généré à partir de l'intégralité de la conversation "Travailler sur shield" (02/07/2026 → 07/08/2026, 510 messages).*
