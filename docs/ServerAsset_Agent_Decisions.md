# ServerAsset & Agent distant — Document de décisions

**Contexte :** Obsidian Hive / ShieldAI. Ce document couvre toutes les décisions prises sur `ServerAsset` (surveillance/administration d'une machine distante) et l'agent qui y est installé. Server 0% avant cette session — tout ce qui suit est un design neuf, rien n'est encore codé sauf mention contraire.

---

## 1. Pourquoi ServerAsset existe — la distinction avec NetworkAsset

- **NetworkAsset** = surveille le réseau **là où Obsidian Hive tourne lui-même** (local uniquement pour le MVP).
- **ServerAsset** = surveille/administre un serveur ou réseau **ailleurs**, où Obsidian Hive n'est pas physiquement présent. Nécessite un **agent installé sur place** qui communique avec le moteur central à distance.
- **Lien entre les deux** : le protocole agent↔moteur central construit pour ServerAsset débloquera automatiquement le mode distant de NetworkAsset plus tard (même problème de fond : "un agent local qui remonte au central").

---

## 2. Scope de l'agent — décision tranchée : Option B (agent généraliste), avec garde-fou strict

Deux options envisagées :
- Option A (rejetée comme scope final, mais reste la base v1) : simple capteur IDS/IPS distant
- **Option B (retenue)** : agent généraliste multi-capabilities — surveillance réseau **et** actions à la demande (scan, anti-phishing, sandbox, port scan, lecture de logs, etc.)

**Garde-fou non négociable, décidé explicitement** : **pas de shell arbitraire.** L'agent n'exécute jamais une commande libre envoyée par un LLM ou un admin — uniquement des **tools précis et fermés**, chacun audité, avec confirmation humaine obligatoire pour tout ce qui est sensible (même mécanisme `confirm()`/`WSConfirmer` déjà utilisé pour Coralie). Raison : un agent à shell ouvert, potentiellement piloté par un LLM, serait la fonctionnalité la plus dangereuse de tout le projet (risque de prompt injection → exécution de commande arbitraire sur l'infra de production d'un client). Sam a confirmé explicitement ne jamais vouloir qu'un LLM pilote cet agent sans validation humaine.

---

## 3. Les deux façons d'utiliser une capability — distinction clé

### 3.1 Exécution relayée par l'agent (capabilities "sans installation lourde")
Pour Scanner (web), Anti-Phishing, Sandbox, Port Scan (réutilise le scanner de ports déjà présent dans le Simulateur — pas de nouveau module à écrire) : la **logique tourne côté moteur central**, mais le **trafic réseau** est relayé via l'agent quand la cible n'est joignable que depuis le réseau local du client (ex: site interne, IP privée du LAN). L'agent sert de tunnel/proxy réseau, pas d'exécuteur de la logique métier.

Piège identifié à éviter : si un admin, depuis le dashboard central, entre `localhost`/une IP privée en pensant cibler le réseau du client, sans passer par le relais agent, ça résout vers le serveur central lui-même, pas vers la bonne machine — d'où la nécessité d'un vrai tunnel, pas un simple passage d'URL.

### 3.2 Modules installés localement (capabilities "lourdes")
IDS/IPS et Simulateur d'attaque doivent tourner **physiquement sur la machine cible** pour agir réellement (capture de trafic, exécution de payloads sur place). Ces modules sont **téléchargés à la demande** par l'agent une fois installé, pas embarqués de force dans l'installation de base.

**Protection du code** : ces modules seront distribués sous forme de **binaire compilé** (Nuitka recommandé plutôt que PyInstaller — transpile en C avant compilation, plus résistant à la rétro-ingénierie qu'un bytecode `.pyc` extractible), servi via une route backend dédiée (`GET /agent/modules/{module}?version=x`), accessible uniquement avec le credential de l'agent.
⚠️ **Limite honnête à garder en tête** : un binaire compilé ralentit un curieux, mais ne bloque pas un attaquant déterminé avec accès root sur sa propre machine (dump mémoire, débogueur). C'est un rehaussement de barrière, pas un coffre-fort — l'argument de vente reste l'abonnement/support/mises à jour, pas "impossible à copier".

---

## 4. Flow d'installation de l'agent

1. Admin crée un `ServerAsset` (dashboard ou via Coralie) → backend génère un `install_token` **à usage unique**, expirant (proposition : 1h par défaut), `agent_status = pending_install`
2. UI affiche une commande à copier :
   ```
   curl -sSL https://<host>/api/agent/install.sh?token=xxx | bash
   ```
3. Le script d'installation (téléchargé via route dédiée, pas d'auth requise — le token est déjà la preuve) :
   - détecte OS/architecture
   - crée un utilisateur + dossier dédiés (`/opt/obsidian-agent`)
   - installe le **cœur de l'agent** (léger : registration, heartbeat, exécution de tools, dashboard local — voir §6) comme service systemd
   - écrit la config locale (token + URL du moteur central)
   - démarre le service
4. **Premier contact** : l'agent appelle `/agent/register` avec le token → le central valide (unique, non expiré, correspond à un `ServerAsset` en attente) → échange contre un **credential longue durée**, généré une seule fois → le token est immédiatement invalidé
5. **Fonctionnement courant** : l'agent ouvre un canal WebSocket persistant vers le central (heartbeat régulier), `agent_status` passe à `connected`. Le central peut alors lui envoyer des tool calls via ce canal — même famille de pattern que le `WSManager` déjà utilisé pour la connexion admin, avec un registre séparé de type `connected_agents`.

---

## 5. Authentification agent ↔ central

**Décision MVP : secret + hash, pas mTLS.**
- Au `/agent/register` réussi, le central génère un secret aléatoire (32 bytes), le transmet **une seule fois** à l'agent (stocké dans sa config locale), et ne garde que le **hash** côté central (jamais le secret en clair en DB) — comparaison type mot de passe à chaque requête ultérieure.

**Note pour plus tard — durcissement mTLS (à garder, pas urgent) :**
> Actuellement : credential secret + hash côté central (simple, suffisant pour le MVP).
> Amélioration prévue plus tard : passer en **mTLS** (mutual TLS) — chaque côté (agent ET central) présente un certificat pour prouver son identité mutuellement dès l'établissement de la connexion, avant tout échange. Beaucoup plus résistant au vol/rejeu qu'un secret classique (implique une clé privée qui ne quitte jamais la machine), et permet une révocation instantanée d'un agent précis. Coût : infra de génération/renouvellement/révocation de certificats à construire — pas justifié tant que le MVP tourne avec peu de clients ; à réévaluer une fois en prod avec plusieurs serveurs distants réels.

---

## 6. Dashboard local sur la machine du ServerAsset

Le script d'installation déploie aussi un **mini-dashboard local**, servi directement sur la machine du client (ex: `localhost:PORT`). Objectif : permettre à un opérateur physiquement sur place (typiquement quelqu'un de l'équipe du client, pas l'admin Obsidian Hive) d'agir sans qu'on lui distribue un compte admin central séparé.

- **Authentification de ce dashboard local** : pas de login classique — c'est **le credential de l'agent lui-même** qui prouve la légitimité de l'accès (la machine a déjà été enregistrée comme ServerAsset valide).
- **Scope d'accès — décision tranchée : strictement limité à cet asset**, jamais une vue sur l'ensemble du central. Raisons :
  - **Sécurité** : si le credential agent donnait accès à tout le central, la compromission d'**un seul client** exposerait potentiellement les données de **tous les autres clients** — inacceptable pour un produit de cybersécurité, et contraire au modèle multi-tenant.
  - **Métier** : l'opérateur sur place appartient à l'équipe du client, pas à Obsidian Hive — aucune raison qu'il voie les assets/rapports d'un autre client.
  - **Implémentation** : pas une confiance côté frontend — toute requête passée via ce dashboard local est filtrée **côté backend** par `server_asset_id = celui de cette machine`, cohérent avec le principe déjà appliqué partout ailleurs dans le projet ("jamais confiance au client, toujours vérifié serveur").

---

## 7. Catalogue de capabilities — état des lieux

| Capability | Type d'exécution | Statut |
|---|---|---|
| Scanner web (vulnérabilités OWASP) | Relayée (logique centrale, tunnel réseau via agent) | Design confirmé |
| Anti-Phishing (email/URL) | Relayée | Design confirmé |
| Sandbox (analyse de code) | Relayée | Design confirmé |
| Port scan | Relayée — **réutilise le scanner de ports déjà existant dans le Simulateur**, pas de nouveau module | Design confirmé |
| IDS/IPS | Module installé localement, à la demande | Design confirmé (packaging binaire à faire) |
| Simulateur d'attaque | Module installé localement, à la demande | Design confirmé (packaging binaire à faire) |
| `check_service_status`, `read_log_tail`, `get_system_info` | Tools simples, exécution locale par l'agent | Proposés comme premiers tools de test du pipeline |

---

## 8. Ordre de construction proposé (pas encore commencé au moment de ce document)

1. Modèle `ServerAsset` (types.py, sur le patron de `NetworkAsset`)
2. Génération/validation de l'`install_token`
3. Route `/agent/register` (remplace le stub existant dans `core_router.py`)
4. Registry des agents connectés + canal WS agent↔central
5. Catalogue de tools v1 (3-4 tools simples : `get_system_info`, `check_service_status`, `read_log_tail`) pour valider le pipeline de bout en bout
6. Script d'installation, une fois le reste testable

---

## 9. Points encore ouverts / à trancher plus tard

- **Système de licence/paiement pour les modules installés localement** — pas encore construit. Note importante actée : **l'IDS n'a pas de modèle ML fixe/livré** — le modèle est entraîné sur place, sur le trafic spécifique de chaque client (phase d'apprentissage : Suricata tourne en IPS seul le temps de capturer le trafic, puis un modèle est fit et Suricata repasse en IDS complété par le ML). Conséquences : (1) le modèle entraîné n'a presque aucune valeur à protéger en soi (inutilisable ailleurs) — ce qui compte à protéger, c'est le code/la méthodologie (pipeline de features, hyperparamètres, logique de seuil), pas un résultat figé ; (2) déporter l'entraînement/l'inférence côté central est exclu — ça enverrait le trafic brut du client vers l'extérieur, contraire à la décision de confidentialité déjà actée (100% local pour les modules sensibles). Question ouverte, non tranchée (pas de système de licence construit à ce jour) : que faire des données déjà capturées si la licence expire/coupe **pendant** la phase d'apprentissage (avant que le modèle soit fit) ? Recommandation de Claude à réévaluer le moment venu : Suricata continue en IPS seul (règles), la capture pour le ML se met en pause plutôt que d'être perdue, reprend si la licence est revalidée — cohérent avec le principe de grace period (ne jamais couper la protection de base pour un souci de connectivité/paiement temporaire).
- Mécanisme de vérification de licence proposé (à formaliser) : heartbeat WS agent↔central existant réutilisé pour transporter un flag `license_status: valid | grace_period | invalid` ; grace period recommandée avant toute coupure de fonctionnalité pour ne pas pénaliser une simple coupure réseau temporaire.
- Protection du code des modules installés localement : combiner compilation (Nuitka ou **PyArmor**, spécifiquement pensé pour Python) + vérification de licence périodique + checksum d'intégrité au démarrage — aucune couche n'est infaillible seule, l'empilement rend l'effort disproportionné pour un attaquant occasionnel. Limite assumée : inefficace contre un attaquant déterminé avec accès root sur sa propre machine.
- Détail exact du modèle Pydantic `ServerAsset` (champs `install_token_expires_at`, `agent_credential_hash`, `capabilities`, `last_heartbeat` — brouillon proposé, pas encore validé ligne par ligne)
- Durée d'expiration exacte de l'`install_token` (1h proposé, pas confirmé)
- Format de packaging exact du binaire des modules lourds (Nuitka proposé, pas testé)
- Nettoyage des bridges réseau orphelins en cas de changement de `deployment_mode` à chaud (concerne NetworkAsset, mais pertinent le jour où ServerAsset gère aussi du réseau local via IDS) — voir note dédiée déjà écrite séparément
