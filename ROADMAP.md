# ShieldAI — Roadmap Technique

> Document de référence interne. Mis à jour au fur et à mesure.

---

## Vue d'ensemble

ShieldAI est organisé en 7 couches. Chaque couche dépend de la précédente.
On ne passe pas à la couche suivante tant que la précédente ne tourne pas.

```
COUCHE 7 — Dashboard + Ecosystem        (React, extension, mail proxy)
COUCHE 6 — API Gateway                  (FastAPI, routes, WebSocket)
COUCHE 5 — Agents IA                    (AegisAnalyst, AegisCore, AegisRed)
COUCHE 4 — Event Bus                    (asyncio.Queue → Redis plus tard)
COUCHE 3 — Managers                     (Workflow, Task, Asset, Alert)
COUCHE 2 — Workflows                    (Web, Server, Email, Network, Code)
COUCHE 1 — Fondations                   (types, modèles, classes asset)
```

---

## Couche 1 — Fondations

### `assets/types.py` 🔄 en cours
Tous les enums et modèles Pydantic de base.

**Contenu :**
- `Priority(IntEnum)` — LOW, MEDIUM, HIGH, CRITICAL
- `AssetType(StrEnum)` — WEB_SITE, WEB_APP, SERVER, EMAIL, CODE, NETWORK
- `AssetStatus(StrEnum)` — ACTIVE, INACTIVE, SUPPRESSED, SCANNING, ERROR, ARCHIVED
- `AlertLevel(StrEnum)` — INFO, WARNING, CRITICAL
- `Severity(StrEnum)` — INFO, LOW, MEDIUM, HIGH, CRITICAL
- `EventType(StrEnum)` — tous les types d'événements du système
- `ScanType(StrEnum)` — PORT_SCAN, WEB_AUDIT, VULN_SCAN, THREAT_INTEL, etc.
- `SimulationStatus(StrEnum)` — PENDING_APPROVAL, APPROVED, RUNNING, COMPLETED, etc.
- `FixStatus(StrEnum)` — PROPOSED, TESTING, READY, APPLIED, FAILED, etc.
- `AssetItem(BaseModel)` — modèle de base commun à tous les assets

**Règles :**
- `__lt__` sur AssetItem pour la PriorityQueue (priorité d'abord, timestamp ensuite)
- `datetime.now(timezone.utc)` — pas `datetime.utcnow()` (déprécié 3.12)

---

### `assets/asset_classes.py` ❌ à faire
Classes Pydantic spécialisées par type d'asset. Chacune hérite de `AssetItem`.

**Contenu :**

```
WebAsset(AssetItem)
├── type: AssetType = WEB_SITE | WEB_APP
├── url: str
└── allowed_domains: list[str]

ServerAsset(AssetItem)
├── type: AssetType = SERVER
├── ip: str
├── port_range: str = "1-65535"
└── ssh_port: int = 22

EmailAsset(AssetItem)
├── type: AssetType = EMAIL
├── domain: str
└── smtp_server: str | None

NetworkAsset(AssetItem)
├── type: AssetType = NETWORK
└── cidr: str               # ex: "192.168.1.0/24"

CodeAsset(AssetItem)
├── type: AssetType = CODE
├── repo_url: str
└── branch: str = "main"
```

**Pourquoi des classes séparées ?**
Validation Pydantic stricte par type. Un WebAsset sans URL est invalide dès la création.
Les workflows reçoivent un type précis — pas de `metadata["url"]` magique.

---

## Couche 2 — Workflows

### `assets/workflows/workflow_base.py` ✅ fait
Interface abstraite commune à tous les workflows.

```python
class WorkflowBase(ABC):
    async def run_async(self, *args, **kwargs): ...
    def run(self, *args, **kwargs): ...
```

---

### `assets/workflows/web_workflow.py` 🔄 en cours
Workflow pour les assets de type WEB_SITE et WEB_APP.

**Responsabilité :**
Recevoir un WebAsset, orchestrer le scan web, générer le rapport.

**Flow :**
```
WebAsset reçu
    ↓
Scanner initialisé (config depuis asset + config dict)
    ↓
scan() → appelle Scanner.scan()
    ↓
ScannerResult retourné
    ↓
report() → traite et retourne le résultat
```

**Interface :**
```python
class WebWorkflow(WorkflowBase):
    def __init__(self, asset: WebAsset, config: dict)
    async def scan(self, scan_attrs: dict | None) -> ScannerResult
    async def report(self, result: ScannerResult | None) -> ScannerResult
    async def run_async(self, scan_attrs: dict | None)
    def run(self, scan_attrs: dict | None)
```

---

### `assets/workflows/server_workflow.py` ❌ à faire
Workflow pour les assets de type SERVER.

**Flow :**
```
ServerAsset reçu
    ↓
Port scan (tous les ports)
    ↓
Banner grabbing → identification services
    ↓
CVE matching sur les services détectés
    ↓
Si vulns critiques → demande simulation (validation admin requise)
    ↓
Rapport
```

---

### `assets/workflows/email_workflow.py` ❌ à faire
Workflow pour les assets de type EMAIL.

**Flow :**
```
EmailAsset reçu
    ↓
Check SPF / DKIM / DMARC
    ↓
Réputation domaine mail
    ↓
Activation mail proxy (si configuré)
    ↓
Anti-phishing actif sur les flux
    ↓
Rapport
```

---

### `assets/workflows/network_workflow.py` ❌ à faire
Workflow pour les assets de type NETWORK.

**Flow :**
```
NetworkAsset reçu (plage CIDR)
    ↓
Scan de toute la plage IP
    ↓
Cartographie des hôtes actifs
    ↓
Détection services exposés
    ↓
IDS/IPS activé sur le trafic
    ↓
Rapport
```

---

### `assets/workflows/code_workflow.py` ❌ à faire
Workflow pour les assets de type CODE.

**Flow :**
```
CodeAsset reçu
    ↓
Clone du repo
    ↓
Analyse statique
    ↓
Sandbox (exécution isolée si nécessaire)
    ↓
Rapport
```

---

## Couche 3 — Managers

### `core/workflow_manager.py` ❌ à faire
**Responsabilité unique :** recevoir un asset, choisir le bon workflow, l'exécuter dans la queue.

```
WorkflowManager
├── _queue: asyncio.PriorityQueue
├── _workers: list[asyncio.Task]
├── add(asset) → instancie le bon workflow, met en queue
├── _worker() → consomme la queue en continu, exécute les workflows
├── start(n_workers) → démarre n workers
└── stop() → vide la queue, annule les workers proprement
```

**Logique de routing :**
```python
AssetType.WEB_SITE  → WebWorkflow
AssetType.WEB_APP   → WebWorkflow
AssetType.SERVER    → ServerWorkflow
AssetType.EMAIL     → EmailWorkflow
AssetType.NETWORK   → NetworkWorkflow
AssetType.CODE      → CodeWorkflow
```

**Priorité d'exécution :**
Les assets CRITICAL passent avant les LOW.
À priorité égale, le plus ancien passe en premier (timestamp monotonic).

---

### `core/task_manager.py` ❌ à faire
**Responsabilité unique :** gérer les tâches asyncio longues (scan, simulation, etc).

```
TaskManager
├── _tasks: dict[str, asyncio.Task]
├── add_task(coro, task_id) → crée et enregistre la task
├── cancel_task(task_id) → annule proprement
├── get_status(task_id) → pending | running | done | cancelled | failed
├── list_tasks() → toutes les tasks actives
└── cleanup() → retire les tasks terminées
```

---

### `core/asset_manager.py` ❌ à faire
**Responsabilité unique :** CRUD des assets + déclenchement automatique.

```
AssetManager
├── _assets: dict[str, AssetItem]      # stockage en mémoire pour le MVP
├── _workflow_manager: WorkflowManager
├── add(asset) → valide + stocke + déclenche WorkflowManager.add()
├── get(asset_id) → AssetItem
├── list(type, status) → list[AssetItem]
├── update(asset_id, data) → met à jour + re-déclenche si nécessaire
└── remove(asset_id) → passe status à ARCHIVED
```

**Le moment clé :**
```python
async def add(self, asset):
    self._assets[asset.id] = asset
    await self._workflow_manager.add(asset)  # tout se déclenche ici
```

---

### `core/alert_manager.py` ❌ à faire
**Responsabilité unique :** créer, grouper, envoyer les alertes. Anti-spam intégré.

```
AlertManager
├── _alerts: list[Alert]
├── create(level, title, description, asset_id)
├── acknowledge(alert_id)
├── resolve(alert_id)
├── list(asset_id, level, resolved)
└── _should_group(alert) → évite le spam d'alertes similaires
```

**Niveaux :**
```
INFO     → log silencieux uniquement
WARNING  → stocké + visible dashboard
CRITICAL → stocké + notification immédiate admin
```

---

## Couche 4 — Event Bus

### `core/event_bus.py` ❌ à faire
**Pour le MVP :** `asyncio.Queue` simple avec interface propre.
**En prod :** Redis Pub/Sub — on switche sans toucher au reste.

```
EventBus
├── _subscribers: dict[EventType, list[callable]]
├── publish(event: Event) → envoie à tous les subscribers
├── subscribe(event_type, handler) → enregistre un handler
├── subscribe_all(handler) → reçoit tous les events (pour AegisCore)
└── start() / stop()
```

### `core/events.py` ❌ à faire
Modèles des events qui circulent sur le bus.

```python
class Event(BaseModel):
    id: str                     # UUID
    type: EventType
    asset_id: str
    source: str                 # quel composant a publié
    payload: dict               # données de l'event
    timestamp: datetime
    correlation_id: str | None  # pour grouper des events liés
```

---

## Couche 5 — Agents IA

### `core/agents/aegis_analyst.py` ❌ à faire
**Responsabilité :** interpréter les résultats bruts des modules, expliquer les vulnérabilités, proposer des fixes.

- Reçoit un `ScannerResult` ou résultat brut d'un module
- Appelle le LLM (Groq en dev, Anthropic en prod)
- Retourne une analyse structurée + fix proposé
- Ne prend jamais de décisions — il analyse seulement

---

### `core/agents/aegis_core.py` ❌ à faire
**Responsabilité :** écouter tous les events, corréler, décider, mettre à jour le risk score, créer les alertes.

- S'abonne à tous les events via `event_bus.subscribe_all()`
- Corrèle les events d'un même asset
- Met à jour le risk score selon les events reçus
- Crée les alertes via AlertManager
- Demande des simulations si nécessaire (avec validation admin)

---

### `core/agents/aegis_red.py` ❌ à faire
**Responsabilité :** piloter les simulations d'attaque.

- Vit exclusivement dans la sandbox Docker
- N'a aucun accès aux assets réels
- Reçoit un asset cloné + type de simulation
- Adapte sa stratégie selon ce qu'il découvre
- Retourne un rapport de résistance

---

## Couche 6 — API Gateway

### `api/main.py` ❌ à faire

**Routes principales :**
```
POST   /assets                    → ajouter un asset
GET    /assets                    → lister les assets
GET    /assets/{id}               → détail asset + risk score
DELETE /assets/{id}               → archiver un asset
GET    /assets/{id}/vulns         → vulnérabilités détectées
GET    /assets/{id}/alerts        → alertes de l'asset
GET    /alerts                    → toutes les alertes
POST   /simulations/{id}/approve  → admin valide une simulation
POST   /simulations/{id}/reject   → admin refuse une simulation
POST   /fixes/{id}/approve        → admin valide un fix
GET    /tasks                     → tâches en cours
WS     /ws                        → dashboard temps réel
```

---

## Couche 7 — Dashboard + Ecosystem

### Dashboard React ❌ à faire (après API)
Interface admin temps réel. WebSocket pour les updates live.
- Vue globale : liste des assets + risk scores
- Vue asset : détail, vulns, alertes, historique
- Centre de validation : simulations et fixes en attente
- Logs et audit trail

### Browser Extension ❌ à faire
Chrome + Firefox. Manifest V3.
- Intercepte chaque URL avant le clic
- Appelle l'API anti-phishing ShieldAI
- Bloque / avertit / autorise
- Remonte les events au dashboard

### Mail Proxy ❌ à faire
SMTP/IMAP. Python avec `aiosmtpd`.
- Intercepte les mails entrants avant livraison
- Anti-phishing + TrustSignal + ContextGuard
- Bloque ou délivre selon le score
- Alerte l'admin si suspect

---

## Ordre de développement

```
✅ ÉTAPE 1  assets/types.py + asset_classes.py
🔄 ÉTAPE 2  assets/workflows/web_workflow.py    ← on est ici
❌ ÉTAPE 3  core/workflow_manager.py
❌ ÉTAPE 4  core/task_manager.py
❌ ÉTAPE 5  core/asset_manager.py
❌ ÉTAPE 6  core/event_bus.py + core/events.py
❌ ÉTAPE 7  core/alert_manager.py
❌ ÉTAPE 8  core/agents/aegis_analyst.py
❌ ÉTAPE 9  core/agents/aegis_core.py
❌ ÉTAPE 10 core/agents/aegis_red.py
❌ ÉTAPE 11 api/main.py
❌ ÉTAPE 12 dashboard React
❌ ÉTAPE 13 browser extension + mail proxy
```

---

## Règles du projet

- Benny code, Claude review
- On ne passe pas à l'étape suivante si l'étape courante ne tourne pas
- Pas de Redis, pas de DB avant que les workflows tournent
- Chaque composant a une responsabilité unique
- Toute simulation requiert validation admin explicite — sans exception
- AegisRed n'a aucun accès aux assets réels — sans exception

---

*ShieldAI — Built from Africa. Built for the world.*
