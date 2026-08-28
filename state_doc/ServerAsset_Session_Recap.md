# ServerAsset — Récap de session : de la conception au déploiement réel

**Contexte :** cette session part du document de décisions déjà écrit (`ServerAsset_Agent_Decisions.md`, design pur, rien codé) et couvre toute l'implémentation du cœur de l'agent, jusqu'à un test réel réussi sur VM avec install → register → tool calls → self-destruct.

---

## 1. Le cœur de l'agent (`core_agent/`)

Quatre fichiers, structure finale :

- **`config.py`** — `AgentConfig` (Pydantic). Charge/persiste un `config.toml` local, écriture atomique (fichier temp + `os.replace`), permissions `600`. Chemin configurable via `OBSIDIAN_AGENT_CONFIG_PATH` (défaut `/opt/obsidian-agent/config.toml`). Le secret est chargé **une fois** au démarrage et gardé en mémoire — jamais relu à chaque usage (coût inutile, aucun gain de sécurité réel puisque le secret finit en RAM de toute façon).
- **`transport.py`** — `AgentHttpClient` (httpx + tenacity pour les retries réseau/5xx/429, jamais sur les 4xx) et `AgentWSClient` (lib `websockets`, boucle heartbeat avec détection d'ack manquant, reconnexion avec backoff exponentiel plafonné).
- **`dispatcher.py`** — `AgentDispatcher`, route chaque message WS entrant par `type` (dict de handlers, pas de chaîne de `if`).
- **`main.py`** — classe `Agent` : charge la config, s'enregistre si `pending_token` présent, instancie WS/dispatcher, lance `run_forever()`.

---

## 2. Design de sécurité retenu

- **Secret/token toujours en header `Authorization: Bearer`**, jamais en query string (logs de reverse proxy) — appliqué uniformément : REST, WebSocket (via `additional_headers`, possible car client Python pur, pas de restriction navigateur), et les scripts bash générés (`curl -H "Authorization: Bearer ..."`).
- **Pré-hash SHA-256 avant bcrypt** (`ServerAsset.hash_secret_input`) — bcrypt tronque/rejette au-delà de 72 octets ; le digest fixe de 32 octets contourne la limite sans jamais avoir à raccourcir le secret lui-même.
- **Auto-destruction sans agent root** : un script `uninstall.sh` dédié, exécutable via une règle `sudo` **restreinte à ce seul script** (`NOPASSWD` scopé), pas un agent qui tourne en root.
- **Fail-closed sur `allowed_tools`** : liste vide par défaut, l'admin autorise chaque tool un par un.
- **Deux niveaux de risque par tool** : LOW (pas de confirmation) vs MEDIUM/HIGH (confirmation humaine obligatoire, même mécanisme `WSConfirmer` que Coralie).

---

## 3. Bugs trouvés et corrigés (dans l'ordre où ils sont apparus)

| # | Bug | Fix |
|---|---|---|
| 1 | `_register()` : condition inversée (succès traité comme échec, erreur crash sur `KeyError`) | Condition réécrite dans le bon sens |
| 2 | `AgentHttpClient.__init__` exigeait `install_token` même sans register — crash à chaque redémarrage normal | `install_token` rendu optionnel |
| 3 | Secret jamais posé sur `http_client` après register — 401 sur le download suivant | Ajout de `http_client.set_secret(secret)` |
| 4 | `download_file` : `await` manquant, retournait une coroutine non exécutée | `return await self._download_file(...)` |
| 5 | `_download_tool_engine` retournait tantôt un `bool`, tantôt un `dict` | Toujours un dict avec `success` |
| 6 | `tool_call` (objet Pydantic) passé brut à `json.dumps` | `.model_dump(mode="json")` |
| 7 | `normalize_asset_item` : `json.dumps` plantait sur des `datetime` dans les champs `extra` | `default=` avec `isoformat()` pour `datetime`, `raise` sinon |
| 8 | `generate_secret()` utilisait 64 bytes (~86 caractères) → dépassait la limite bcrypt (72 octets) | Retour à 32 bytes + pré-hash SHA-256 (fix définitif, indépendant de la taille) |
| 9 | Connexion WS agent → 403 : `asset_id` manquant dans l'URL de test | Ajouté, puis déplacé proprement dans `Agent.init_classes()` plutôt que codé en dur dans le script de test |
| 10 | Typo `config_updated` (émis) vs `config_update` (écouté) — sync jamais reçue | Aligné sur `config_update` |
| 11 | `allowed_tools`/`capabilities` jamais transmis dans la réponse `/register` — agent pensait tout interdit | Ajoutés à la réponse + sync systématique à la connexion (pas seulement sur push ponctuel) |
| 12 | `uninstall.sh` ne finissait jamais (fichiers/user jamais supprimés) | `KillMode=control-group` (défaut systemd) tuait tout le cgroup dès la sortie du process principal → `KillMode=process` |
| 13 | `StartLimitIntervalSec`/`StartLimitBurst` dans la mauvaise section du unit file | Déplacés de `[Service]` vers `[Unit]` |
| 14 | Emojis dans les `echo` du script bash + locale absente → plantage | `export LANG=C.UTF-8` / `LC_ALL=C.UTF-8` en tête de script + dans le service |
| 15 | Conflit `libgcc_s` au runtime du binaire Nuitka (version glibc système différente) | `--noinclude-dlls="libgcc_s*"` à la compilation |

---

## 4. Tools ServerAsset — état complet

**Déjà là avant cette session :** `get_system_info`, `check_service_status`, `read_file`.

**9 ajoutés cette session** (tous en lecture seule, allowlist stricte via `safe_run`/`SERVER_ALLOWED_COMMANDS`) :

| Tool | Risque | Confirmation |
|---|---|---|
| `list_directory` | LOW | Non |
| `disk_usage` | LOW | Non |
| `list_processes` | MEDIUM | Oui (args de commande potentiellement sensibles) |
| `search_in_file` | MEDIUM | Oui (accès contenu arbitraire) |
| `check_open_ports` | LOW | Non |
| `list_logged_in_users` | LOW | Non |
| `last_logins` | LOW | Non |
| `network_interfaces` | LOW | Non |
| `list_block_devices` | LOW | Non |

Nouveaux binaires autorisés dans `allow_commands.py` : `ss`, `who`, `last`, `lsblk`, `ip` (restreint aux sous-commandes `addr`/`route`/`link` — `ip netns exec` équivaudrait à un shell arbitraire sinon).

---

## 5. Scripts bash

- **`install.sh`** — servi par `/api/download/agent/install.sh` (token en header, non consommé). Crée l'utilisateur dédié, télécharge le binaire agent, écrit `config.toml`, écrit `uninstall.sh` en heredoc, pose la règle sudoers restreinte, écrit et démarre le service systemd.
- **`reregister.sh`** — servi par `/api/download/agent/reregister.sh`, pour réactiver un agent révoqué (régénère un `install_token`, pas de vrai "dé-revoke"). Ne touche que le token en config + `systemctl restart`.
- **`uninstall.sh`** — écrit par `install.sh`, jamais servi en HTTP séparément. Déclenché à distance par le message WS `self_destruct`.

Route de téléchargement du binaire (`agent_core`) et du `tool_engine` : même principe, token/secret en header, jamais en query string.

---

## 6. Tests réalisés

1. **Script Python interactif e2e** (`test_agent_e2e.py`) — crée un asset de test, lance l'agent comme process séparé, boucle interactive pour taper des tool calls à la volée. A servi à tout valider avant le vrai déploiement.
2. **Test réel sur VM Kali** — `install.sh` exécuté pour de vrai via `curl | bash`, service systemd réel créé, tools testés en conditions réelles (`disk_usage`, `list_logged_in_users`), puis suppression de l'asset côté central → self-destruct → nettoyage complet vérifié (service, dossier, utilisateur système, tous supprimés).

**Résultat : flow complet validé de bout en bout.** ✅

---

## 7. Prochaines étapes identifiées

- Encore plus de tools ServerAsset
- Binariser IDS/IPS et Simulateur (capabilities lourdes), + route de téléchargement à la demande, + gestion des événements associés
- Retour aux autres modules du MVP :
  - **Scanner** — ML encore fake, données d'entraînement manquantes, ré-audit détection/scoring à faire
  - **Sandbox** — même situation (ML pas prêt, données manquantes)
  - **Deepfake (TrustSignal)** — bloqué par la puissance machine ; plan : Colab, mais upload de données lourd à prévoir
  - **ContextGuard** — modèle à améliorer, intégration SDK à simplifier pour Coralie/Alex

---

## Ce que cette session démontre

Un flow production-grade complet : provisioning à distance sécurisé (token à usage unique), authentification agent↔central robuste (secret + hash, pré-hashé), exécution de commandes encadrée (allowlist stricte, fail-closed), et démantèlement propre et automatisé (auto-destruction sans privilèges excessifs). Testé et validé sur une vraie machine, pas seulement en local.
