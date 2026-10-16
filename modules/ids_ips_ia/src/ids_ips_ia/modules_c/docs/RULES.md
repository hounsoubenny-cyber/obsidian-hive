# Les règles de détection (`rules.c`)

Une règle est une petite fonction qui **lit un flux** et rend un `FlowRuleResult { verdict, reason }`.
Elle ne bloque rien elle-même : c'est la table de flux qui agit (`_after_packet`, dans `flow_table.c`).
Elle tourne **après chaque paquet**, donc elle voit un flux dès son premier paquet.

## Les verdicts

| Verdict | Effet |
|---|---|
| `UNKNOW` | pas d'avis, le verdict du flux ne change pas |
| `BLOCK` | l'IP initiatrice est bloquée, le flux est envoyé puis retiré |
| `LIMIT_REACHED` | le flux est seulement marqué, l'IP n'est pas bloquée |

`reason` dit **quelle règle** a décidé (`FlowRuleReason`, stocké dans `FlowData.rule_reason`).
Ne pas confondre avec `FlowEndReason` (`reason` du record), qui dit **pourquoi le flux quitte la table**.
Un flux bloqué par un scan Xmas part avec `reason = END_BLOCKED` ET `rule_reason = RULE_XMAS_SCAN`.

## Les drapeaux TCP (flags)

Chaque paquet TCP porte des drapeaux, comme des étiquettes :

| Flag | Sens |
|---|---|
| `SYN` | « on peut parler ? » (début de connexion) |
| `ACK` | « bien reçu » (présent presque partout ensuite) |
| `FIN` | « je ferme » (toujours accompagné d'un ACK) |
| `RST` | « non / coupe tout » |
| `PSH` | « envoie les données tout de suite » |
| `URG` | « donnée urgente » |

Une vraie connexion suit une logique : `SYN` → `SYN+ACK` → `ACK` → échanges `ACK` / `PSH+ACK` → `FIN+ACK` des deux côtés.
Les scans « furtifs » envoient des combinaisons **qui n'existent pas** dans une vraie conversation.
Selon la norme TCP, un port fermé répond `RST` et un port ouvert se tait : le silence révèle les ports ouverts.

> Dans un flux, les compteurs (`flag_count`) cumulent les paquets **des deux sens**.
> La règle tourne après chaque paquet : elle voit donc le premier paquet seul, avant la réponse (RST) de la cible.

## Les 5 règles

| Règle | Détecte | Verdict | Seuil par défaut |
|---|---|---|---|
| `port_scan` | une IP visite beaucoup de **ports distincts** | `BLOCK` | 20 ports |
| `null_scan` | paquet TCP **sans aucun drapeau** | `BLOCK` | aucun (1 paquet suffit) |
| `xmas_scan` | `FIN+PSH+URG` allumés (« sapin de Noël »), jamais de `SYN`/`ACK`/`RST` | `BLOCK` | aucun |
| `fin_scan` | `FIN` **tout seul**, sans `ACK` | `BLOCK` | aucun |
| `flood` | trop de paquets/s de l'initiateur (UDP, ICMP, ICMPv6) | `LIMIT_REACHED` | 10 000 paquets/s |

- `port_scan` : la `PortMap` de l'IP initiatrice (bitmap de 65 536 bits) compte les ports de destination distincts. Elle vit tant que l'IP a au moins un flux (`refcount`).
- `flood` : débit mesuré sur **100 ms au minimum** (`FLOOD_MIN_WINDOW_MS`), pour qu'une courte rafale ne compte pas.
- `rules_check_all` lance toutes les règles actives. Un `BLOCK` l'emporte, sinon le premier `LIMIT_REACHED`.

## Que se passe-t-il sur un `BLOCK` ?

1. Le verdict et `rule_reason` sont écrits dans le flux.
2. L'IP initiatrice entre dans la liste noire (`ft_block_ip`).
3. Sa `PortMap` est remise à zéro (`portmap_reset`) : si l'admin la débloque, elle repart de 0 au lieu d'être re-bloquée au paquet suivant.
4. Le flux est envoyé au sink avec `END_BLOCKED`, puis retiré (`_ft_remove`).
5. Ensuite, tout paquet dont la **source ou la destination** est bloquée est ignoré (les réponses de la victime ne fabriquent pas de faux flux).

## Réglages à chaud

Chaque règle a un `enabled` et un seuil, **atomiques**, partagés par toutes les captures. Le changement vaut dès le paquet suivant.

```c
engine_rules_set_enabled(e, RULE_PORT_SCAN, 0);
engine_rules_set_threshold(e, RULE_PORT_SCAN, 50);
```
```python
eng.rules_set("port_scan", threshold=50)
eng.rules_set("xmas_scan", enabled=False)
eng.rules_get()          # {nom: {"enabled": bool, "threshold": int | None}}
```

Désactiver une règle ne débloque pas les IP qu'elle a déjà bloquées.

## Limites à connaître

- **Spoofing** : un seul paquet suffit pour bloquer. Quelqu'un peut forger l'adresse source d'une IP légitime pour la faire bloquer. Les listes « ignorer » (`ign_src` / `ign_dst`) passent **avant** les règles : elles servent de liste blanche (passerelle, DNS...).
- Les seuils par défaut sont des estimations : à régler sur le trafic réel.
- La liste noire est encore un `Dict` interne à la table : Python ne peut pas la lire ni la modifier.

## Ajouter une règle

1. Ajouter une valeur à `FlowRuleReason` (`flow.h`), **avant** `RULE_COUNT`.
2. Écrire `FlowRuleResult rule_xxx(data, ports, cfg)` dans `rules.c` (commencer par tester `_enabled`).
3. L'ajouter au tableau `RULES` (`rules_check_all`), à `NAMES`, et à `rules_config_default`.
4. Côté Cython : l'ajouter à `RULE_IDS` et `RULE_NAMES`.
5. Écrire ses tests dans `test_rules.c`.
