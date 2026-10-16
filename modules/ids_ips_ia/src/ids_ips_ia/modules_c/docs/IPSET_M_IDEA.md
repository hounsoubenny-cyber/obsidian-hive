# Blocklist partagée redimensionnable

*Comment une liste noire d'IP, partagée entre toutes les threads de capture et Python, peut grandir sans jamais faire attendre un lecteur.*

---

## 1. Le point de départ

Chaque `FlowTable` (une par thread de capture) possède sa liste noire : un `Dict` local, **non thread-safe**, rempli par les règles. Deux problèmes :

- **Python ne peut pas y toucher** pendant que la capture tourne : la thread lit le dict à chaque paquet (source ET destination). Écrire depuis Python pendant cette lecture, c'est une course de données (chaînage `next` non atomique, `free()` possible en pleine traversée).
- **Un blocage est local à une interface** : bloquer sur `eth0` ne fait rien sur `wlan0`.

Il fallait donc : **une seule liste noire, partagée par toutes les threads de capture et par Python** — c'est la *struct mère*. Et comme une liste noire doit pouvoir grandir : **un redimensionnement sans arrêter la capture**.

---

## 2. L'idée (celle de Benny) 👇

> Un set de taille fixe, c'est un jour un mur. Alors : quand il se remplit, on en crée un autre plus grand, on y met les anciens éléments, et on **remplace le pointeur avec des atomiques**. Puis `free` sur l'ancien.
> Pour savoir si l'ancien peut être libéré : chaque set a un **compteur d'usage**, la mère garde les sets **retired**, et à chaque `add` on balaye : les retired dont le compteur est à 0, on les libère.

Ce design contient déjà tout l'essentiel, et il est **correct dans son architecture** :

| Élément de l'idée | Pourquoi c'est bon |
|---|---|
| **La struct mère** (elle tient `actuel` + `retired`) | C'est elle qu'on partage entre threads ; les sets ne se connaissent pas entre eux |
| **Le pointeur atomique** pour changer de set | Un seul `store` : chaque lecteur voit soit l'ancien set, soit le nouveau — jamais un mélange |
| **La construction du nouveau set avant la bascule** | Le nouveau est complet et cohérent avant d'être publié |
| **Le balayage paresseux** (sweep au `add` suivant) | L'écrivain n'attend jamais les lecteurs : il nettoie au coup d'écriture suivant |
| **Un mutex d'écriture** (les écrivains se sérialisent) | Un seul écrivain à la fois : pas de resize concurrent, pas de coordination écrivain-écrivain |

Et la solution au « `free` sur l'ancien, ça peut poser des soucis ? » était la bonne question à se poser. Parce que oui : **le `free` est le seul vrai danger du design**. Deux pièges, dont un invisible.

---

## 3. Le piège visible : la vue déchirée

Le lecteur fait deux lectures : `_hash(...) & s->mask`, puis `cells[i]`. Si le mask et les cells sont publiés **séparément**, un lecteur peut prendre l'ancien `mask` avec les nouvelles `cells` — mauvaise case, index hors bornes, ou pire pour un IDS : un **faux négatif** (« pas bloquée » alors qu'elle l'est). Fail-open, interdit par la philosophie du projet.

**Correction** : mask et cases voyagent **ensemble** dans un descripteur immuable (`struct IpTable`), et le lecteur ne fait qu'**UN** chargement atomique — celui de `current`. Toute sa lecture est cohérente par construction.

---

## 4. Le piège invisible : la course du compteur 💥

C'est le cœur du sujet. Version naïve du protocole lecteur :

```
R : t = load(current)          ← le lecteur reçoit l'ancien set
R : inc(t->readers)            ← il signe « je lis t »
R : recherche dans t
R : dec(t->readers)
```

Et l'écrivain, à son balayage : *« retired dont le compteur vaut 0 → free »*.

La course, minute par minute :

1. Le lecteur charge `current` → il tient l'ancien set.
2. Il s'apprête à incrémenter le compteur… **le scheduler le préempte.** (Rien d'exotique : une thread mise de côté quelques millisecondes, ça arrive des milliers de fois par seconde.)
3. L'écrivain bascule `current` vers le nouveau set, et met l'ancien dans `retired`.
4. Au `add` suivant, il balaye et lit le compteur de l'ancien : **il lit 0 — et c'est vrai**. Le lecteur n'a pas encore signé. Il `free` l'ancien set. *L'écrivain n'a fait aucune erreur.*
5. Le lecteur se réveille et fait `inc(t->readers)`… **dans de la mémoire libérée.** 💀

Le point crucial : **aucune opération n'est fausse** dans cette timeline. Pas de lecture déchirée, pas de réordonnancement, pas de valeur invisible. `seq_cst`, `alignas(64)` sur le compteur — tout est respecté. Le problème est ailleurs :

> **Le compteur vit dans l'objet qu'on veut libérer.** Le lecteur doit incrémenter le compteur de `t`… ce qui suppose d'avoir déjà chargé `t`… et entre « charger le pointeur » et « signer le compteur », le lecteur est **invisible**. Or charger et signer sont deux instructions sur deux adresses : **aucune atomicité ne peut les fusionner** (le modèle mémoire C n'a même pas de notion de « libéré »).

« Vérifier si `t` est free avant de l'utiliser » n'existe pas : `free()` ne marque rien, le drapeau serait dans l'objet mort, et le check-then-use recrée le même trou décalé d'une instruction.

---

## 5. La correction : le signe de vie déménage chez le lecteur 📒

L'idée de Benny est conservée **dans son intégralité** — une seule chose bouge : **l'endroit où le lecteur signe qu'il lit**.

| | Version compteur | Version corrigée (hazard pointer) |
|---|---|---|
| Le lecteur signe… | dans le set (`t->readers`) | **dans son propre slot** (`slots[numero]`) |
| Ce « registre » peut-il être libéré par l'écrivain ? | oui (c'est la course) | **non** : le slot appartient au thread, jamais à l'objet |
| Le balayage paresseux | inchangé | inchangé : *« retired dont l'adresse apparaît dans un slot → on garde ; sinon → free »* |
| Le mutex d'écriture | inchangé | inchangé |

Le protocole lecteur devient :

```
R : t = load(current)        ← 1. prendre la table courante
R : slots[moi] = t           ← 2. la réclamer DANS SON PROPRE slot (sa ligne de cache, jamais libérée)
R : re-load(current)         ← 3. revalider : si current a changé, RETRY (retour à 1)
R : recherche dans t         ← 4. lecture sans verrou
R : slots[moi] = NULL        ← 5. rendre la main
```

**Pourquoi c'est sûr — le raisonnement complet** (deux cas, pas de troisième) :

- **Le balayage VOIT mon slot** → il ne libère pas `t`. Je lis tranquille. ✔
- **Le balayage ne voit pas mon slot** → son scan s'est fait avant mon écriture… donc la bascule aussi… donc à mon étape 3, `current` a déjà changé → **je retry sans avoir touché `t`**. ✔

Le retry, c'est exactement l'idée de Benny du « code de retour pour réessayer » — elle devient la boucle de revalidation.

Détail de coût : le slot du lecteur est aligné sur **64 octets** (`alignas(64)`) — le lecteur écrit dans sa propre ligne de cache, il ne fait rebondir celle d'aucune autre thread. Un léger surcoût par recherche (un store local + un load de revalidation) contre **zéro attente, zéro verrou** sur le chemin chaud.

---

## 6. Les slots : numéros fixes, pas de plomberie

Chaque thread de lecture a **un numéro**, pris à l'inscription (`ipset_m_register`) :

- **Les threads de capture** : numéro fixe pris à la naissance (dans `engine_start`) — elles vivent aussi longtemps que l'engine.
- **Les threads Python** : tant que le GIL est tenu pendant toute la lecture (pas de `nogil` entre hold et release), deux threads Python ne peuvent pas être dans le protocole en même temps → **elles partagent un seul slot**.
- Le tableau est statique (32 slots), sous le mutex d'écriture pour l'attribution — pas de TLS, pas d'allocation à chaud.

Cas limite assumé : si `malloc` recycle l'adresse d'un retired pour un nouveau set, un slot peut contenir une adresse « morte ET vivante » à la fois → le balayage **retarde** d'un tour la libération. C'est toujours dans le sens sûr : jamais un free prématuré, au pire un free paresseux.

---

## 7. Le design final

```
                    ┌────────────────────── IpSetMother ──────────────────────┐
                    │  current : _Atomic(struct IpTable *)   ← LA bascule      │
                    │  slots[32] : alignas(64), un par thread de lecture      │
                    │  retired[] : les vielles tables, pas encore libérées     │
                    │  lock (mutex) : écritures + inscription des lecteurs    │
                    �───────────────┬─────────────────────────────┬────────────┘
                                    │ publie                      │ sweep au add suivant :
                    ┌───────────────▼──────────┐   libère si    │ aucun slot ne la réclame
                    │        IpTable            │   réclamée …   ▼
                    │  cells[]  mask  (immuables après publication)  [free]
                    │  fiches IpEntry : immuables, publiées en release
                    │  TOMB + fiches retirées (libérées avec la table)
                    └──────────────────────────┘
```

- **Le lecteur** (chemin chaud, chaque paquet, `nogil`) : hold → lookup → release. Sans verrou, sans attente, jamais dans une mémoire libérée.
- **L'écrivain** (règles dans `_after_packet`, ou Python via `engine_block_*`) : sous le mutex, resize par doublement si besoin (les fiches sont **redéposées par pointeur** — aucun malloc de fiche), bascule en un `store`, sweep paresseux au coup suivant.
- **Une seule liste** pour tout le monde : les règles et Python bloquent dans la même mère → visible par toutes les captures au paquet suivant.

## 8. Ce qui a été livré

| Fichier | Contenu |
|---|---|
| `ipset_m.h` | L'API : création, inscription des lecteurs, protocole hold/lookup/release, add/remove/count |
| `ipset_m.c` | L'implémentation : table immuable, slots alignés, resize, sweep paresseux |
| `test_ipset_m.c` | 6 tests : basiques, resize forcé, **la course mise en scène** (lecteur hold pendant un resize → la table n'est pas libérée, la lecture finit sans crash), libération au dernier lecteur, saturation des slots, 4 écrivains + 4 lecteurs à chaud |

Le test n°3 est la preuve : *un lecteur tient la vieille table, l'écrivain déclenche 200 ajouts et plusieurs resizes, le sweep passe à chaque fois — la table est toujours là, et `ipset_m_lookup(t, ...)` rend la bonne réponse.* Sans le slot, cette ligne serait un use-after-free.

---

## 9. L'étape d'après

1. Remplacer le `Dict *blocked` de chaque `FlowTable` par la mère (prêtée via un `ft_create_shared`, comme les listes d'IP à ignorer de l'engine).
2. Exposer `engine_block_add/remove/contains/count` — sans le verrou de l'engine : la mère se protège seule.
3. Les méthodes Python : `eng.block()`, `eng.unblock()`, `eng.is_blocked()`, `eng.blocked_count()`.
4. Donner son numéro de slot à chaque thread de capture à `engine_start` ; les threads Python partagent le slot GIL.

---

*Résumé en une phrase : l'idée de Benny — mère + pointeur atomique + balayage paresseux — était la bonne architecture ; la seule correction nécessaire fut de déplacer le signe de vie du lecteur depuis l'objet (un compteur, qui peut mourir) vers sa propre mémoire (un slot, que l'écrivain ne peut jamais libérer).*
