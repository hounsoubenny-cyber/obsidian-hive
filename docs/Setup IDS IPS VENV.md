# Setup venv dédié — `ids_ips_venv`

Guide pour recréer un venv Python avec un interpréteur **copié** (pas symlink), qui **partage les packages** de `pyglobal0` sans les dupliquer, et qui peut recevoir des **capabilities Linux** (`CAP_NET_ADMIN`) pour éviter `sudo` sur les commandes nftables.

## Pourquoi ce setup ?

- `setcap` sur un binaire ne fonctionne que sur un **vrai fichier**, pas sur un symlink (`setcap` s'applique aux attributs étendus du fichier lui-même).
- Le module `reaction` (IDS/IPS) utilise `python-nftables` pour parler à nftables **directement depuis le process Python** (in-process, via Netlink), sans passer par `sudo nft ...` à chaque commande — d'où le besoin de `CAP_NET_ADMIN` sur l'interpréteur Python exact qui exécute ce code.
- On garde un venv séparé pour ce module (isolation, capability dédiée) sans dupliquer 10-20 Go de `site-packages` déjà présents dans `pyglobal0`.

## Étape 1 — Créer le venv avec un interpréteur copié

```bash
/usr/bin/python3.11 -m venv --copies ~/ids_ips_venv
```

- `--copies` force une copie physique du binaire Python (au lieu du symlink par défaut sous Linux).
- Peu importe que la source (`/usr/bin/python3.11` ou `pyglobal0/bin/python3.11`) soit elle-même un symlink : `venv --copies` utilise `shutil.copyfile()` en interne, qui **suit** les symlinks et copie le contenu réel du fichier cible. Le résultat est identique dans les deux cas.

**Vérifier que c'est bien une copie et pas un symlink :**
```bash
ls -la ~/ids_ips_venv/bin/python3.11
file ~/ids_ips_venv/bin/python3.11
```
→ Attendu : pas de `->` dans `ls -la`, et `file` doit dire `ELF 64-bit LSB pie executable...`

## Étape 2 — Partager les packages de `pyglobal0` sans les dupliquer

Créer un fichier `.pth` qui **exécute du code** (au lieu d'un simple chemin brut) :

```bash
echo "import site; site.addsitedir('/home/hounsousamuel/pyglobal0/lib/python3.11/site-packages')" > ~/ids_ips_venv/lib/python3.11/site-packages/_pyglobal0.pth
```

### Pourquoi `site.addsitedir()` et pas juste un chemin brut dans le `.pth` ?

- Un `.pth` classique (une ligne = un chemin) ajoute juste ce chemin à `sys.path`. Ça suffit pour des packages **normaux** (ex: `geoip2`), dont le code vit physiquement dans `site-packages`.
- Mais les packages installés en **mode éditable** (`pip install -e`, ex: `modules_utils`) ne vivent pas dans `site-packages` : pip y dépose un `.pth` spécial qui redirige vers le vrai dossier source ailleurs sur le disque. Ce `.pth` imbriqué n'est traité que si le dossier est ajouté via `site.addsitedir()` — pas via un chemin brut ajouté par un `.pth` externe.
- `site.addsitedir(chemin)` réplique le comportement d'un site-packages "principal" : elle **re-scanne** le dossier donné à la recherche de `.pth`, et donc suit correctement les redirections des installs éditables.

**Comportement du partage :**
- ✅ Lecture : tous les packages de `pyglobal0` (y compris les installs éditables) sont visibles depuis `ids_ips_venv`.
- ✅ Écriture protégée : un `pip install xxx` lancé depuis `ids_ips_venv` installe toujours dans le `site-packages` **propre** d'`ids_ips_venv`, jamais dans `pyglobal0`. L'original reste intact.

**Tester :**
```bash
~/ids_ips_venv/bin/python3.11 -c "import geoip2; print(geoip2.__file__)"
~/ids_ips_venv/bin/python3.11 -c "import modules_utils; print(modules_utils.__file__)"
```

## Étape 3 — Vérifier le point de montage (nosuid/noexec)

`setcap` échoue silencieusement si le point de montage a l'option `nosuid`.

```bash
mount | grep $(df --output=target ~/ids_ips_venv | tail -1)
```
→ Vérifier l'absence de `nosuid` **et** `noexec` dans les options affichées.

## Étape 4 — Appliquer la capability

```bash
sudo setcap cap_net_admin+ep ~/ids_ips_venv/bin/python3.11
getcap ~/ids_ips_venv/bin/python3.11
```
→ Attendu : `.../python3.11 cap_net_admin=ep`

⚠️ Le `setcap` doit être réappliqué à chaque fois que le venv est recréé (nouveau binaire = nouveau fichier = capability à réappliquer).

## Étape 5 — Configurer la variable d'environnement

Dans `.env` (lu par `ap_config.py` via `dotenv`) :
```
OBSIDIAN_IDS_IPS_PY_VENV=/home/hounsousamuel/ids_ips_venv/bin/python3.11
```

C'est ce chemin qu'utilise `NetworkWorkflow.run_async()` pour lancer le process IDS/IPS. Si ce chemin est faux ou que le venv n'existe plus, le process se lance avec un interpréteur sans capability → fallback silencieux sur `sudo`/`subprocess` dans `React._run_command()`.

## Récapitulatif — recréation complète en cas de suppression

```bash
rm -rf ~/ids_ips_venv
/usr/bin/python3.11 -m venv --copies ~/ids_ips_venv
echo "import site; site.addsitedir('/home/hounsousamuel/pyglobal0/lib/python3.11/site-packages')" > ~/ids_ips_venv/lib/python3.11/site-packages/_pyglobal0.pth
sudo setcap cap_net_admin+ep ~/ids_ips_venv/bin/python3.11
getcap ~/ids_ips_venv/bin/python3.11
```

## Points de vigilance

- **Mise à jour patch mineure du système** (ex: 3.11.14 → 3.11.15) : sans impact, la copie continue de fonctionner (ABI 3.11.x stable).
- **Montée de version majeure** (ex: 3.11 → 3.12) : nécessite de recréer le venv de toute façon (extensions C compilées liées à l'ABI 3.11), copie ou symlink ne change rien à ça.
- **`_run_command()` dans `reaction_module.py`** : doit distinguer les vraies commandes `nft` des autres commandes système (`chmod`, etc.) avant de router vers le backend `python-nftables`. Sinon les commandes non-nft (comme `decrease_access_rights()`) échouent silencieusement en tentant d'être interprétées comme du nft. *(Fix déjà appliqué et validé au test du 28/08.)*
