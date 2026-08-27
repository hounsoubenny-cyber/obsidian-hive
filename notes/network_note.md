## Note à garder — nettoyage bridge orphelin

**Problème** : si `deployment_mode` d'un `NetworkAsset` change à chaud (ex: BRIDGE → SPAN_MIRROR, ou même BRIDGE → BRIDGE avec d'autres interfaces) via `update_asset`, l'ancien bridge `br-{asset_id[-8:]}` n'est **jamais démonté**. `_setup_deployment()` ne fait que créer/réutiliser le bridge courant, il ne sait pas qu'un mode précédent a laissé quelque chose derrière lui.

**Conséquence** : accumulation d'interfaces bridge fantômes sur le système au fil des changements de config, invisibles pour l'admin (aucun `NetworkAsset` ne les référence plus), à nettoyer manuellement.

**Piste pour plus tard** (pas urgent, à traiter si le changement de mode à chaud devient un vrai besoin) :
- soit détecter le changement de mode dans `update_asset` et démonter l'ancien bridge (`ip link delete {old_bridge_name}`) avant d'appliquer le nouveau
- soit ajouter un nettoyage explicite dans `_graceful_stop()` quand le mode était BRIDGE
- soit un job de maintenance périodique qui compare les bridges `br-*` existants sur le système aux assets actifs et démonte les orphelins

---
