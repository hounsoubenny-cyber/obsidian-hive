## Petit doc — les 3 modes de déploiement NetworkAsset

**GATEWAY** 🌐
Obsidian Hive est déjà le routeur du réseau — le trafic passe par lui de par sa position, sans rien à configurer. `interface` = les interfaces déjà existantes sur la machine (ex: `eth0`).
→ Détection **et** blocage possibles (il est dans le chemin par nature). Simple, mais suppose que tu contrôles déjà le rôle de routeur.

**SPAN_MIRROR** 🔀
Un switch physique copie tout son trafic vers un port dédié (à configurer côté switch, hors Obsidian Hive). L'interface branchée sur ce port passe en mode "promiscuous" pour lire cette copie.
→ Détection seulement (IDS) — la copie arrive en parallèle, trop tard pour bloquer l'original. Zéro risque pour le réseau si ça plante.
→ Utile pour voir aussi le trafic *interne* au LAN (entre deux PC du même switch), que GATEWAY/BRIDGE ne voient pas forcément.

**BRIDGE** 🌉
Obsidian Hive s'insère physiquement à un point de passage obligé (ex: entre le switch et la sortie internet), avec deux interfaces fusionnées en une interface virtuelle transparente (`br-xxx`).
→ Détection **et** blocage réels (rien ne passe sans traverser la machine). Mais point de panne unique : si ça plante, plus rien ne circule entre les deux segments.
→ Ne voit que ce qui traverse ce point précis, pas le trafic 100% local d'un côté.

---