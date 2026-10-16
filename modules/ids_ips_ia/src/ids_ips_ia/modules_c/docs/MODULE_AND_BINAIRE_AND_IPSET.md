## 🧠 L'`IpSet`, pas à pas

**Le besoin** : savoir « cette IP est-elle bloquée ? » à **chaque paquet**, donc des milliers de fois par seconde, très vite.

**L'idée** : un tableau de cases. Le hash transforme l'IP en grand nombre, et il faut en tirer un numéro de case.

### 1️⃣ Le `&` au lieu du modulo
Le modulo (`%`) est le reste d'une division, et la division est lente pour le processeur. Si le nombre de cases est une **puissance de 2**, on peut faire pareil avec un `&`, qui coûte un seul cycle :

```
16 cases → mask = 15 = 0b1111
hash = 37 = 0b100101
37 & 15 = 0b0101 = 5      (et 37 % 16 = 5, pareil)
```

Le `& mask` garde seulement les derniers bits. C'est pour ça que `ipset_create` arrondit à une puissance de 2 (`cells <<= 1`) et que `mask = cells - 1`. Avec 10 cases, `mask = 9 = 0b1001` n'atteindrait que les cases 0, 1, 8 et 9, donc ça ne marche que pour les puissances de 2.

Comme on ne garde que les derniers bits, ils doivent bien être mélangés. C'est le rôle de `fmix32` dans `_hash` : sans lui, `10.0.0.1` et `10.0.0.2` tomberaient dans des cases voisines.

Le `& mask` sert aussi à **faire le tour** : `(i + 1) & mask`, quand `i = 15`, redonne `0`. Et `(i - 1) & mask` avec `i = 0` redonne la dernière case, grâce au débordement des entiers non signés.

### 2️⃣ L'adressage ouvert
Deux IP peuvent tomber dans la même case, c'est une collision. Ton `Dict` règle ça avec une **liste chaînée par case**. L'`IpSet` règle ça autrement : si la case est prise, on prend **la suivante**. Tout reste dans un seul tableau, sans `malloc` par collision, et les cases voisines sont proches en mémoire, donc c'est très rapide.

Trois IP A, B, C tombent toutes dans la case 3 :
```
cases :  0  1  2  3  4  5  6  7
         .  .  .  A  B  C  .  .
```
Pour chercher C, on regarde 3 (A, pas elle), 4 (B, pas elle), 5 (C, trouvée ✅). Pour chercher une IP absente qui tombe aussi en 3, on parcourt 3, 4, 5, puis la case 6 est **vide**, donc elle n'est pas là.

**La règle d'or : une chaîne n'a jamais de trou.** Une case vide veut dire « fin de la chaîne ».

### 3️⃣ Pourquoi jamais plus de la moitié pleine
Il faut toujours une case vide pour arrêter une recherche. À 50 % de remplissage, une recherche coûte en moyenne 1,5 à 2,5 cases. C'est le prix de la vitesse : il y a deux fois plus de cases que d'IP, d'où `max_cells_used = cells / 2`.

### 4️⃣ Retirer : le piège
Si on vide la case 4 (B), la recherche de C s'arrête en 4 (« vide, donc absente ») et on perd C. On met donc une **TOMB** (une pierre tombale) : « occupée mais vide, continue ».
```
après remove(B) :   .  .  .  A  ☠  C  .  .      C est toujours trouvée
```
C'est là que se cachait le bug que j'ai corrigé : les ☠ s'accumulaient pour toujours. La correction consiste à remettre une case à vide **si la suivante est vide**, puisque la chaîne s'arrête là de toute façon, et à remonter vers les ☠ précédentes :
```
remove(C) : la case 6 est vide → la 5 redevient vide, la 4 (☠) aussi
            .  .  .  A  .  .  .  .
```

### 5️⃣ Lire sans verrou
Les threads de capture lisent sans jamais attendre. Chaque case contient un pointeur vers une fiche **qu'on ne modifie jamais** après publication. L'écrivain remplit la fiche en entier, puis publie le pointeur (`release`), et le lecteur le lit avec `acquire`. Il voit donc la fiche complète ou rien, jamais une IP à moitié écrite. Les fiches retirées ne sont pas libérées tout de suite (`retired`), car un lecteur peut encore les consulter.

Dis-moi quelle étape reste floue, la 1️⃣, la 4️⃣ ou la 5️⃣, et je la reprends avec un autre exemple 🙂
