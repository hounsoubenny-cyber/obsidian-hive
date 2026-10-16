**RCU (Read-Copy-Update)** est un mécanisme de synchronisation qui permet à des lecteurs d'accéder à une structure de données partagée **sans verrou**, tandis que les écrivains peuvent modifier cette structure en parallèle. L'idée est que les lecteurs voient soit l'ancienne version, soit la nouvelle version, mais jamais un état incohérent.

Le principe est le suivant :
1. **Copie** : L'écrivain crée une nouvelle version de l'élément à modifier.
2. **Mise à jour** : Il publie atomiquement le pointeur vers la nouvelle version.
3. **Attente** : Il attend qu'une **période de grâce** s'écoule, garantissant qu'aucun lecteur n'utilise encore l'ancienne version.
4. **Libération** : Il peut alors libérer l'ancienne version en toute sécurité.

**QSBR (Quiescent-State-Based Reclamation)** est une implémentation spécifique de RCU. Sa particularité est que ce sont **les threads lecteurs eux-mêmes** qui signalent périodiquement qu'ils sont dans un **état de quiétude** (quiescent state), c'est-à-dire qu'ils ne détiennent plus aucune référence vers les données partagées.

Le fonctionnement est simple : chaque thread lecteur maintient un compteur et, à intervalles réguliers (par exemple dans sa boucle principale), il indique "je ne suis plus en train de lire". L'écrivain peut alors comparer ces compteurs pour savoir quand tous les lecteurs ont dépassé un certain point, lui permettant de libérer la mémoire en toute sécurité.

### 🔍 La différence essentielle

| Caractéristique | RCU classique | QSBR |
| :--- | :--- | :--- |
| **Signalement** | Le système détecte automatiquement les périodes de grâce (ex: changement de contexte dans le noyau). | Le thread lecteur **doit explicitement** signaler son état de quiétude. |
| **Performance** | Très bonne. | **Meilleure** : les lecteurs n'ont pratiquement aucun surcoût (pas de barrières mémoire). |
| **Contrainte** | Transparent pour l'application. | **Nécessite** que l'application intègre l'appel de signalement dans sa logique. |

En résumé, RCU est le concept général de synchronisation, et QSBR est une façon très efficace de l'implémenter lorsque l'application peut facilement indiquer ses points de repos.

Si tu veux, on peut détailler comment implémenter une petite structure de données lock-free avec ces mécanismes.
