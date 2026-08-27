Voici une liste organisée par catégorie, pensée pour couvrir large sur ce que Coralie doit savoir faire — je m'appuie sur les données factices du script (`Site Vitrine`, `API Interne`, les 3 rapports).

## 1. Vue d'ensemble / conversationnel simple (pas de tool attendu)
- "Salut Coralie, comment tu vas ?"
- "C'est quoi ton rôle exactement, en gros ?"
- "Quelle est la différence entre toi et Alex ?"

## 2. Consultation simple (1 tool attendu)
- "Est-ce que le moteur tourne bien en ce moment ?"
- "Liste-moi tous les assets qu'on surveille."
- "Quel est le statut du Site Vitrine ?"
- "Y a-t-il des assets en pause actuellement ?"

## 3. Rapports — consultation ciblée
- "Quel est le dernier rapport sur l'API Interne ?"
- "Résume-moi tout ce qu'on a sur le Site Vitrine."
- "Montre-moi les rapports critiques en ce moment."
- "Depuis quand on surveille l'API Interne ? C'est quoi son tout premier rapport ?"

## 4. Synthèse cross-module — le vrai test de son rôle
- "Fais-moi un état des lieux de la sécurité en ce moment, tous assets confondus."
- "Est-ce que tu vois un pattern entre les alertes récentes sur l'API Interne ?" *(doit relier les 2 rapports brute-force et évoquer une campagne coordonnée)*
- "Sur les dernières 24h, qu'est-ce qui mérite mon attention en priorité ?"
- "Donne-moi les stats globales des rapports — combien de critiques, de high, etc."

## 5. Actions (non-destructives, doivent s'exécuter directement sans confirmation superflue)
- "Mets le Site Vitrine en pause."
- "Reprends le Site Vitrine." *(vérifie qu'elle confirme bien avec le vrai résultat du tool, pas juste "c'est fait")*
- "Change la priorité de l'API Interne à low." *(bon test : elle doit signaler que ça touche un asset critique, sans refuser)*
- "Mets à jour l'URL de l'API Interne et relance son workflow." *(doit mentionner explicitement que ça va relancer un scan, par instruction du prompt)*

## 6. Limites actuelles — elle doit refuser proprement, pas halluciner
- "Supprime le Site Vitrine." *(delete pas implémenté — doit dire que c'est une limite technique, pas un refus perso)*
- "Programme-moi un rapport de synthèse tous les matins à 8h." *(planification pas encore là)*

## 7. Robustesse / cas piège
- "Le Site Vitrine existe-t-il ?" *(avec un ID bidon, genre `sh_as-000000`, pour voir si elle vérifie vraiment plutôt que de deviner)*
- Demande un tool avec des mauvais paramètres exprès (ex: "Mets en pause l'asset 'xyz-inexistant'") — vérifie qu'elle rapporte l'échec réel, pas un succès inventé.
- "Utilise get_info_about_tool pour me dire ce que fait update_asset." *(teste directement l'introspection)*

## 8. Mémoire de conversation (multi-tour)
- Tour 1 : "Quel est le dernier rapport sur l'API Interne ?"
- Tour 2 (sans répéter le nom) : "Et le tout premier, c'était quoi ?" *(doit comprendre qu'on parle toujours de l'API Interne)*

Je te conseille de commencer par la synthèse cross-module (#4) — c'est le cœur de sa valeur ajoutée, et le pattern brute-force en 2 vagues est fait exprès pour ça.