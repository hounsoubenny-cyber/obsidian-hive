## Les features — c'est quoi et pourquoi

L'idée centrale : **le texte IA et le texte humain ont des signatures statistiques différentes**, indépendamment du sens. Même si tu comprends pas la langue, tu peux détecter ces patterns.

---

## 1. Perplexité

### C'est quoi

La perplexité mesure **à quel point un texte est prévisible** pour un modèle de langage.

```
Texte facile à prédire → perplexité basse
Texte difficile à prédire → perplexité haute
```

### Pourquoi ça discrimine humain vs IA

Un LLM génère toujours le token le plus probable. Résultat :

```
Texte IA    → très prévisible → perplexité BASSE  (20-50)
Texte humain→ imprévisible    → perplexité HAUTE  (100-300)
```

Les humains font des choix de mots inattendus, des tournures originales, des erreurs, des expressions idiomatiques. Les LLMs choisissent le chemin le plus probable à chaque étape.

### Comment on la calcule

On prend GPT-2 comme référence. On lui donne le texte et on mesure sa "surprise" :

```
"Le chat dort sur le tapis"
      ↓
GPT-2 prédit token par token :
  "Le"    → P("chat" | "Le") = 0.3      pas très prévisible
  "chat"  → P("dort" | "Le chat") = 0.6  assez prévisible
  "dort"  → P("sur" | ...) = 0.7        prévisible
  ...

Perplexité = exp( - moyenne des log probabilités )
```

---

## 2. Burstiness

### C'est quoi

Mesure la **variation de longueur des phrases** dans un texte.

### Pourquoi ça discrimine

```
Texte humain :
"Oui." 
"C'est exactement ce que je voulais dire depuis le début, et franchement je suis surpris que personne n'ait soulevé ce point avant."
"Bref."

→ variation énorme entre phrases courtes et longues
→ burstiness HAUTE

Texte IA :
"Ce phénomène est particulièrement intéressant à analyser."
"Il convient de noter plusieurs aspects importants à ce sujet."
"Cette observation mérite une attention particulière."

→ toutes les phrases font ~10 mots
→ burstiness BASSE
```

### Comment on la calcule

```
longueurs = [nombre de mots par phrase]
burstiness = écart-type(longueurs) / moyenne(longueurs)

→ proche de 0 = très uniforme = probablement IA
→ grand       = très variable = probablement humain
```

---

## 3. Stylometrics

C'est un ensemble de features linguistiques statistiques.

### TTR — Type-Token Ratio

```
Texte : "le chat mange le poisson et le chat dort"
Tokens (tous les mots)  : 9
Types  (mots uniques)   : 6  (le, chat, mange, poisson, et, dort)

TTR = 6/9 = 0.67

→ TTR haute = vocabulaire riche = plutôt humain
→ TTR basse = répétitions = plutôt IA
```

### Hapax Legomena

```
Mots qui apparaissent exactement UNE fois dans le texte

"le chat mange le poisson et le chat dort"
hapax = ["mange", "poisson", "et", "dort"]  → 4 hapax

ratio_hapax = 4/9 = 0.44

→ humains utilisent plus de mots uniques
→ IA répète plus souvent les mêmes mots
```

### Entropy N-gram

```
Mesure la diversité des séquences de mots

bigrams de "le chat mange le poisson" :
["le chat", "chat mange", "mange le", "le poisson"]

entropie = - somme( P(bigram) * log(P(bigram)) )

→ entropie haute = séquences très diverses = humain
→ entropie basse = séquences répétitives  = IA
```

### Compression Ratio

```
import zlib

ratio = len(zlib.compress(text.encode())) / len(text.encode())

→ texte répétitif   → très compressible → ratio BAS  → IA
→ texte varié       → peu compressible  → ratio HAUT → humain
```

C'est une mesure d'entropie informationnelle — brillant parce que c'est indépendant de la langue.

### Discourse Markers

```
Mots comme : "Moreover", "Furthermore", "In conclusion",
             "It is important to note", "Additionally"

→ les LLMs en abusent massivement
→ les humains les utilisent moins et plus naturellement

ratio = count(discourse_markers) / nombre_de_mots
```

### Hedge Words

```
Mots comme : "perhaps", "might", "could", "it seems",
             "generally", "typically"

→ les LLMs sur-utilisent ces mots pour paraître nuancés
→ signal fort de génération IA
```

---

## Résumé visuel

```
                    Texte IA    Texte Humain
                    ────────    ────────────
Perplexité          BASSE       HAUTE
Burstiness          BASSE       HAUTE
TTR                 BASSE       HAUTE
Hapax ratio         BAS         HAUT
N-gram entropy      BASSE       HAUTE
Compression ratio   BAS         HAUT
Discourse markers   HAUT        BAS
Hedge words         HAUT        BAS
```

Ces features sont **complémentaires** à l'embedding RoBERTa :
- RoBERTa capture le **sens et le style** global
- Ces features capturent les **patterns statistiques** indépendants du sens

C'est pourquoi leur combinaison est plus forte que chacun séparément.

---

## Les formules

### Perplexité
```
PP(T) = exp( -1/N * Σ log P(tᵢ | t₁...tᵢ₋₁) )

N = nombre de tokens
P(tᵢ | t₁...tᵢ₋₁) = probabilité du token i donnée par GPT-2
```

---

### Burstiness
```
B = σ(L) / μ(L)

L = liste des longueurs de phrases en mots
σ = écart-type
μ = moyenne
```

---

### TTR
```
TTR = |V| / N

|V| = nombre de mots uniques (types)
N   = nombre total de mots (tokens)
```

---

### Hapax Ratio
```
H = |{w : freq(w) = 1}| / N

|{w : freq(w) = 1}| = nombre de mots qui apparaissent exactement 1 fois
N = nombre total de mots
```

---

### N-gram Entropy
```
E = - Σ P(gᵢ) * log₂( P(gᵢ) )

P(gᵢ) = freq(gᵢ) / nombre total de n-grams
```

---

### Compression Ratio
```
CR = len( zlib(text) ) / len( text )
```

---

### Discourse Markers Ratio
```
DM = count(discourse_markers ∩ words) / N
```

---

### Hedge Words Ratio
```
HW = count(hedge_words ∩ words) / N
```

---

Tu codes et tu m'appelles si t'es bloqué.