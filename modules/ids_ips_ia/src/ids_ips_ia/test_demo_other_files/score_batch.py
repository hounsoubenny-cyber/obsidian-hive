"""
score_batch.py — calcul du score d'anomalie pour UN LOT de paquets d'un coup (numpy).

Même logique que `_calculate_ip_score_anomaly` / le .pyx, APRÈS correction :
`rate` est toujours un ratio dans [0, 1] (part de paquets anormaux dans la fenêtre).

À placer dans : ids_ips_ia/detection/score_batch.py
"""
import numpy as np

# Barèmes. Lecture : "si dec <= -0.8 -> 40 pts ; sinon si dec <= -0.7 -> 30 pts ; ..."
# Il y a toujours UNE case de plus que de seuils (la case "au-dessus de tous les seuils").
DEC_THRESHOLDS = np.array([-0.8, -0.7, -0.5, -0.3, -0.1, 0.0])
DEC_POINTS = np.array([40, 30, 25, 17, 12, 10, 0], dtype=float)

RATE_POINTS = np.array([0, 5, 10, 15, 20, 25, 30], dtype=float)
# Clés de config, du seuil le plus bas au plus haut, avec leur valeur par défaut
RATE_KEYS = (("minimal", 0.1), ("low", 0.3), ("medium", 0.5),
             ("high", 0.6), ("very_high", 0.75), ("critical", 0.9))


def score_anomaly_batch(pred, dec, seq, rate, ports, critical_port, score_conf, ano_conf_rate):
    """
    Tous les arguments "tableaux" ont la même longueur N (un élément par anomalie).

    pred   : -1 (anormal) ou 1                     seq   : True si anomalie de séquence
    dec    : decision_function (float)             rate  : ratio [0, 1]
    ports  : port destination en STR ("" si inconnu, comme dans le wrapper)
    critical_port / score_conf / ano_conf_rate : les mêmes dicts que dans AnomalyScorer

    Retourne un tableau de N scores (float), plafonnés à max_score_anomaly.
    """
    pred = np.asarray(pred)
    dec = np.asarray(dec, dtype=float)
    seq = np.asarray(seq, dtype=bool)
    rate = np.nan_to_num(np.asarray(rate, dtype=float), nan=0.0)   # NaN -> 0 (comme les `>` du .pyx)

    max_score = score_conf.get("max_score_anomaly", 180.0)
    port_weight = score_conf.get("port_weight", 35.0)
    ml_predict = score_conf.get("ml_predict", 15.0)

    # ── Bloc 1 : le port ─────────────────────────────────────────────────────
    # On cherche dans le dict UNE fois par port distinct (il y en a peu), puis on
    # "redistribue" le résultat sur les N éléments avec `inv`.
    uniq, inv = np.unique(np.asarray(ports, dtype=str), return_inverse=True)
    if critical_port:
        base_u = np.array([min(critical_port.get(p, 10.0), port_weight) if p else 10.0 for p in uniq])
        crit_u = np.array([p in critical_port for p in uniq])
    else:
        base_u = np.full(len(uniq), 10.0)
        crit_u = np.zeros(len(uniq), dtype=bool)

    is_anom = pred == -1
    score = base_u[inv]                                    # points du port
    score = score + np.where(is_anom, ml_predict, 0.0)     # +15 si le modèle dit "anormal"
    score = score + np.where(is_anom & crit_u[inv], 30.0, 0.0)   # anormal ET port critique

    # ── Bloc 2 : decision_function ───────────────────────────────────────────
    # searchsorted(seuils, x) = "combien de seuils sont STRICTEMENT plus petits que x ?"
    # = le numéro de la case où tombe x -> on lit les points de cette case.
    score = score + DEC_POINTS[np.searchsorted(DEC_THRESHOLDS, dec, side="left")]
    # (dec = NaN tombe dans la dernière case = 0 point, comme le .pyx)

    # ── Bloc 3 : taux d'anomalies ────────────────────────────────────────────
    score = score + np.where(seq, 10.0, 0.0)               # +10 pour une anomalie de séquence
    rate_thresholds = np.array([ano_conf_rate.get(k, d) for k, d in RATE_KEYS])
    score = score + RATE_POINTS[np.searchsorted(rate_thresholds, rate, side="left")]

    return np.minimum(score, max_score)
