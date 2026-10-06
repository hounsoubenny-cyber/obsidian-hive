"""Version numpy de calculate_ip_score_anomaly (copie fidèle de la logique du .pyx)
+ test d'équivalence contre une version "boucle" et micro-benchmark.
"""
import time
import numpy as np

DEC_TH = np.array([-0.8, -0.7, -0.5, -0.3, -0.1, 0.0])      # croissant
DEC_PTS = np.array([40, 30, 25, 17, 12, 10, 0], float)        # 7 cases = 6 seuils + "au-dessus"
RATE_PTS = np.array([0, 5, 10, 15, 20, 25, 30], float)


def score_anomaly_batch(pred, dec, seq, rate, ports, critical_port, score_conf, ano, seq_length):
    """pred: -1/1 | dec: decision_function | seq: bool (anomalie de séquence)
    rate: pkt_rate | ports: str ("" si inconnu) — tous des tableaux de longueur N."""
    pred = np.asarray(pred); dec = np.asarray(dec, float)
    seq = np.asarray(seq, bool); rate = np.asarray(rate, float)

    max_score = score_conf.get("max_score_anomaly", 180.0)
    port_weight = score_conf.get("port_weight", 35.0)
    ml_predict = score_conf.get("ml_predict", 15.0)

    # 1) Ports : on ne cherche dans le dict qu'UNE fois par port distinct, puis on "redistribue"
    uniq, inv = np.unique(np.asarray(ports, dtype=str), return_inverse=True)
    if critical_port:
        base_u = np.array([min(critical_port.get(p, 10.0), port_weight) if p else 10.0 for p in uniq])
        crit_u = np.array([p in critical_port for p in uniq])
    else:
        base_u = np.full(len(uniq), 10.0)
        crit_u = np.zeros(len(uniq), bool)
    is_anom = pred == -1
    s = base_u[inv] + np.where(is_anom, ml_predict, 0.0) + np.where(is_anom & crit_u[inv], 30.0, 0.0)

    # 2) decision_function : la cascade if/elif devient "dans quelle case tombe dec ?"
    s += DEC_PTS[np.searchsorted(DEC_TH, dec, side="left")]      # NaN -> dernière case -> 0 point

    # 3) taux d'anomalies (séquence : rate / seq_length, +10 points)
    ratio = np.where(seq, rate / seq_length if seq_length > 0 else 0.0, rate)
    s += np.where(seq, 10.0, 0.0)
    rate_th = np.array([ano.get(k, d) for k, d in
                        (("minimal", .1), ("low", .3), ("medium", .5), ("high", .6), ("very_high", .75), ("critical", .9))])
    s += RATE_PTS[np.searchsorted(rate_th, ratio, side="left")]  # côté "left" = comparaison stricte (>)

    return np.minimum(s, max_score)


# ---- référence : le .pyx recopié en Python pur, un élément à la fois ----
def score_ref(pred, dec, seq, rate, port, critical_port, sc, ano, seq_length):
    score = 0.0
    mx = sc.get("max_score_anomaly", 180.0); pw = sc.get("port_weight", 35.0); ml = sc.get("ml_predict", 15.0)
    if port and critical_port:
        score += min(critical_port.get(port, 10.0), pw)
    else:
        score += 10.0
    if pred == -1: score += ml
    if pred == -1 and port in critical_port: score += 30.0
    for th, pts in zip(DEC_TH, DEC_PTS):
        if dec <= th:
            score += pts; break
    if seq:
        score += 10.0; ratio = rate / seq_length if seq_length > 0 else 0.0
    else:
        ratio = rate
    for k, d, pts in (("critical", .9, 30), ("very_high", .75, 25), ("high", .6, 20),
                      ("medium", .5, 15), ("low", .3, 10), ("minimal", .1, 5)):
        if ratio > ano.get(k, d):
            score += pts; break
    return min(score, mx)


if __name__ == "__main__":
    rng = np.random.default_rng(1)
    N, SEQ = 50_000, 60
    crit = {"22": 40.0, "3389": 45.0, "445": 40.0, "80": 12.0}
    sc, ano = {"ml_predict": 15.0, "port_weight": 35.0, "max_score_anomaly": 180.0}, {}

    # valeurs exactement sur les seuils = les cas où les bugs se cachent
    edge_dec = np.array([-0.8, -0.7, -0.5, -0.3, -0.1, 0.0, 0.0001, np.nan])
    edge_rate = np.array([0.1, 0.3, 0.5, 0.6, 0.75, 0.9, 1.0, 0.0])
    dec = np.concatenate([rng.uniform(-1, .5, N), edge_dec])
    rate = np.concatenate([rng.uniform(0, 1, N), edge_rate])
    n = len(dec)
    pred = np.where(rng.random(n) < .5, -1, 1)
    seq = rng.random(n) < .5
    ports = rng.choice(["22", "80", "3389", "445", "8080", "None", ""], n)

    ref = np.array([score_ref(*a, crit, sc, ano, SEQ) for a in zip(pred, dec, seq, rate, ports)])
    vec = score_anomaly_batch(pred, dec, seq, rate, ports, crit, sc, ano, SEQ)
    print("équivalent à la référence :", np.array_equal(ref, vec), f"({n} cas, seuils exacts + NaN inclus)")

    t = time.perf_counter()
    for a in zip(pred, dec, seq, rate, ports): score_ref(*a, crit, sc, ano, SEQ)
    t1 = time.perf_counter() - t
    t = time.perf_counter(); score_anomaly_batch(pred, dec, seq, rate, ports, crit, sc, ano, SEQ); t2 = time.perf_counter() - t
    print(f"boucle {t1/n*1e6:.2f} µs/élt | numpy {t2/n*1e6:.3f} µs/élt")

    print("\n--- comment detection_module appelle le score ---")
    print("paquet anormal, 5 paquets anormaux dans la fenêtre : pkt_rate=5 (un COMPTE)  ->",
          score_ref(-1, -0.65, False, 5, "80", crit, sc, ano, SEQ))
    print("même cas avec un vrai ratio 5/60                      ->",
          score_ref(-1, -0.65, False, 5 / 60, "80", crit, sc, ano, SEQ))
    print("séquence 45/60 anormaux : prop_anom=0.75 puis /SEQ_LENGTH ->",
          score_ref(-1, -0.65, True, 0.75, "80", crit, sc, ano, SEQ),
          "| si on passait 45 (compte) ->", score_ref(-1, -0.65, True, 45, "80", crit, sc, ano, SEQ))
