# cython: boundscheck=False, wraparound=False, cdivision=True
# cython: language_level=3

cpdef double calculate_ip_score_anomaly_cython(
    int pred,
    double dec_func,
    bint seq_anomaly,
    double pkt_rate,
    str port,
    dict critical_port,
    dict score_conf,
    dict ano_conf_rate,
    int seq_length
):
    """
    Version Cython ultra-rapide de calculate_ip_score_anomaly.
    
    Args:
        pred: -1 ou 1
        dec_func: valeur de decision_function
        seq_anomaly: True si anomalie de séquence
        pkt_rate: taux de paquets anormaux
        port: port destination (str)
        critical_port: dict des ports critiques
        score_conf: dict SCORE_CONF
        ano_conf_rate: dict ANO_CONF_RATE
        seq_length: SEQ_LENGTH
    
    Returns:
        Score normalisé (0-300)
    """
    cdef double score = 0.0
    cdef double max_score = score_conf.get('max_score_anomaly', 180.0)
    cdef double port_weight = score_conf.get('port_weight', 35.0)
    cdef double ml_predict = score_conf.get('ml_predict', 15.0)
    
    # Port score
    cdef double port_score 
    if port and critical_port:
        port_score = critical_port.get(port, 10.0)
        if port_score > port_weight:
            port_score = port_weight
        score += port_score
    else:
        score += 10.0
    
    # ML prediction
    if pred == -1:
        score += ml_predict
    
    # Contexte critique (port + anomalie)
    if pred == -1 and port in critical_port:
        score += 30.0
    
    # Decision function scoring
    if dec_func <= -0.8:
        score += 40.0
    elif dec_func <= -0.7:
        score += 30.0
    elif dec_func <= -0.5:
        score += 25.0
    elif dec_func <= -0.3:
        score += 17.0
    elif dec_func <= -0.1:
        score += 12.0
    elif dec_func <= 0.0:
        score += 10.0
    
    # Anomaly ratio
    cdef double anomaly_ratio
    # Anomalie de séquence
    if seq_anomaly:
        score += 10.0
        anomaly_ratio = pkt_rate / seq_length if seq_length > 0 else 0.0
    else:
        anomaly_ratio = pkt_rate
    
    cdef double critical_th = ano_conf_rate.get('critical', 0.9)
    cdef double very_high_th = ano_conf_rate.get('very_high', 0.75)
    cdef double high_th = ano_conf_rate.get('high', 0.6)
    cdef double medium_th = ano_conf_rate.get('medium', 0.5)
    cdef double low_th = ano_conf_rate.get('low', 0.3)
    cdef double minimal_th = ano_conf_rate.get('minimal', 0.1)
    
    if anomaly_ratio > critical_th:
        score += 30.0
    elif anomaly_ratio > very_high_th:
        score += 25.0
    elif anomaly_ratio > high_th:
        score += 20.0
    elif anomaly_ratio > medium_th:
        score += 15.0
    elif anomaly_ratio > low_th:
        score += 10.0
    elif anomaly_ratio > minimal_th:
        score += 5.0
    
    if score > max_score:
        score = max_score
    
    return score