#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug  7 06:17:41 2026

@author: hounsousamuel


anomaly_scorer.py

Extrait de detection_module.py : le scoring des anomalies par IP
(AnomalyScorer), le petit moniteur de logs console (TextMonitor),
et la résolution DNS avec cache borné (resolve_hostname).
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import socket
import json
import time
import asyncio
import numpy as np
from datetime import datetime

import dpkt

from ids_ips_ia.models.models import Models
from ids_ips_ia.ids_ips_utils.suricata_integration import IPS
from ids_ips_ia.reaction.reaction_module import React, GeoLocator
from ids_ips_ia.ids_ips_utils.mail_sms_sender import Text
from ids_ips_ia.config.config_ids import (
    THREAT_LEVELS,
    CRITICAL_PORT_KEY, CONFIG,
    SCORING_CONFIG_KEY,
    ANOMALY_RATE_THRESHOLDS_KEY,
    DECAY_CONFIG_KEY, DANGEROUS_LOCALISATION_KEY, SEQ_LENGTH
)
from ids_ips_ia.ids_ips_utils.logger import get_logger
from ids_ips_ia.ids_ips_utils.instance_id import INSTANCE_SUFFIX

try:
    from ids_ips_ia.detection._cython_module.calculate_ip_score_anomaly_cython import calculate_ip_score_anomaly_cython
    _USE_CYTHON = True
except Exception:
    _USE_CYTHON = False

logger = get_logger()

DEFAULT_CRITICAL_PORT = {
    "22": 25,    # SSH
    "3389": 25,  # RDP
    "445": 20,   # SMB
    "80": 10,    # HTTP
    "443": 10,   # HTTPS
    "21": 15,    # FTP
    "23": 20,
}
DEFAULT_DANGEROUS_LOCALISATION = {}

locator_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', INSTANCE_SUFFIX)
ip_score_dir = os.path.join(locator_dir, 'historique_score')
os.makedirs(locator_dir, exist_ok=True)
os.makedirs(ip_score_dir, exist_ok=True)

_hostname_cache: dict[str, str] = {}
_HOSTNAME_CACHE_MAXSIZE = 500


async def resolve_hostname(ip: str) -> str:
    """Essaie de résoudre le nom d'hôte d'une IP (avec cache borné, FIFO)"""
    if not ip or ip in ("0.0.0.0", "127.0.0.1", "::", "::1"):
        return "local"
    
    if ip in _hostname_cache:
        return _hostname_cache[ip]

    is_resolved = False
    try:
        result = asyncio.to_thread(socket.gethostbyaddr, ip)
        result = asyncio.wait_for(result, 0.5)
        value = result[0]
        is_resolved = True
    except Exception:
        value = "non-résolu"

    if len(_hostname_cache) >= _HOSTNAME_CACHE_MAXSIZE:
        oldest_ip = next(iter(_hostname_cache))
        del _hostname_cache[oldest_ip]

    if is_resolved:
        _hostname_cache[ip] = value
    return value


class TextMonitor:
    def __init__(self, window_size=60):
        from collections import deque
        self.scores = deque(maxlen=window_size)
        self.actions = deque(maxlen=window_size)

    def update(self, score, action, ip):
        self.scores.append(score)
        self.actions.append(action)

        avg_score = sum(self.scores) / len(self.scores) if self.scores else 0
        recent_alerts = list(self.actions)[-5:]

        logger.print(f"\n \n \n {'='*150}")
        logger.print(f"🕒  Date : {time.ctime()}")
        logger.print(f"🕒 {time.strftime('%H:%M:%S %d/%m/%Y')} | IP: {ip}")
        logger.print(f"📊 Score: {score:.1f} | Moyenne: {avg_score:.1f}")
        logger.print(f"🚨 Action: {action}")
        logger.print(f"📈 Récent: {', '.join(recent_alerts[-3:])}")
        logger.print(f"{'='*150}")
        logger.print('\n \n \n')


class AnomalyScorer:
    def __init__(self, React: React, Text: Text, loss_per_hour=5, reset_days=14):
        self.loss_per_hour = loss_per_hour
        self.reset_days = reset_days * 24 * 3600
        self.ip_data = {}
        self.save_atexit()
        self.ip_score_dir = os.path.join(ip_score_dir, 'scores.pkl')
        self.load(self.ip_score_dir)
        self.critical_port = CONFIG.CONFIG.get(CRITICAL_PORT_KEY, {})
        self.GeoLocator = GeoLocator()
        self.React = React
        self.Text = Text
        self.TextMonitor = TextMonitor()
        self.ip_event_history = {}  # {ip: {'events': [...], 'last_update': time, 'escalation_level': 0}}
        self.EVENT_WINDOW = 30  # Fenêtre temporelle en secondes
        self.ESCALATION_THRESHOLD = 3
        self.dangerous_localisation = CONFIG.CONFIG.get(DANGEROUS_LOCALISATION_KEY, {})
        self.last_save = time.time()
        self.save_interval = 300
        logger.print(f"AnomalyScorer initialisé avec dossier de scores ip à : {self.ip_score_dir}")

    def save(self, filename, value):
        try:
            import joblib
            joblib.dump(value, filename, compress=5)
            os.chmod(filename, 0o644)
            logger.print(f'Fichier sauvegarder dans : {filename}')
            try:
                with open(filename.replace('.pkl', '.json'), 'w', encoding='utf-8') as f:
                    json.dump(value, f, indent=4, ensure_ascii=False)
                logger.print(f"Fichier sauvegarder aussi dans : {filename.replace('.pkl', '.json')}")
                os.chmod(filename.replace('.pkl', '.json'), 0o644)
            except Exception:
                pass
            return True

        except Exception as e:
            logger.print("Erreur lord de la sauvegarde du fichier historique : ", e)
            return False

    def save_whitelist(self, filename, value):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(value, f, indent=4, ensure_ascii=False)
            logger.print('Fichier sauvegarder dans : ', filename)
            os.chmod(filename, 0o644)
            return True

        except Exception as e:
            logger.print("Erreur lord de la sauvegarde du fichier historique : ", e)
            return False

    def load(self, filename):
        try:
            import joblib
            data = joblib.load(filename)
            logger.print('Fichier chargé depuis : ', filename, "avec ", len(data), 'entrées !')
            self.blocked_for = data if isinstance(data, dict) else {}
            return True

        except Exception as e:
            logger.print("Erreur lord du chargement du fichier historique : ", e)
            return False

    def save_atexit(self):
        import atexit

        def _save():
            self.save(self.ip_score_dir, self.ip_data)
            logger.print('Fin sauvegarde !')
        atexit.register(_save)

    def _get_ip(self, pkt: dpkt.ethernet.Ethernet, with_dst: bool = False):
        try:
            if isinstance(pkt, str):
                return (pkt, pkt) if with_dst else pkt

            if isinstance(pkt, dpkt.ethernet.Ethernet):
                ip = pkt.data
            else:
                ip = pkt

            if isinstance(ip, dpkt.ip.IP):
                src = ip.src
                try:
                    src = socket.inet_ntoa(src)
                    dst = socket.inet_ntoa(ip.dst)
                    return (src, dst) if with_dst else src
                except Exception as e:
                    logger.print(f"Erreur IPv4 extraction: {e}")
                    return ("0.0.0.0", "0.0.0.0") if with_dst else "0.0.0.0"

            elif isinstance(ip, dpkt.ip6.IP6):
                try:
                    src = socket.inet_ntop(socket.AF_INET6, ip.src)
                    dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
                    return (src, dst) if with_dst else src
                except Exception as e:
                    logger.print(f"Erreur IPv6 extraction: {e}")
                    return ("::", "::") if with_dst else "::"
            else:
                return ("0.0.0.0", "0.0.0.0") if with_dst else "0.0.0.0"

        except Exception as e:
            logger.print(f"Erreur _get_ip globale: {e}")
            return ("0.0.0.0", "0.0.0.0") if with_dst else "0.0.0.0"

    def _get_port(self, pkt: dpkt.ethernet.Ethernet):
        """Extrait le port destination d'un paquet"""
        try:
            if isinstance(pkt, dpkt.ethernet.Ethernet):
                ip = pkt.data
                if isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    transport = ip.data
                else:
                    return None
            else:
                transport = pkt

            if isinstance(transport, dpkt.tcp.TCP):
                return transport.dport
            elif isinstance(transport, dpkt.udp.UDP):
                return transport.dport
            elif isinstance(transport, dpkt.icmp.ICMP):
                return None
            else:
                return None

        except Exception as e:
            logger.print(f"Erreur _get_port: {e}")
            return None

    async def get_ia_preds_pkt(self, features: dict | np.ndarray, models: dict, Model: Models, how, *args, **kwargs):
        ae_pkt, if_pkt, lof_pkt, scaler = (models["ae_pkt"], models["if_pkt"], models["lof_pkt"], models['scaler_pkt'])
        de_func = await Model.apredict_packet(ae_pkt, if_pkt, lof_pkt, scaler, pkt_features=features, method="decision_function", how=how)
        pred = await Model.apredict_packet(ae_pkt, if_pkt, lof_pkt, scaler, pkt_features=features, method="predict", how=how)
        return {
            "predict": pred,
            'decision_function': de_func,
        }

    async def get_ia_preds_seq(self, features: dict | np.ndarray, models: dict, Model: Models, how, *args, **kwargs):
        ae_seq, cnn_seq, if_seq, lof_seq, scaler = (models["ae_seq"], models["cnn_seq"], models["if_seq"],
                                                      models["lof_seq"], models['scaler_seq'])

        de_func = await Model.apredict_sequence(ae_seq, cnn_seq, if_seq, lof_seq, scaler, features, method="decision_function", how=how)
        pred = await Model.apredict_sequence(ae_seq, cnn_seq, if_seq, lof_seq, scaler, features, method="predict", how=how)
        return {
            "predict": pred,
            'decision_function': de_func,
        }

    def _calculate_ip_score_anomaly(self, ia_preds: dict, pkt, pkt_rate: int, seq_anomaly: bool = False):
        score = 0
        SCORE_CONF = CONFIG.CONFIG.get(SCORING_CONFIG_KEY, {})
        max_score = SCORE_CONF.get('max_score_anomaly', 180)

        port = self._get_port(pkt) if pkt else None

        if not self.critical_port:
            self.critical_port = DEFAULT_CRITICAL_PORT

        if port:
            port_score = self.critical_port.get(str(port), 10)
            score += min(port_score, SCORE_CONF.get('port_weight', port_score))
        else:
            score += 10

        pred = ia_preds.get("predict", 1)
        dec_func = ia_preds.get('decision_function', 0)
        if pred == -1:
            score += SCORE_CONF.get('ml_predict', 15)

        if ((pred == -1) and (port in self.critical_port)):
            score += 30

        if dec_func <= -0.8:
            score += 40
        elif dec_func <= -0.7:
            score += 30
        elif dec_func <= -0.5:
            score += 25
        elif dec_func <= -0.3:
            score += 17
        elif dec_func <= -0.1:
            score += 12
        elif dec_func <= 0.0:
            score += 10
        else:
            score += 0

        if seq_anomaly:
            score += 10
            anomaly_ratio = pkt_rate / SEQ_LENGTH if SEQ_LENGTH > 0 else 0
        else:
            anomaly_ratio = pkt_rate

        ANO_CONF_RATE = CONFIG.CONFIG.get(ANOMALY_RATE_THRESHOLDS_KEY, {})
        if anomaly_ratio > ANO_CONF_RATE.get('critical', 0.9):
            score += 30
        elif anomaly_ratio > ANO_CONF_RATE.get('very_high', 0.75):
            score += 25
        elif anomaly_ratio > ANO_CONF_RATE.get('high', 0.6):
            score += 20
        elif anomaly_ratio > ANO_CONF_RATE.get('medium', 0.5):
            score += 15
        elif anomaly_ratio > ANO_CONF_RATE.get('low', 0.3):
            score += 10
        elif anomaly_ratio > ANO_CONF_RATE.get('minimal', 0.1):
            score += 5

        return min(score, max_score)

    def calculate_ip_score_anomaly(self, ia_preds: dict, pkt, pkt_rate: int, seq_anomaly: bool = False):
        if not _USE_CYTHON:
            return self._calculate_ip_score_anomaly(ia_preds, pkt, pkt_rate, seq_anomaly)
        else:
            pred = ia_preds.get("predict", 1)
            dec_func = ia_preds.get('decision_function', 0)
            port = str(self._get_port(pkt)) if pkt else ""

            return calculate_ip_score_anomaly_cython(
                pred=pred,
                dec_func=dec_func,
                seq_anomaly=seq_anomaly,
                pkt_rate=pkt_rate,
                port=port,
                critical_port=self.critical_port,
                score_conf=CONFIG.CONFIG.get(SCORING_CONFIG_KEY, {}),
                ano_conf_rate=CONFIG.CONFIG.get(ANOMALY_RATE_THRESHOLDS_KEY, {}),
                seq_length=SEQ_LENGTH
            )

    def calculate_ip_score_dangerous(self, ip: str, anomaly_score: int | float):
        if ip not in self.ip_data:
            self.get_default(ip)

        bonus = 0
        SCORE_CONF = CONFIG.CONFIG.get(SCORING_CONFIG_KEY, {})
        max_score = SCORE_CONF.get('max_score_total', 300)

        ip_data = self.ip_data[ip]
        self.ip_data[ip]['ip'] = ip
        geo_loc = self.GeoLocator.locate(ip)
        geo_loc = ip_data.get('geoloc', geo_loc)
        if not self.dangerous_localisation:
            self.dangerous_localisation = DEFAULT_DANGEROUS_LOCALISATION
        geo_score = self.dangerous_localisation.get(geo_loc, 0)
        bonus += min(geo_score, SCORE_CONF.get("geo_max", geo_score))

        blocked_count = ip_data.get('blocked_count', 0)
        count = 0
        if blocked_count >= 10:
            count += 45
        elif blocked_count >= 6:
            count += 35
        elif blocked_count >= 3:
            count += 20
        elif blocked_count >= 1:
            count += 10

        bonus += min(count, SCORE_CONF.get('block_history_weight', 45))
        timestamp = ip_data.get('last_update_timestamp', time.time())

        anomaly_count = ip_data.get('anomaly_count', 0)
        if anomaly_count >= 25:
            bonus += 35
        elif anomaly_count >= 15:
            bonus += 28
        elif anomaly_count >= 8:
            bonus += 18
        elif anomaly_count >= 4:
            bonus += 8

        bonus += self.detect_beaconing(ip)
        bonus = min(bonus, SCORE_CONF.get('max_bonus', 100))
        score = anomaly_score + bonus
        new_score = self.decay_hours(score, timestamp)

        self.update(new_score, ip, geo_loc)
        return min(new_score, max_score)

    def decay_hours(self, score, timestamp: float):
        now = time.time()
        decay = now - timestamp
        reset_days = CONFIG.CONFIG.get(DECAY_CONFIG_KEY, {}).get("reset_seconds", self.reset_days)
        if decay > reset_days:
            return 0
        score = score - ((decay / 3600) * CONFIG.CONFIG.get(DECAY_CONFIG_KEY, {}).get("loss_per_hour", self.loss_per_hour))
        return max(0, min(score, 100))

    def update(self, score, ip, geo_loc: str = None):
        if geo_loc is None:
            geo_loc = self.GeoLocator.locate(ip)

        date = datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
        ip_data = self.ip_data[ip]
        ip_data["score"] = score
        ip_data['last_update'] = date
        ip_data['last_update_timestamp'] = time.time()
        ip_data['geoloc'] = geo_loc
        ip_data['anomaly_count'] = ip_data.get('anomaly_count', 0) + 1

        self.ip_data[ip] = ip_data

    def make_blocked(self, ip):
        blocked_count = self.ip_data.get(ip, {}).get("blocked_count", 0)
        blocked_count += 1
        self.ip_data[ip]["blocked_count"] = blocked_count
        return True

    def get_message(self, action: str, duration: float, decision: dict, ip: str):
        action = str(action).upper()
        date = datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
        duration = duration if duration is not None else 'infini'

        message = f"""
        🚨 ALERTE CRITIQUE

        IP: {ip}
        Score: {decision['score']}/100
        Action: {action}
        Duration : {duration}
        Date : {date}

        Données IP:
        {json.dumps(self.ip_data[ip], indent=2)}
        """

        logger.print(message)
        return message

    def get_default(self, ip):
        date = datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
        dic = {
            'score': 0,
            'anomaly_count': 0,
            'last_update': date,
            'last_update_timestamp': time.time(),
            'geoloc': self.GeoLocator.locate(ip),
            'blocked_count': 0,
            'fisrt_seen': date,
            "resolution": None,
            "input": True,
            "port": None,
            "ip": ip,
            "decision": {
                "level": None,
                "action": None,
                "duration": None,
            }
        }
        self.ip_data[ip] = dic
        return dic
    
    def cleanup_stale_data(self):
        """
        Garbage collector : Nettoie la RAM des IPs inactives.
        Appelé périodiquement avant chaque sauvegarde sur le disque.
        """
        try:
            current_time = time.time()
            
            # =========================================================
            # 1. Nettoyage de la mémoire à COURT TERME (ip_event_history)
            # =========================================================
            keys_to_delete_events = []
            
            # On itère sur une copie des clés pour éviter les erreurs de concurrence
            for ip, data in list(self.ip_event_history.items()):
                last_update = data.get('last_update', 0)
                # Si l'IP n'a rien envoyé depuis plus de 30 secondes (EVENT_WINDOW)
                if (current_time - last_update) > self.EVENT_WINDOW:
                    keys_to_delete_events.append(ip)

            for ip in keys_to_delete_events:
                self.ip_event_history.pop(ip, None) # Suppression safe

            # =========================================================
            # 2. Nettoyage de la mémoire à LONG TERME (ip_data)
            # =========================================================
            decay_conf = CONFIG.CONFIG.get(DECAY_CONFIG_KEY, {})
            reset_seconds = decay_conf.get("reset_seconds", self.reset_days)
            
            keys_to_delete_data = []
            
            for ip, data in list(self.ip_data.items()):
                last_update = data.get('last_update_timestamp', 0)
                
                # Si l'IP n'a rien fait depuis X jours (reset_seconds)
                if (current_time - last_update) > reset_seconds:
                    # ⚠️ RÈGLE D'OR : On ne supprime JAMAIS une IP si elle 
                    # est actuellement bloquée dans le pare-feu !
                    if ip not in self.React.blocked:
                        keys_to_delete_data.append(ip)

            for ip in keys_to_delete_data:
                self.ip_data.pop(ip, None)

            # =========================================================
            # Logs de suivi
            # =========================================================
            if keys_to_delete_events or keys_to_delete_data:
                logger.debug(
                    f"🧹 Garbage Collector : "
                    f"{len(keys_to_delete_events)} historiques courts purgés | "
                    f"{len(keys_to_delete_data)} IPs mortes purgées de la RAM."
                )

        except Exception as e:
            logger.error(f"❌ Erreur dans le Garbage Collector de l'IDS : {e}")
            import traceback
            logger.error(traceback.format_exc())
        
    def _analyze_event(self, ip: str, current_score: int | float, event_timestamp: float | None = None):
        current_time = event_timestamp if event_timestamp is not None else time.time()
        if ip in self.ip_event_history:
            events = self.ip_event_history[ip].get('events', {})
            self.ip_event_history[ip]['events'] = [
                event for event in events
                if (current_time - event['timestamp']) <= self.EVENT_WINDOW
            ]

        new_event = {
            'timestamp': current_time,
            'score': current_score,
        }

        if ip not in self.ip_event_history:
            self.ip_event_history[ip] = {
                'events': [new_event],
                'escalation_level': 0,
                'last_update': current_time
            }
            return 1.0

        self.ip_event_history[ip]['events'].append(new_event)
        self.ip_event_history[ip]['last_update'] = current_time
        events = self.ip_event_history[ip]['events']

        num_events = len(events)
        avg_score = sum(e['score'] for e in events) / num_events
        max_score = max(e['score'] for e in events)
        scores = [e['score'] for e in events]

        multiplier = 1.0

        if num_events == 1:
            return 1.0

        if num_events <= 2:
            if max_score > avg_score * 1.5:
                multiplier = 1.3
            else:
                multiplier = 1.1

        elif num_events == 3:
            if max_score > avg_score * 1.8:
                multiplier = 1.6
            else:
                multiplier = 1.2

        elif num_events <= 5:
            is_increasing = all(scores[i] <= scores[i + 1] for i in range(len(scores) - 1))
            multiplier = 2.0 if is_increasing else 1.5

        elif num_events < 10:
            is_increasing = all(scores[i] <= scores[i + 1] for i in range(len(scores) - 1))
            multiplier = 2.3 if is_increasing else 1.8

        else:
            multiplier = 2.5
            logger.print(f"🔴🔴🔴 ATTAQUE COORDONNÉE: {ip} ({num_events} anomalies)")

        return multiplier

    def detect_beaconing(self, ip):
        if ip not in self.ip_data:
            return 0
        events = self.ip_event_history.get(ip, {}).get('events', [])
        if len(events) < 5:
            return 0

        recent_events = events[-20:]
        timestamps = [e['timestamp'] for e in recent_events]

        intervals = np.array([timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)])
        intervals = intervals[intervals > 0]
        if intervals.shape[0] < 3:
            return 0

        mean_interval = max(intervals.mean(), 1e-8)
        cv = intervals.std() / mean_interval
        beaconing_score = 0
        detection_details = []

        if 1 <= mean_interval <= 300:
            if cv < 0.1:
                beaconing_score += 60
                detection_details.append(f"RAPIDE: intervalle={mean_interval:.1f}s, CV={cv:.3f}")
            elif cv < 0.2:
                beaconing_score += 40
                detection_details.append(f"RAPIDE MODÉRÉ: intervalle={mean_interval:.1f}s, CV={cv:.3f}")
            elif cv < 0.3:
                beaconing_score += 20
                detection_details.append(f"RAPIDE LÉGER: intervalle={mean_interval:.1f}s, CV={cv:.3f}")

        elif 300 < mean_interval <= 3600:
            if cv < 0.15:
                beaconing_score += 50
                detection_details.append(f"MOYEN: intervalle={mean_interval/60:.1f}min, CV={cv:.3f}")
            elif cv < 0.25:
                beaconing_score += 30
                detection_details.append(f"MOYEN MODÉRÉ: intervalle={mean_interval/60:.1f}min, CV={cv:.3f}")

        elif 3600 < mean_interval <= 86400:
            if cv < 0.1:
                beaconing_score += 30
                detection_details.append(f"LENT: intervalle={mean_interval/3600:.1f}h, CV={cv:.3f}")

        if len(intervals) >= 4:
            jitter = np.abs(intervals[1:] - intervals[:-1])
            mean_jitter = max(jitter.mean(), 1e-8)
            if mean_interval > 0:
                jitter_ratio = mean_jitter / mean_interval
                if jitter_ratio < 0.1:
                    beaconing_score += 15
                    detection_details.append(f"JITTER FAIBLE: ratio={jitter_ratio:.3f}")

        if beaconing_score >= 50:
            logger.print(f"🚨 BEACONING C2 DÉTECTÉ sur {ip}")
            logger.print(f"   Score beaconing : {beaconing_score}")
            for detail in detection_details:
                logger.print(f"   - {detail}")
            logger.print(f"   Total événements analysés : {len(recent_events)}")
            return min(beaconing_score, 100)

        elif beaconing_score >= 30:
            logger.print(f"⚠️ BEACONING POTENTIEL sur {ip} (score={beaconing_score})")
            return beaconing_score

        return 0

    def decide_action(self, score_dangerous: int):
        for level_name, config in THREAT_LEVELS.items():
            min_score, max_score = config['score_range']
            if min_score <= score_dangerous < max_score:
                return {
                    'level': level_name,
                    'action': config['action'],
                    'duration': config.get('duration'),
                    'score': score_dangerous
                }

        return THREAT_LEVELS['log_only']

    def get_list_blocked_ip(self, *args, **kwargs):
        DATA = {}
        if self.ip_data:
            for ip, data in self.ip_data.items():
                if isinstance(data, dict):
                    if "geoloc" not in data:
                        data["geoloc"] = self.GeoLocator.locate(ip)
                    DATA[ip] = data

        return DATA

    def action(self, src, dst, decision: dict, block_input: bool | None = None):
        """
        Applique une action en fonction de la décision de l'IDS/IPS.
        Utilise UNIQUEMENT les règles nftables (pas de tc).
        """
        if any(ip in ('::', '0.0.0.0', '255.255.255.255') or (ip and ip.startswith('ff'))
               for ip in (src, dst) if ip):
            logger.print(f"⚠️ IP spéciale ignorée : src={src}, dst={dst}")
            return

        if block_input is None:
            src_is_local = src in IPS if src else False
            dst_is_local = dst in IPS if dst else False

            if src_is_local and not dst_is_local:
                block_input = False
                direction = "SORTANT"
            else:
                block_input = True
                direction = "ENTRANT"

        else:
            direction = "ENTRANT" if block_input else "SORTANT"

        target_ip = src if src else dst
        if target_ip in self.React.whitelist:
            logger.print(f"✅ {target_ip} - Whitelistée, aucune action")
            return

        action_type = decision.get('action', 'log_only')
        duration = decision.get('duration', 3600)

        if action_type == 'log_only':
            score = decision.get('score', 0)
            logger.print(f"📊 {target_ip} - Score {score} - Surveillance ({direction})")

        elif action_type == 'rate_limit':
            self.React.block(ip=target_ip, rule="rate_limit_data", input=block_input, timeout=duration, unit="s")
            logger.print(f"🐌 {target_ip} - Nombre de connexion limitée ({direction})")
            self.make_blocked(target_ip)

        elif action_type == 'rate_limit_data':
            self.React.block(ip=target_ip, rule="rate_limit_data", input=block_input, timeout=duration, unit="s")
            logger.print(f"🐌 {target_ip} - Bande passante limitée ({direction})")
            if target_ip in self.ip_data:
                logger.print("\n", json.dumps(self.ip_data[target_ip], indent=2, ensure_ascii=False))
            self.make_blocked(target_ip)

        elif action_type == 'block_temp':
            self.React.block(ip=target_ip, rule="drop", input=block_input, timeout=duration, unit="s")
            self.make_blocked(target_ip)
            logger.print(f"🔒 {target_ip} - Bloqué temporairement ({duration}s, {direction})")
            if target_ip in self.ip_data:
                logger.print("\n", json.dumps(self.ip_data[target_ip], indent=2, ensure_ascii=False))

        elif action_type == 'block_perm':
            self.React.block(ip=target_ip, rule="drop", input=block_input, timeout=float("inf"))
            logger.print(f"🚨 {target_ip} - BLOQUÉ DÉFINITIVEMENT ({direction})")
            if target_ip in self.ip_data:
                logger.print("\n", json.dumps(self.ip_data[target_ip], indent=2, ensure_ascii=False))
            self.make_blocked(target_ip)

    async def detect_pkt(
        self,
        pkt,
        pkt_rate: int,
        features: dict | np.ndarray,
        models: dict,
        Model: Models,
        seq_anomaly: bool = False,
        mode: str = 'ids',
        how: str = "all",
        event_timestamp: float | None = None,
    ):
        mode = mode.lower().strip()
        src, dst = self._get_ip(pkt, with_dst=True)
        if any(ip in ('::', '0.0.0.0', '255.255.255.255') or (ip and ip.startswith('ff'))
               for ip in (src, dst) if ip):
            logger.print(f"⚠️ IP spéciale ignorée : src={src}, dst={dst}")
            return 0.0

        target = src if src else dst
        src_is_local = src in IPS if src else False
        dst_is_local = dst in IPS if dst else False
        block_input = False if (src_is_local and not dst_is_local) else True
        if target in self.React.whitelist:
            logger.print("Ip présente dans whitelist !")
            return 0.0

        if not seq_anomaly:
            ia_preds = await self.get_ia_preds_pkt(features, models, Model, how=how)
        else:
            ia_preds = await self.get_ia_preds_seq(features, models, Model, how=how)

        score = self.calculate_ip_score_anomaly(
            ia_preds=ia_preds, pkt=pkt,
            seq_anomaly=seq_anomaly,
            pkt_rate=pkt_rate
        )

        score_dangerous = self.calculate_ip_score_dangerous(target, score)
        multiplier = self._analyze_event(target, score_dangerous, event_timestamp=event_timestamp)

        if multiplier > 1.0:
            score_dangerous_correlated = min(score_dangerous * multiplier, 300)

            logger.print(f"📊 CORRÉLATION DÉTECTÉE: {target} ")
            logger.print(f"Score {score_dangerous:.0f} → {score_dangerous_correlated:.0f} ")
            logger.print(f"(×{multiplier:.1f})")

            score_dangerous = score_dangerous_correlated

        decision = self.decide_action(score_dangerous)
        self.ip_data[target]['decision'] = decision
        self.ip_data[target]['input'] = block_input
        self.ip_data[target]['ip'] = target
        self.ip_data[target]['port'] = self._get_port(pkt)
        self.ip_data[target]['resolution'] = await resolve_hostname(target)

        type_detect = "SÉQUENCE" if seq_anomaly else "PAQUET"

        logger.print(f"[{type_detect}] {target} - Score: {score_dangerous} - {decision.get('level', 'log_only')}")

        self.TextMonitor.update(score_dangerous, action=decision.get('level', 'log_only'), ip=target)

        if mode == 'ips':
            await asyncio.to_thread(self.action, src, dst, decision, block_input=block_input)
        else:
            logger.print(f"[MODE IDS] Aurait exécuté: {decision}")

        t = time.time()
        if t - self.last_save >= self.save_interval:
            self.cleanup_stale_data()
            await asyncio.to_thread(self.save, self.ip_score_dir, self.ip_data)
            self.last_save = time.time()
        return score_dangerous