#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug  7 06:19:46 2026

@author: hounsousamuel

detector.py

AnomalyDetector : orchestre la boucle de détection temps réel
(monitoring Suricata, scoring des paquets/séquences, sauvegardes).
Extrait de detection_module.py.

"""

import os
import json
import time
import dill
import dpkt
import joblib
import atexit
import socket
import asyncio
import threading
import traceback
import numpy as np
import queue as pyqueue
import multiprocessing as mp
from datetime import datetime
from collections import deque
from ids_ips_ia.models.models import Models
from ids_ips_ia.ids_ips_utils.loader import load
from ids_ips_ia.reaction.reaction_module import React
from ids_ips_ia.core.capture import detect_all_ifaces
from ids_ips_ia.ids_ips_utils.logger import get_logger
from ids_ips_ia.ids_ips_utils.mail_sms_sender import Text
from ids_ips_ia.detection.blocked_skip import BlockedSkipper
from ids_ips_ia.detection.anomaly_logger import AnomalyLogger
from ids_ips_ia.core.features_extractor import FeatureExtractor
from ids_ips_ia.ids_ips_utils.real_time_plot import RealTimePLot
from ids_ips_ia.ids_ips_utils.warnings_manager import suppres_warnings
from ids_ips_ia.ids_ips_utils.model_file_validation import validate_model_file
from ids_ips_ia.ids_ips_utils.suricata_integration import Utils, State, IPS # noqa
from ids_ips_ia.memory_managers.shared_memory_packet_manager import MemoryManager
from ids_ips_ia.detection.anomaly_scorer import AnomalyScorer, resolve_hostname
from modules_utils.stop_process import kill_process_group_async as kill_process
from ids_ips_ia.ids_ips_utils.instance_id import INSTANCE_SUFFIX
from ids_ips_ia.config.config_ids import (
    CONFIG, SEUIL_KEY, ANOMALY_CONFIG_KEY, SEQ_LENGTH,
    SEQ_STRIDE, DETECT_BATCH_SIZE, MODEL_ERROR_THRESHOLD
)
suppres_warnings()
logger = get_logger()

BASEDIR = os.path.dirname(os.path.abspath(__file__))
DATADIR = os.path.join(BASEDIR, "data", INSTANCE_SUFFIX)
ANOM_DIR = os.path.join(DATADIR, "anomalies")

os.makedirs(BASEDIR, exist_ok=True)
os.makedirs(DATADIR, exist_ok=True)
os.makedirs(ANOM_DIR, exist_ok=True)

ANOMALY_CONF = CONFIG.CONFIG.get(ANOMALY_CONFIG_KEY, {})
MAX_ANOMALIES = ANOMALY_CONF.get("max_anomalies_per_file", 10000)
ANOMALY_FILE_PREFIX = ANOMALY_CONF.get("anomaly_file_prefix", "anomalies")
ANOMALY_BATCH_SIZE = 256

class AnomalyDetector:
    # Ordre aligné avec le déballage : ae_pkt, if_pkt, lof_pkt, scaler_pkt, ae_seq, cnn_seq, if_seq, lof_seq, scaler_seq
    KEYS = [
        'ae_pkt',      # [0]
        'if_pkt',      # [1]
        'lof_pkt',     # [2]
        'scaler_pkt',  # [3]
        'ae_seq',      # [4]
        'cnn_seq',     # [5]
        'if_seq',      # [6]
        'lof_seq',     # [7]
        'scaler_seq'   # [8]
    ]
    MAX_SYSTEM_ALERTS = 200
    # Profondeur du pipeline = nb de lots que le producteur peut avoir "d'avance" sur le consommateur.
    # 1 = recouvrement complet (1 lot en inférence + 1 lot déjà prêt). Plus grand = plus de latence, pas plus de vitesse.
    PIPELINE_DEPTH = 1
    IDLE_SLEEP_MIN = 0.001      # attente minimale du producteur quand la file amont est vide (s)
    IDLE_SLEEP_MAX = 0.010      # plafond du backoff : latence max ajoutée au 1er paquet après un silence (10 ms)
    
    def __init__(
        self, 
        enable_graph: bool,
        Models_instance: Models,
        queue: pyqueue.Queue | MemoryManager,
        nom: str = 'Admin',
        prenom: str = 'Admin',
        graph: RealTimePLot = None,
        interfaces: list = None,
        whitelist: str = "whitelist.json",
        clear_sets_at_exit: bool = True,
        unlock_at_exit: bool = True,
        mode: str = "ids",
    ):
        self.tasks = []
        if isinstance(interfaces, str):
            interfaces = [interfaces]

        self.q = queue
        self.mod = {}
        self.whitelist = []
        self.interfaces = interfaces or self.detect_all_interfaces()
        self.last_anomalies_queue: deque = deque(maxlen=int(MAX_ANOMALIES) * 3)
        self.anomaly_logger_stats = {}
        # Alertes SYSTEME (≠ alertes d'attaque) : ex. inférence en panne. {id: entrée complète}
        self.system_alerts: dict[str, dict] = {}
        self._system_alerts_lock = threading.Lock()
        self._infer_fail = {s: {"consecutive": 0, "alert_id": None} for s in ("packet", "sequence")}
        
        def after_write(logger: AnomalyLogger, *args, **kwargs):
            self.anomaly_logger_stats = logger.stats()
            return
        
        self.anomaly_logger = AnomalyLogger(
            directory=ANOM_DIR, 
            prefix=ANOMALY_FILE_PREFIX, 
            max_per_file=int(MAX_ANOMALIES),
            on_warning=logger.warning,
            batch_size=ANOMALY_BATCH_SIZE,
            flush_interval=10.0,
            on_write=None,
            after_write=after_write,
        )
        self.React = React(
            whitelist=whitelist,
            clear_sets_at_exit=clear_sets_at_exit,
            unlock_at_exit=unlock_at_exit
        )
        self.whitelist = self.React.whitelist
        self.white_file = self.React.whitelist_filename
        self.skipper = BlockedSkipper(self.React)
        self.pkt_rate_to_plot = deque(maxlen=100000)
        self.seq_reat_to_plot = deque(maxlen=100000)

        self.state = State()
        self.Text = Text(nom=nom, prenom=prenom)
        self.Models = Models_instance
        self.Utils = Utils()
        self.AnomalyScorer = AnomalyScorer(React=self.React, Text=self.Text)
        self.FeatureExtractor = FeatureExtractor()
        self.enable_graphe = enable_graph
        self.log_path = self.Utils.detect_os_and_path()["log"] or f"/var/log/suricata{INSTANCE_SUFFIX}"
        try:
            os.makedirs(self.log_path, exist_ok=True)
        except Exception:
            pass
        self.stop_event = mp.Event()
        self.model_lock = threading.Lock()
        self.current_model_path = ""
        self._monitor_task = None
        self._refit_task = None
        self._pipe_queue = None      # file des lots prêts (créée par detect()), lue par stats()
        
        if enable_graph:
            logger.info('Graphes activées, bonne visualisation !')
            if graph:
                self.graph = graph
                logger.info('graph bien reçue !')
            else:
                self.graph = RealTimePLot()
                self.graph.control()
                logger.info('Graphe bien crée !')
        else:
            logger.info('[ANOMALY_DETECTOR] Graphes descativées !')

        self.monotor_event = asyncio.Event()
        self.save_atexit()
        self._model_refs = None
        self.mode = mode
        self.detect_start_time = None
        self.detect_end_time = None
        self.pkt_proccessed = 0
        self._started_at = time.monotonic()
        # compteurs de la boucle de détection (un seul écrivain : le thread detect) ; lus par stats()
        self.stat_batches = 0        # nb de lots scorés
        self.stat_scored = 0         # nb de paquets scorés (somme des tailles de lots)
        self.stat_last_batch = 0     # taille du dernier lot
        self.stat_sequences = 0      # nb de séquences évaluées
        logger.info()
        logger.info("=" * 60)
        logger.info("🛡️  ANOMALY DETECTOR INITIALISÉ")
        logger.info("=" * 60)
        logger.info(f"   PID              : {os.getpid()}")
        logger.info(f"   Mode             : {self.mode.upper()}")
        logger.info(f"   Interfaces       : {self.interfaces}")
        logger.info(f"   Graphiques       : {'✅ Activés' if enable_graph else '❌ Désactivés'}")
        logger.info(f"   Queue            : {'MemoryManager' if hasattr(self.q, 'name') else 'Queue'}")
        logger.info(f"   Whitelist        : {len(self.whitelist)} IPs")
        logger.info("=" * 60)
        logger.info()

    def _get_last_alerts(self, n: int = 5):
        if isinstance(n, int):
            return list(self.last_anomalies_queue)[-n:]
        return []

    def _add_alert(self, data: dict):
        self.last_anomalies_queue.append(data)
    
    def _get_system_alerts(self, n: int = 50, status: str | None = None) -> list[dict]:
        """Les n dernières alertes système (plus récentes en dernier), filtrables par statut 'open'/'resolved'."""
        if not (isinstance(n, int) and n > 0):
            return []
        
        with self._system_alerts_lock:
            items = [dict(v) for v in self.system_alerts.values()]
        if status:
            items = [a for a in items if a["status"] == status]
        return items[-n:]

    def _track_inference(self, stage: str, scores, n_items: int):
        """
        Suit les échecs d'inférence d'un étage ("packet" | "sequence"). Un lot est en échec si TOUS ses scores
        sont NaN. Au bout de MODEL_ERROR_THRESHOLD échecs consécutifs : UNE entrée complète est ajoutée dans
        `system_alerts` (la détection continue, rien n'est bloqué ni arrêté) ; elle est mise à jour tant que la
        panne dure, puis passée en 'resolved' au premier lot sain.
        """
        st = self._infer_fail[stage]
        now = time.time()
        failed = n_items > 0 and bool(np.isnan(scores).all())
        with self._system_alerts_lock:
            entry = self.system_alerts.get(st["alert_id"]) if st["alert_id"] else None
            if not failed:
                if entry is not None:
                    entry.update(
                        status="resolved", 
                        resolved_at=datetime.fromtimestamp(now).isoformat(timespec="seconds"),
                        resolved_epoch=now
                    )
                st["consecutive"], st["alert_id"] = 0, None
                return
            st["consecutive"] += 1
            err = getattr(self.Models, "last_batch_error", None) or {
                "stage": stage, "type": "NaNScores", "message": "scores tous NaN (features invalides ?)", "at": now
            }
            if entry is not None:
                entry["consecutive_failures"] = st["consecutive"]
                entry["items_unscored"] += n_items
                entry.update(last_failure_at=datetime.fromtimestamp(now).isoformat(timespec="seconds"), last_error=err)
                return
            if st["consecutive"] < MODEL_ERROR_THRESHOLD:
                return
            alert_id = f"sys-{int(now * 1000)}-{stage}"
            iso = datetime.fromtimestamp(now).isoformat(timespec="seconds")
            self.system_alerts[alert_id] = {
                "id": alert_id,
                "type": "model_inference_failure",
                "severity": "critical",
                "status": "open",
                "stage": stage,
                "message": (f"Inférence '{stage}' en échec sur {st['consecutive']} lots consécutifs : "
                            "les éléments concernés ne sont PAS analysés par l'IA (ni alerte IA, ni blocage)."),
                "threshold": MODEL_ERROR_THRESHOLD,
                "consecutive_failures": st["consecutive"],
                "items_unscored": n_items,
                "detection_continues": True,
                "mode": self.mode,
                "opened_at": iso, "opened_epoch": now,
                "last_failure_at": iso,
                "resolved_at": None, "resolved_epoch": None,
                "last_error": err,
            }
            st["alert_id"] = alert_id
            while len(self.system_alerts) > self.MAX_SYSTEM_ALERTS:            # borne mémoire : on purge les plus anciennes
                self.system_alerts.pop(next(iter(self.system_alerts)))
        logger.info(f"🚨 ALERTE SYSTEME {alert_id} : inférence '{stage}' en panne ({st['consecutive']} échecs) - {err}")

    def _change_mode(self, mode):
        mode = str(mode).lower().strip()
        if mode in ("ids", "ips"):
            self.mode = mode
        
    def _update_model_refs(self, with_lock: bool = True):
        """Crée un NOUVEAU tuple immuable contenant toutes les références."""
        ae_pkt = self.mod.get('ae_pkt')
        if_pkt = self.mod.get('if_pkt')
        lof_pkt = self.mod.get('lof_pkt')
        scaler_pkt = self.mod.get('scaler_pkt')
        ae_seq = self.mod.get('ae_seq')
        cnn_seq = self.mod.get('cnn_seq')
        if_seq = self.mod.get('if_seq')
        lof_seq = self.mod.get('lof_seq')
        scaler_seq = self.mod.get('scaler_seq')

        new_refs = (
            ae_pkt, if_pkt, lof_pkt, scaler_pkt,
            ae_seq, cnn_seq, if_seq, lof_seq, scaler_seq
        )

        if with_lock:
            with self.model_lock:
                self._model_refs = new_refs
        else:
            self._model_refs = new_refs

        logger.info("✅ Références modèles mises à jour")

    def _stop(self):
        self.stop_event.set()
        self.anomaly_logger.close()

    def stop(self, *args, **kwargs):
        self._stop()
    
    def stats(self) -> dict:
        """Instantané des compteurs du détecteur (lecture seule, sans verrou : ce sont des entiers)."""
        up = time.monotonic() - self._started_at
        qsize = self.q.qsize() if hasattr(self.q, "qsize") else None
        qmax = getattr(self.q, "maxsize", 0) or 0
        return {
            "mode": self.mode,
            "uptime_s": round(up, 1),
            "packets_processed": self.pkt_proccessed,
            "processed_per_s": round(self.pkt_proccessed / up, 1) if up > 0 else 0.0,
            "queue": {
                "size": qsize, "max": qmax or None,
                "fill_pct": round(100 * qsize / qmax, 1) if qmax and qsize is not None else None,
            },
            "batches": self.stat_batches,
            "last_batch_size": self.stat_last_batch,
            "avg_batch_size": round(self.stat_scored / self.stat_batches, 1) if self.stat_batches else 0.0,
            "sequences_evaluated": self.stat_sequences,
            # ready_batches toujours = depth  -> l'inférence est le goulot ; toujours 0 -> c'est la préparation (capture/features)
            "pipeline": {
                "depth": self.PIPELINE_DEPTH,
                "ready_batches": pq.qsize() if (pq := getattr(self, "_pipe_queue", None)) is not None else 0,
            },
            "config": {"seq_length": SEQ_LENGTH, "seq_stride": SEQ_STRIDE, "batch_size": DETECT_BATCH_SIZE},
            "anomalies_in_memory": len(self.last_anomalies_queue),
            "inference": {
                stage: {"consecutive_failures": st["consecutive"], "failing": st["alert_id"] is not None}
                for stage, st in self._infer_fail.items()
            },
            "system_alerts_open": len(self._get_system_alerts(self.MAX_SYSTEM_ALERTS, "open")),
        }

    def save(self, filename, value):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(value, f, indent=4, ensure_ascii=False)
            logger.info('Fichier sauvegarder dans : ', filename)
            os.chmod(filename, 0o644)
            return True

        except Exception as e:
            logger.error("Erreur lord de la sauvegarde du fichier historique : ", e)
            return False

    def load_whitelist(self, filename):
        try:
            data = []
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
            logger.info('Fichier chargé depuis : ', filename)
            os.chmod(filename, 0o644)

        except Exception as e:
            logger.error("Erreur lord du chargement du fichier de whitelist : ", e)

        self.whitelist = data

    def save_atexit(self):
        def _save():
            self.save(self.white_file, self.whitelist)
            logger.info('Fin sauvegarde !')
        atexit.register(_save)

    def load_anomalies(self):
        try:
            files = sorted(
                [f for f in os.listdir(ANOM_DIR)
                 if f.startswith(ANOMALY_FILE_PREFIX) and f.endswith(".pkl")]
            )

            if files:
                path = os.path.join(ANOM_DIR, files[-1])
                try:
                    return joblib.load(path), path
                except Exception:
                    pass

            first_file = os.path.join(ANOM_DIR, f"{ANOMALY_FILE_PREFIX}_0.pkl")
            joblib.dump([], first_file)
            return [], first_file

        except Exception as e:
            logger.error(f"Erreur load_anomalies : {e}")
            first_file = os.path.join(ANOM_DIR, f"{ANOMALY_FILE_PREFIX}_0.pkl")

            os.makedirs(os.path.dirname(first_file), exist_ok=True)
            joblib.dump([], first_file)
            return [], first_file

    @staticmethod
    def detect_all_interfaces():
        """Détecte TOUTES les interfaces sauf loopback"""
        return detect_all_ifaces()

    def _to_alert_entry(self, array, pred, source):
        return {
            "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "prediction": pred,
            "source": source,
            "seq_length": len(array),
            "features": array.tolist()
        }
    
    def log_anomaly(self, array, pred, source="IA"):
        self.anomaly_logger.log(array, pred, source)
        
    # def log_anomaly(self, array, pred, source="IA"):
    #     try:
    #         anomaly_entry = self._to_alert_entry(array, pred, source)
    #         self.anomalies.append(anomaly_entry)
    #         if len(self.anomalies) >= int(MAX_ANOMALIES):
    #             self.current_file = self.next_anomaly_file()
    #             joblib.dump(self.anomalies, self.current_file)
    #             self.anomalies = []
    #         else:
    #             joblib.dump(self.anomalies, self.current_file)

    #     except Exception as e:
    #         logger.error(f"Erreur log_anomaly : {e}")

    def _is_ipv6(self, ip_str):
        """Détecte si une string est une IPv6 valide"""
        try:
            socket.inet_pton(socket.AF_INET6, ip_str)
            return True
        except (OSError, ValueError):
            return False

    async def monitor_suricata_alerts(
        self,
        eve_file: str | None = None,
        verbose: bool = False,
        ready_event: threading.Event | None = None,
    ):
        """Monitor les alertes Suricata"""
        if eve_file is None:
            suricata_paths = self.Utils.get_suricata_paths()
            eve_file = suricata_paths['eve_file']

        if not os.path.exists(eve_file):
            logger.info(f"⚠️ Fichier alert introuvable: {eve_file}")
            logger.info("Création du fichier...")
            os.makedirs(os.path.dirname(eve_file), exist_ok=True)
            open(eve_file, 'a').close()

        # Prendre la taille en octet (offset pour tail)
        start_offset = os.path.getsize(eve_file)
        logger.info(f"📡 Monitoring Suricata alerts: {eve_file} (offset {start_offset})")

        tail = await asyncio.create_subprocess_exec(
            "sudo", "tail", "-c", f"+{start_offset + 1}", "-F", eve_file,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,  # crée un nouveau groupe de process (sudo + tail dedans)
        )

        if ready_event is not None:
            ready_event.set()
            logger.info("✅ Monitoring attaché, prêt à capter les alertes")

        error_count = 0
        try:
            while not self.monotor_event.is_set():
                line = await tail.stdout.readline()
                if not line:
                    break

                decoded = line.decode(errors="ignore").strip()
                alert = self.Utils.parse_eve_line(decoded)
                if not alert:
                    await asyncio.sleep(0.001)
                    continue

                try:
                    if alert.get("event_type") not in ("alert", "anomaly", "drop"):
                        await asyncio.sleep(0.001)
                        continue
                    eth = self._create_fake_packet_from_alert(alert)

                    if not self._validate_fake_packet(eth):
                        if verbose:
                            logger.info(f"⚠️ Paquet invalide ignoré : {alert['src_ip']} → {alert['dst_ip']}")
                        continue

                    if verbose:
                        proto = "IPv4" if eth.type == dpkt.ethernet.ETH_TYPE_IP else "IPv6"
                        logger.info(f"[SURICATA] {alert['message']} | "
                                      f"{alert['src_ip']}:{alert['src_port']} → "
                                      f"{alert['dst_ip']}:{alert['dst_port']} ({proto})")

                    self.q.put_nowait((eth, alert))

                except Exception as e:
                    error_count += 1
                    if error_count <= 5 or verbose:
                        logger.info(f"⚠️ Erreur création paquet : {e}")
                        if verbose:
                            logger.error(traceback.format_exc())

        except asyncio.CancelledError:
            raise

        finally:
            await kill_process(tail, "tail")

    def _validate_fake_packet(self, eth):
        """Valide qu'un paquet fake est exploitable"""
        try:
            if not isinstance(eth, dpkt.ethernet.Ethernet):
                return False

            ip = eth.data

            if isinstance(ip, dpkt.ip.IP):
                if ip.src == b'\x00\x00\x00\x00' or ip.dst == b'\x00\x00\x00\x00':
                    return False
                return True

            elif isinstance(ip, dpkt.ip6.IP6):
                zero_ipv6 = b'\x00' * 16
                if ip.src == zero_ipv6 or ip.dst == zero_ipv6:
                    return False
                return True

            else:
                return False

        except Exception:
            return False

    def _create_fake_packet_from_alert(self, alert):
        """
        Crée un paquet dpkt.ethernet.Ethernet depuis une alerte Snort
        Détection IPv4/IPv6 robuste + validation
        """
        eth = dpkt.ethernet.Ethernet()
        eth.fake = True
        eth.src = b'\x00\x11\x22\x33\x44\x55'
        eth.dst = b'\xff\xff\xff\xff\xff\xff'

        src_ip_str = alert['src_ip']
        dst_ip_str = alert['dst_ip']
        src_port = int(alert.get('src_port', 0))
        dst_port = int(alert.get('dst_port', 0))
        protocol = alert.get('protocol', 'TCP').upper()

        is_ipv6 = self._is_ipv6(src_ip_str) or self._is_ipv6(dst_ip_str)

        if not is_ipv6:  # IPv4
            eth.type = dpkt.ethernet.ETH_TYPE_IP

            ip_pkt = dpkt.ip.IP()
            ip_pkt.v = 4
            ip_pkt.hl = 5
            ip_pkt.ttl = 64

            try:
                ip_pkt.src = socket.inet_aton(src_ip_str)
                ip_pkt.dst = socket.inet_aton(dst_ip_str)
            except OSError as e:
                logger.error(f"⚠️ IP invalide: {src_ip_str} / {dst_ip_str} : {e}")
                ip_pkt.src = socket.inet_aton("0.0.0.0")
                ip_pkt.dst = socket.inet_aton("0.0.0.0")

            if protocol == 'TCP' or src_port > 0 or dst_port > 0:
                ip_pkt.p = dpkt.ip.IP_PROTO_TCP

                tcp_pkt = dpkt.tcp.TCP()
                tcp_pkt.sport = src_port
                tcp_pkt.dport = dst_port
                tcp_pkt.flags = dpkt.tcp.TH_SYN
                tcp_pkt.seq = 0
                tcp_pkt.ack = 0
                tcp_pkt.win = 65535
                tcp_pkt.off = 5

                ip_pkt.data = tcp_pkt

            elif protocol == 'UDP':
                ip_pkt.p = dpkt.ip.IP_PROTO_UDP

                udp_pkt = dpkt.udp.UDP()
                udp_pkt.sport = src_port
                udp_pkt.dport = dst_port
                udp_pkt.ulen = 8

                ip_pkt.data = udp_pkt

            elif protocol == 'ICMP':
                ip_pkt.p = dpkt.ip.IP_PROTO_ICMP

                icmp_pkt = dpkt.icmp.ICMP()
                icmp_pkt.type = 8
                icmp_pkt.code = 0

                ip_pkt.data = icmp_pkt

            else:
                ip_pkt.p = dpkt.ip.IP_PROTO_TCP
                tcp_pkt = dpkt.tcp.TCP()
                tcp_pkt.sport = 0
                tcp_pkt.dport = 0
                ip_pkt.data = tcp_pkt

            ip_pkt.len = len(ip_pkt)
            eth.data = ip_pkt

        else:  # IPv6
            eth.type = dpkt.ethernet.ETH_TYPE_IP6

            ip6_pkt = dpkt.ip6.IP6()
            ip6_pkt.v = 6
            ip6_pkt.hlim = 64

            try:
                ip6_pkt.src = socket.inet_pton(socket.AF_INET6, src_ip_str)
                ip6_pkt.dst = socket.inet_pton(socket.AF_INET6, dst_ip_str)
            except OSError as e:
                logger.error(f"⚠️ IPv6 invalide: {src_ip_str} / {dst_ip_str} : {e}")
                ip6_pkt.src = socket.inet_pton(socket.AF_INET6, "::")
                ip6_pkt.dst = socket.inet_pton(socket.AF_INET6, "::")

            if protocol == 'TCP' or src_port > 0 or dst_port > 0:
                ip6_pkt.nxt = dpkt.ip.IP_PROTO_TCP

                tcp_pkt = dpkt.tcp.TCP()
                tcp_pkt.sport = src_port
                tcp_pkt.dport = dst_port
                tcp_pkt.flags = dpkt.tcp.TH_SYN
                tcp_pkt.seq = 0
                tcp_pkt.ack = 0
                tcp_pkt.win = 65535
                tcp_pkt.off = 5

                ip6_pkt.data = tcp_pkt

            elif protocol == 'UDP':
                ip6_pkt.nxt = dpkt.ip.IP_PROTO_UDP

                udp_pkt = dpkt.udp.UDP()
                udp_pkt.sport = src_port
                udp_pkt.dport = dst_port
                udp_pkt.ulen = 8

                ip6_pkt.data = udp_pkt

            elif protocol == 'ICMP':
                ip6_pkt.nxt = 58
                ip6_pkt.data = b'\x80\x00\x00\x00\x00\x00\x00\x00'

            else:
                ip6_pkt.nxt = dpkt.ip.IP_PROTO_TCP
                tcp_pkt = dpkt.tcp.TCP()
                tcp_pkt.sport = 0
                tcp_pkt.dport = 0
                ip6_pkt.data = tcp_pkt

            ip6_pkt.plen = len(ip6_pkt.data)
            eth.data = ip6_pkt

        eth.ts = time.time()

        return eth
    
    def _load_new_model(self, model_path: str):
        """
        Lit + valide + préchauffe le nouveau modèle. Opération LOURDE et bloquante : toujours appelée via asyncio.to_thread
        et JAMAIS sous `model_lock` (sinon la boucle async serait gelée pendant tout le chargement).
        Retourne le modèle, ou None s'il est invalide.
        """
        with open(model_path, "rb") as f:
            new_mod = dill.load(f)
        if not validate_model_file(new_mod):
            return None
        # Préchauffage XLA du modèle NEUF pendant que l'ancien sert encore : l'échange ne coûtera plus de pic.
        # Un échec de préchauffage ne bloque PAS le rechargement (le modèle est valide, il sera juste lent au 1er lot).
        try:
            info = self.Models.warm_up(
                new_mod, max_pkt_batch=DETECT_BATCH_SIZE,
                max_seq_batch=DETECT_BATCH_SIZE // SEQ_STRIDE + 1, stop_event=self.stop_event,
            )
            logger.info(
                f"🔥 Préchauffage terminé en {info['seconds']} s "
                f"({info['pkt_buckets']} tailles paquet, {info['seq_buckets']} tailles séquence)"
             )
        except Exception as e:
            logger.error(f"⚠️ Préchauffage échoué ({type(e).__name__}: {e}) : rechargement quand même")
        return new_mod

    async def reload_model_if_needed(self, new_model_available: mp.Event(), refit_delay: int, model_path: str) -> bool:
        """
        Vérifie si un nouveau modèle est disponible et le recharge.
        1) chargement + validation dans un thread (long)  2) échange des références sous le lock (quelques µs).
        """
        while not self.stop_event.is_set():
            await asyncio.sleep(int(refit_delay * 0.75))
            if not new_model_available.is_set():
                continue
            try:
                logger.info("🔄 Rechargement du nouveau modèle...")

                new_mod = await asyncio.to_thread(self._load_new_model, model_path)
                if new_mod is None:
                    continue              # invalide : on garde l'ancien modèle, le flag reste levé (comme avant)

                with self.model_lock:     # section critique minuscule : on échange seulement les références
                    self.mod = new_mod
                    self._update_model_refs(with_lock=False)

                new_model_available.clear()

                logger.info("✅ Modèle rechargé avec succès !")

            except Exception as e:
                logger.error(f"❌ Erreur rechargement modèle : {e}")
                

    async def stop_refit_task(self):
        if self._refit_task is not None:
            if not self._refit_task.done():
                self._refit_task.cancel()
                try:
                    await self._refit_task
                except asyncio.CancelledError:
                    pass
            
            self._refit_task = None
        return
    
    async def stop_monitor_task(self):
        if self._monitor_task is not None and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            
            self._monitor_task = None
        return
    
    def _drain_entries(self, max_items: int) -> list:
        """
        Vide la file SANS attendre, jusqu'à `max_items` éléments.

        Retourne une liste ordonnée de `(pkt, alert, from_alert)` :
          - paquet capturé : (pkt, None, False)
          - paquet issu d'une alerte Suricata (fake_pkt, alert) : (fake_pkt, alert, True)
        Un élément illisible est loggué puis ignoré, il ne fait pas perdre le reste du lot.
        """
        entries = []
        while len(entries) < max_items:  # and not self.stop_event.is_set():
            try:
                item = self.q.get_nowait()
            except pyqueue.Empty:
                break
            try:
                if self.skipper.should_skip(item):
                    # Penser a remonter les ip blocké sinon ils pourront pas évoluer vers block_perm
                    continue
                self.pkt_proccessed += 1
                if isinstance(item, tuple) and isinstance(item[1], bytes):
                    ts, raw_bytes = item
                    pkt = dpkt.ethernet.Ethernet(raw_bytes)
                    pkt.ts = ts
                    item = pkt
                if isinstance(item, tuple):
                    fake_pkt, alert = item
                    entries.append((fake_pkt, alert, True))
                else:
                    entries.append((item, None, False))
            except Exception as e:
                logger.error(f"Erreur lecture paquet : {e}")
        return entries

    async def detect(
        self, path: str,
        combination_mode: str = "or",
        packet_anomaly: float = 0.4,
        verbose: bool = True,
        new_model_available: mp.Event = None,
        refit_delay: int = None,
        model_path: str = None
    ):
        try:
            mod = dill.loads(load(path))
            info = self.Models.warm_up(
                mod, max_pkt_batch=DETECT_BATCH_SIZE,
                max_seq_batch=(DETECT_BATCH_SIZE // SEQ_STRIDE) + 1, stop_event=self.stop_event,
            )
            logger.info(
                f"🔥 Préchauffage terminé en {info['seconds']} s "
                f"({info['pkt_buckets']} tailles paquet, {info['seq_buckets']} tailles séquence)"
             )
            self.current_model_path = path
            with self.model_lock:
                self.mod = mod

            self._update_model_refs(with_lock=True)
        except Exception as e:
            logger.error(f"Erreur chargement modèle : {e}")
            return

        logger.info()
        logger.info("=" * 60)
        logger.info("🚀 DÉMARRAGE DE LA DÉTECTION TEMPS RÉEL")
        logger.info("=" * 60)
        logger.info(f"   PID              : {os.getpid()}")
        logger.info(f"   Modèle           : {os.path.basename(path)}")
        logger.info(f"   Mode combinaison : {combination_mode}")
        logger.info(f"   Seuil anomalie   : {packet_anomaly}")
        logger.info(f"   Verbose          : {verbose}")
        logger.info(f"   Batch max        : {DETECT_BATCH_SIZE} paquets")
        logger.info(f"   Stride séquence  : {SEQ_STRIDE} paquets (fenêtre = {SEQ_LENGTH})")
        logger.info("=" * 60)
        logger.info()
        self.detect_start_time = time.time()

        if any(p is None for p in (new_model_available, refit_delay, model_path)):
            refit_task = None
        else:
            refit_task = asyncio.create_task(self.reload_model_if_needed(new_model_available, refit_delay, model_path))
        
        self._refit_task = refit_task

        # ================= PIPELINE : capture || traitement =================
        #
        #  file amont --> [ PRODUCTEUR ] --> ready (asyncio.Queue) --> [ CONSOMMATEUR ] --> alertes
        #                  drain + features        lots prêts            modèles + décisions
        #
        # Pendant que le consommateur attend l'inférence (dans un thread), le producteur prépare déjà
        # le lot suivant. `slots` compte les places libres dans `ready` : le producteur en RÉSERVE une
        # AVANT de drainer. File pleine => il n'a encore rien vidé, les paquets restent dans la file
        # amont (c'est elle qui encaisse la pression) et le prochain lot sera aussi gros que possible.
        self._bg_tasks = set()            # références fortes des tâches de fond (voir _spawn_bg)
        ready: asyncio.Queue = asyncio.Queue(maxsize=self.PIPELINE_DEPTH)
        slots = asyncio.Semaphore(self.PIPELINE_DEPTH)
        self._pipe_queue = ready          # exposé dans stats() pour voir où est le goulot

        producer = asyncio.create_task(self._detect_producer(ready, slots), name=f"detect-producer##{INSTANCE_SUFFIX}")
        consumer = asyncio.create_task(
            self._detect_consumer(ready, slots, combination_mode, packet_anomaly, verbose),
            name=f"detect-consumer##{INSTANCE_SUFFIX}",
        )

        try:
            # fin normale : stop_event -> le producteur envoie None -> le consommateur finit ses lots puis s'arrête.
            # Si UNE des deux tâches plante, gather lève l'erreur ici et le `finally` annule l'autre.
            await asyncio.gather(producer, consumer)

        except KeyboardInterrupt:
            if verbose:
                logger.info("\n[INFO] Détection interrompue")

        except Exception as e:
            logger.error(f"Erreur pipeline détection : {e}")
            logger.error(traceback.format_exc())

        finally:
            for t in (producer, consumer):
                t.cancel()                # sans effet si la tâche est déjà terminée
            await asyncio.gather(producer, consumer, return_exceptions=True)
            self._pipe_queue = None
            if self._bg_tasks:                                  # tâches de fond encore en vol : on les annule proprement
                for t in list(self._bg_tasks):
                    t.cancel()
                await asyncio.gather(*list(self._bg_tasks), return_exceptions=True)

            self.detect_end_time = time.time()

            await self.stop_monitor_task()

            if refit_task:
                await self.stop_refit_task()

            self.anomaly_logger.close()
            self.stop()

    def _spawn_bg(self, coro):
        """
        Lance une tâche « tir et oubli » EN GARDANT UNE RÉFÉRENCE FORTE.
        La boucle asyncio ne garde que des références faibles aux tâches : sans cet ensemble, une tâche non attendue
        peut être ramassée par le garbage collector avant d'avoir fini (documenté dans la doc de create_task).
        """
        t = asyncio.create_task(coro)
        self._bg_tasks.add(t)
        t.add_done_callback(self._bg_tasks.discard)
        return t

    async def _detect_producer(self, ready: asyncio.Queue, slots: asyncio.Semaphore):
        """
        ÉTAPE 1 du pipeline : file amont -> drain -> skipper -> features, puis dépose le lot dans `ready`.

        N'utilise AUCUNE prédiction : c'est ce qui lui permet de travailler "en avance" sur le consommateur.
        """
        idle = self.IDLE_SLEEP_MIN                      # attente au repos : double à chaque tour vide (1 -> 10 ms)
        while not self.stop_event.is_set():
            await slots.acquire()                       # 1) réserver une place AVANT de drainer (attend si pleine)
            sent = False
            try:
                entries = self._drain_entries(DETECT_BATCH_SIZE)        # 2) vider la file amont d'un coup

                batch, feats = [], []                                   # 3) features, ordre d'arrivée conservé
                for entry in entries:
                    try:
                        feats.append(self.FeatureExtractor.extract_pack_features(entry[0]))
                        batch.append(entry)
                    except Exception as e:
                        logger.error(f"Erreur extraction features : {e}")

                if batch:
                    ready.put_nowait((batch, feats))                    # 4) ne bloque jamais : la place est réservée
                    sent = True
            except Exception as e:
                logger.error(f"Erreur producteur détection : {e}")
                logger.error(traceback.format_exc())

            if sent:
                idle = self.IDLE_SLEEP_MIN              # du trafic : on repart à la réactivité maximale
            else:                        # repos (file amont vide) ou lot entièrement en erreur : on rend la place
                slots.release()
                await asyncio.sleep(idle)
                idle = min(idle * 2, self.IDLE_SLEEP_MAX)   # backoff : moins de réveils (et de GIL) quand rien n'arrive

        await ready.put(None)            # fin normale : signale au consommateur qu'il n'y aura plus de lots

    async def _detect_consumer(
        self, ready: asyncio.Queue, slots: asyncio.Semaphore,
        combination_mode: str, packet_anomaly: float, verbose: bool,
    ):
        """
        ÉTAPE 2 du pipeline : prend les lots prêts dans l'ordre (FIFO) puis
        modèles (paquets) -> décisions -> fenêtre glissante -> modèles (séquences) -> alertes.

        TOUT l'état qui dépend des prédictions vit ICI et nulle part ailleurs (fenêtre glissante, since_seq,
        compteurs de graphes) : un seul consommateur + FIFO = l'ordre des paquets est exactement le même qu'avant.
        """
        buffer_fea = deque(maxlen=SEQ_LENGTH)
        buffer_pred_pkt = deque(maxlen=SEQ_LENGTH)
        buffer_pkt = deque(maxlen=SEQ_LENGTH)
        pkt_rate = deque(maxlen=SEQ_LENGTH)
        seq_rate = deque(maxlen=SEQ_LENGTH)
        scores_deque = deque(maxlen=SEQ_LENGTH)
        comptes_seq = 0
        comptes_pkt = 0

        how = 'all' if combination_mode == "and" else "any"
        since_seq = 0   # paquets reçus depuis la dernière séquence évaluée (stride)
        
        while True:
            
            item = await ready.get()
            if item is None:             # sentinelle du producteur : plus de lots
                break
            slots.release()              # lot pris -> une place se libère -> le producteur prépare DÉJÀ le suivant

            batch, feats = item
            # références modèles lues PAR LOT : un modèle rechargé est pris en compte dès le lot suivant
            refs = self._model_refs      # UNE seule lecture (tuple immuable) -> cohérent même si un rechargement tombe en même temps
            (ae_pkt, if_pkt, lof_pkt, scaler_pkt,
             ae_seq, cnn_seq, if_seq, lof_seq, scaler_seq) = refs
            _mod = dict(zip(self.KEYS, refs))
            mode = self.mode

            try:
                self.stat_batches += 1
                self.stat_scored += len(batch)
                self.stat_last_batch = len(batch)

                # C) UN SEUL appel modèles pour tout le lot (AE + IF + LOF vectorisés)
                pkt_scores, pkt_ia_preds = await self.Models.apredict_packet_batch(
                    ae_pkt, if_pkt, lof_pkt, scaler_pkt, feats,
                    how=how, method="decision_function", return_pred=True
                )
                thr = CONFIG.CONFIG.get(SEUIL_KEY, {}).get('decision', -0.6)
                self._spawn_bg(
                    asyncio.to_thread(
                        self._track_inference,
                        stage="packet", scores=pkt_scores, n_items=len(batch)
                    )
                )

                # D) logique par paquet (décision, alertes) ; on repère au passage les fenêtres à évaluer
                seq_jobs = []
                for (pkt, alert, from_alert), pkt_fea, score_pkt, ia_pred in zip(batch, feats, pkt_scores, pkt_ia_preds):
                    buffer_pkt.append(pkt)
                    buffer_fea.append(pkt_fea)
                    unknown = bool(np.isnan(score_pkt))     # inférence en échec : ni anomalie ni "normal certifié"
                    pkt_pred = 1 if unknown else (-1 if score_pkt < thr else 1)
                    pkt_ia = None if unknown else {"decision_function": float(score_pkt), "predict": int(ia_pred)}
                    buffer_pred_pkt.append(pkt_pred)
                    since_seq += 1

                    if from_alert:   # voie Suricata : paquet fabriqué depuis une alerte (fake_pkt, alert)
                        if combination_mode == "or":
                            pkt_combined_pred = -1 if (pkt_pred == -1 or alert) else 1
                        elif combination_mode == "and":
                            pkt_combined_pred = -1 if (pkt_pred == -1 and alert) else 1
                        elif combination_mode == "weighted":
                            ia_score = 1 if pkt_pred == 1 else 0
                            snort_score = 1 if not alert else 0
                            w_score = 0.6 * ia_score + 0.4 * snort_score
                            pkt_combined_pred = -1 if w_score < 0.5 else 1
                        else:
                            pkt_combined_pred = -1 if (pkt_pred == -1 and alert) else 1

                        if pkt_combined_pred == -1:
                            pkt_rate.append(1)
                            scores = await self.AnomalyScorer.detect_pkt(
                                pkt=pkt, seq_anomaly=False, models=_mod, Model=self.Models, mode=mode,
                                pkt_rate=buffer_pred_pkt.count(-1) / SEQ_LENGTH, features=pkt_fea, how=how,
                                event_timestamp=alert.get("eve_timestamp"),
                                ia_preds=pkt_ia
                            )
                            if self.enable_graphe:
                                scores_deque.append(scores)
                                self.graph.add_data3(scores)

                            source = "Combined" if pkt_pred == -1 and alert else "Snort" if alert else "IA"
                            if verbose:
                                scr_ip_resolution = await resolve_hostname(alert['src_ip'])
                                logger.info(f"[SNORT+MODELE] Anomalie confirmée pour {alert['message']} (IP: {alert['src_ip']}) --> ({scr_ip_resolution})")

                            self.log_anomaly(pkt_fea, pkt_combined_pred, source=source)
                            self._add_alert(
                                {
                                    **self._to_alert_entry(pkt_fea, pkt_combined_pred, source=source),
                                    **dict(zip(("src_ip", "dst_ip"), tuple(self.AnomalyScorer._get_ip(pkt, with_dst=True))))
                                }
                            )
                    elif pkt_pred == -1:
                        pkt_rate.append(1)
                        scores = await self.AnomalyScorer.detect_pkt(
                            pkt=pkt, seq_anomaly=None, models=_mod, Model=self.Models, mode=mode,
                            pkt_rate=buffer_pred_pkt.count(-1) / SEQ_LENGTH, features=pkt_fea, how=how,
                            ia_preds=pkt_ia
                        )
                        if self.enable_graphe:
                            scores_deque.append(scores)
                            self.graph.add_data3(scores)

                        if verbose:
                            logger.info(f"[PAQUET] Anomalie détectée sur un paquet à {datetime.now().strftime('%H:%M:%S')}")

                        self.log_anomaly(pkt_fea, pkt_pred, source="IA")
                        self._add_alert(
                            {
                                **self._to_alert_entry(pkt_fea, pkt_pred, source="IA"),
                                **dict(zip(("src_ip", "dst_ip"), tuple(self.AnomalyScorer._get_ip(pkt, with_dst=True))))
                            }
                        )

                    if self.enable_graphe:
                        num = sum(pkt_rate)
                        if num == SEQ_LENGTH:
                            comptes_pkt += 1

                        if comptes_pkt >= 10:
                            pkt_rate.clear()
                            num = sum(pkt_rate)
                            comptes_pkt = 0

                        self.graph.add_data1(num)

                    # Fenêtre glissante : pleine ET `SEQ_STRIDE` paquets écoulés depuis la dernière évaluation.
                    # (avant : len == SEQ_LENGTH était vrai à CHAQUE paquet -> 4 modèles par paquet)
                    if len(buffer_fea) == SEQ_LENGTH and since_seq >= SEQ_STRIDE:
                        since_seq = 0
                        seq_jobs.append((
                            self.FeatureExtractor.extract_seq_features(np.array(buffer_fea)),
                            pkt,
                            sum(1 for x in buffer_pred_pkt if x == -1) / SEQ_LENGTH,
                        ))

                # E) UN SEUL appel modèles pour toutes les séquences du lot (CNN + AE + IF + LOF)
                if seq_jobs:
                    self.stat_sequences += len(seq_jobs)
                    seq_scores, seq_ia_preds = await self.Models.apredict_sequence_batch(
                        ae_seq, cnn_seq, if_seq, lof_seq, scaler_seq,
                        np.stack([job[0] for job in seq_jobs]),
                        how=how, method="decision_function", return_pred=True
                    )
                    self._spawn_bg(
                        asyncio.to_thread(
                            self._track_inference,
                            stage="sequence", scores=seq_scores, n_items=len(seq_jobs)
                        )
                    )
                    for (seq_fea, last_pkt, prop_anom), score_pred, ia_pred_seq in zip(seq_jobs, seq_scores, seq_ia_preds):
                        seq_unknown = bool(np.isnan(score_pred))
                        pred_seq = 1 if seq_unknown else (-1 if score_pred <= thr else 1)
                        if combination_mode == "or":
                            combined_pred = -1 if (pred_seq == -1 or prop_anom >= packet_anomaly) else 1
                        elif combination_mode == "and":
                            combined_pred = -1 if (pred_seq == -1 and prop_anom >= packet_anomaly) else 1
                        elif combination_mode == "weighted":
                            seq_score = 1 if not pred_seq == -1 else 0
                            w_score = 0.5 * seq_score + 0.5 * (1 - prop_anom)
                            combined_pred = -1 if w_score < 0.5 else 1
                        else:
                            combined_pred = -1 if (pred_seq == -1 and prop_anom >= packet_anomaly) else 1

                        if combined_pred == -1:
                            seq_rate.append(1)
                            await self.AnomalyScorer.detect_pkt(
                                pkt=last_pkt, pkt_rate=prop_anom, features=seq_fea, models=_mod,
                                Model=self.Models, seq_anomaly=True, mode=mode, how=how,
                                ia_preds=None if seq_unknown else {"decision_function": float(score_pred), "predict": int(ia_pred_seq)}
                            )
                            if verbose:
                                logger.info(f"[ALERTE] Anomalie détectée sur la séquence à {datetime.now().strftime('%H:%M:%S')}")
                            self.log_anomaly(seq_fea, combined_pred, source="IA")
                            self._add_alert(
                                {
                                    **self._to_alert_entry(seq_fea, combined_pred, source="IA"),
                                    **dict(zip(("src_ip", "dst_ip"), tuple(self.AnomalyScorer._get_ip(last_pkt, with_dst=True))))
                                }
                            )

                        if verbose:
                            n_anom = round(prop_anom * SEQ_LENGTH)
                            logger.info(f"[SÉQUENCE] {prop_anom} ({n_anom} / {SEQ_LENGTH}) paquets anormaux")
                            if combined_pred != -1:
                                logger.info(f"[OK] Séquence normale à {datetime.now().strftime('%H:%M:%S')}")

                if self.enable_graphe:
                    num = sum(seq_rate)
                    if num == SEQ_LENGTH:
                        comptes_seq += 1

                    if comptes_seq >= 10:
                        seq_rate.clear()
                        scores_deque.clear()
                        num = sum(seq_rate)
                        comptes_seq = 0

                    self.graph.add_data2(num)
                    self.graph.add_data3(sum(scores_deque) / (len(scores_deque) or 1))

            except Exception as e:
                logger.error(f"Erreur détection : {e}")
                logger.error(traceback.format_exc())
                continue

if __name__ == "__main__":
    logger.info("🔍 Vérification de l'intégration de Config...")
    
    # Test 1: La config est-elle chargée ?
    logger.info(f"1. Config chargée : {len(CONFIG.CONFIG)} catégories")
    
    # Test 2: Les modifications sont-elles dynamiques ?
    original_seuil = CONFIG.CONFIG["SEUIL"]["decision"]
    logger.info(f"2. Seuil initial : {original_seuil}")
    
    # Simuler une modification
    result = CONFIG.update("SEUIL", {"decision": -0.5})
    logger.info(f"3. Modification : {result['success']}")
    logger.info(f"4. Nouveau seuil : {CONFIG.CONFIG['SEUIL']['decision']}")
    
    # Test 3: Vérifier l'accès depuis AnomalyScorer
    test_scorer = AnomalyScorer(React=None, Text=None)
    logger.info(f"5. Ports critiques chargés : {len(test_scorer.critical_port)}")
    
    logger.info("\n✅ Intégration Config : OK !")