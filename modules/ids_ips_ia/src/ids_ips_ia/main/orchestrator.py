#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug  7 07:17:06 2026

@author: hounsousamuel

Cœur métier : la classe IDS_IPS (cycle de vie du détecteur, apprentissage,
détection, cleanup).

L'état serveur partagé (server, TOKEN, close_api, start, stop) vit dans
server_state.py, pas ici — voir ce fichier pour le pourquoi.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import threading
import time
import queue
import asyncio
import traceback
import multiprocessing as mp
import dill
from datetime import datetime
from uuid import uuid4
from typing import Optional

from ids_ips_ia.core.capture import collect_and_process, detect_all_ifaces, Capture
from ids_ips_ia.models.models import Models
from ids_ips_ia.models.config import MODEL_DIR
from ids_ips_ia.detection.detection_module import AnomalyDetector
from ids_ips_ia.ids_ips_utils.real_time_plot import RealTimePLot
from ids_ips_ia.ids_ips_utils.suricata_integration import Utils, state
from ids_ips_ia.ids_ips_utils.signal_manager import signal_manager
from ids_ips_ia.ids_ips_utils.model_file_validation import validate_model_file
from ids_ips_ia.refit_system.refit_system import ModelRefitMonitor
from ids_ips_ia.refit_system.refit_queue import RefitQueue
from ids_ips_ia.ids_ips_utils.logger import get_logger
from ids_ips_ia.ids_ips_utils.loader import save
from ids_ips_ia.config.config_ids import (
    GLOBAL_CONFIG as CONFIG, GRAPH,
    CAPTURE_FILENAME, ADD_DATA_TO_CAPTURE_PATH, FILTER,
)
from modules_utils.loop_utils import _run_async
from ids_ips_ia.ids_ips_utils.signal_manager import ignore_termination_signals
from ids_ips_ia.main.server_state import close_api

try:
    mp.set_start_method('spawn')
except RuntimeError:
    pass

logger = get_logger()

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

SEQ_LENGTH = 60
DEFAULT_DURATION = 3600 * 7 * 24
DEFAULT_SAVE_INTERVAL = 36000
DEFAULT_ANOMALY_DIR = "anomalies"
_dir_ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(_dir_, exist_ok=True)

_lock = threading.Lock()

if GRAPH:
    graph = RealTimePLot()
else:
    graph = None


# =============================================================================
# CLASSE IDS_IPS
# =============================================================================
def build_ifaces(ifaces: str | None | list) -> list[str]:
    print('BUILD', ifaces)
    if not ifaces:
        return detect_all_ifaces()

    if isinstance(ifaces, str):
        if ifaces in ("all", "none"):
            return detect_all_ifaces()
        else:
            return [ifaces]
    
    return ifaces

            
class IDS_IPS:
    EPOCHS = 1
    BATCH_SIZE = 32

    def __init__(self):
        self.history = {}
        self.stop_event = threading.Event()
        self.monitor_ready = threading.Event()
        self.stop_event_mp = mp.Event()
        self.model = Models(lock=_lock)
        self.Utils = Utils()
        self.session_id = str(uuid4())
        self.RefitQueue = RefitQueue(session_id=self.session_id)
        self.Capture = None
        self.whiltelist = "whitelist.json"
        self.detector = None  # sera assigné dans _detection_coroutine
        self.process = []
        self.threads = []
        self._cleaned = False

    @staticmethod
    def change_mode(mode, detector: Optional[AnomalyDetector] = None):
        mode = str(mode).strip().lower()
        if detector:
            if mode in ("ids", "ips"):
                detector._change_mode(mode)
            return mode == detector.mode
        return False

    def stop(self):
        self.stop_event.set()
        self.stop_event_mp.set()
        if self.detector:
            self.detector.stop()
        
        self._stop_capture()
        self._stop_refit_queue()
        self._stop_suricata_safe()

    def _create_refit_monitor(self):
        self.ModelRefitMonitor = ModelRefitMonitor(
            capture_path=CAPTURE_FILENAME,
            session_id=self.session_id,
            model_path=self.model_file,
            mode=self.mode,
            epochs=self.EPOCHS,
            batch_size=self.BATCH_SIZE,
            refit_delay=7 * 24 * 3600,
            min_new_packets=1_000_000
        )

    def add_ignored_ip(self, ip: str, direction: str = "src") -> bool:
        """Ajoute une IP à la liste des IPs ignorées (src ou dst)."""
        if self.Capture is None:
            return False
        if direction == "src":
            return self.Capture.add_src_ip_to_ignore(ip)
        elif direction == "dst":
            return self.Capture.add_dst_ip_to_ignore(ip)
        return False

    def remove_ignored_ip(self, ip: str, direction: str = "src") -> bool:
        """Retire une IP de la liste des IPs ignorées (src ou dst)."""
        if self.Capture is None:
            return False
        if direction == "src":
            return self.Capture.remove_src_ip_to_ignore(ip)
        elif direction == "dst":
            return self.Capture.remove_dst_ip_to_ignore(ip)
        return False

    def main(self, config=False):
        try:
            # 1. Récupération de la configuration (interactive ou fichier)
            self._load_configuration(config)

            # 2. Affichage de la configuration
            self._print_configuration()

            # 3. Initialisation des conteneurs partagés
            model_ready = threading.Event()
            model_ready_mp = mp.Event()

            detect_queue = queue.Queue(maxsize=100_000_000)
            process = []

            self._create_refit_monitor()
            # 4. Création des threads d'apprentissage et de détection
            threads = self._start_learning_and_detection_threads(
                model_ready, model_ready_mp, detect_queue,
            )

            r_process = self._start_refit_manager_process(model_ready_mp, self.stop_event_mp)
            process.append(r_process)
            self.process = process
            self.threads = threads
            # 5. Gestion des signaux d'arrêt
            self._setup_signal_handlers(process, threads)

            # 6. Attente de l'arrêt
            _run_async(self._wait_for_stop)

            # 7. Nettoyage final
            self._cleanup(process, threads)

        except Exception as e:
            logger.print(f"[ERROR] Exception fatale dans main : {e}")
            self._emergency_cleanup()

    # ----------------------------------------------------------------------
    # Méthodes privées de configuration
    # ----------------------------------------------------------------------
    def _load_configuration(self, config_flag):
        """Charge la configuration depuis l'utilisateur ou un fichier."""
        if not config_flag:
            self._interactive_config()
        else:
            self._file_config()

        # Conversion et validation des types
        self.ids_mode = str(self.ids_mode)
        self.mode = self.mode.lower()
        self.duration = int(self.duration)
        self.save_interval = int(self.save_interval)
        self.combination_mode = self.combination_mode.lower()
        self.packet_anomaly = float(self.packet_anomaly)
        self.model_file = os.path.join(MODEL_DIR, self.model_file)
        os.makedirs(self.anomaly_dir, exist_ok=True)
        self.verbose = int(self.verbose)
        self.interface = build_ifaces(self.interface)
        
    def _interactive_config(self):
        """Demande interactivement chaque paramètre."""
        self.model_file = input("Nom du fichier modèle (ex: model.pkl) : ").strip() or "model.pkl"
        self.anomaly_dir = input(f"Dossier pour anomalies (default: {DEFAULT_ANOMALY_DIR}/) : ").strip() or DEFAULT_ANOMALY_DIR
        self.duration = input(f"Durée collecte pour fit initial en secondes (default: {DEFAULT_DURATION}) : ").strip() or str(DEFAULT_DURATION)
        self.save_interval = input(f"Durée sauvegarde périodique en secondes (default: {DEFAULT_SAVE_INTERVAL}) : ").strip() or str(DEFAULT_SAVE_INTERVAL)
        self.mode = input("Mode d'entraînement du modèle (full ou fast, par défaut full) : ").strip() or "full"
        self.combination_mode = input("Mode combinaison anomalies (or/and/weighted, default or) : ").strip() or "or"
        self.packet_anomaly = input("Seuil proportion anomalies packets (default 0.3) : ").strip() or "0.4"
        self.interface = input("Interface réseau (ex: wlp2s0, default: toutes) : ").strip() or None
        self.ids_mode = input("Mode de fonctionnement de l'ids/ips (default: ids) : ").strip() or "ids"
        self.verbose = input("Verbosité : (1 ou 0, default 1) : ").strip() or 1
        self.clear_sets_at_exit = input("Nettoyé les sets à la sortie (1 ou 0, default 0)").strip().lower() == "1"
        self.unlock_at_exit = input("Débloqué les ips bloqué à la sortie (1 ou 0, default 1)").strip().lower() == "1"
        self.do_not_fit = input(
            "Capturer le traffic pour fit un modèle ? Mettre 0 pour non, si vous avez un modèle, si il est imcompatible le fit sera quand même lancé (1/0, default 0)"
        ).strip().lower() == "O"
        self.whiltelist = []

    def _file_config(self):
        """Charge la configuration depuis le dictionnaire CONFIG."""
        date = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        self.model_file = CONFIG.get("model_file", f"model_{date}.pkl")
        self.mode = CONFIG.get("mode", "full")
        self.duration = CONFIG.get("duration", 1)
        self.save_interval = CONFIG.get("save_interval", 1)
        self.combination_mode = CONFIG.get("combination_mode", "or")
        self.packet_anomaly = CONFIG.get("packet_anomaly", 0.4)
        self.ids_mode = CONFIG.get("ids_mode", "ids")
        self.interface = CONFIG.get("interface", None)
        self.anomaly_dir = CONFIG.get("anomaly_dir", DEFAULT_ANOMALY_DIR) or DEFAULT_ANOMALY_DIR
        self.verbose = CONFIG.get("verbose", 1)
        self.clear_sets_at_exit = CONFIG.get("clear_sets_at_exit", False)
        self.unlock_at_exit = CONFIG.get("unlock_at_exit", True)
        self.do_not_fit = CONFIG.get("do_not_fit", False)
        self.whiltelist = CONFIG.get("whitelist", [])

    def _print_configuration(self):
        """Affiche la configuration courante."""
        logger.print("Configuration de l'ids/ips : ")
        logger.print("    -Fichier de sauvegarde du model : ", self.model_file)
        logger.print("    -Mode de creation du model : ", self.mode)
        logger.print("    -Durée d'appretissage : ", self.duration)
        logger.print("    -Intervalle de sauvegarde : ", self.save_interval)
        logger.print("    -Mode de l'ids/ips : ", self.ids_mode)
        logger.print("    -Pourcentage d'anomaly suspecté : ", self.packet_anomaly)
        logger.print("    -Mode de combinaison pour prediction du model : ", self.combination_mode)
        logger.print("    -Dossier d'anomalie : ", self.anomaly_dir)
        logger.print("    -Niveau de verbosité : ", self.verbose)

    # ----------------------------------------------------------------------
    # Méthodes privées pour les process d'apprentissage et détection
    # ----------------------------------------------------------------------
    def _start_learning_and_detection_threads(self, model_ready, model_ready_mp, queue_or_mem):
        """Crée et démarre les threads d'apprentissage et de détection."""
        t_learn = threading.Thread(
            target=self._run_async_learning,
            args=(model_ready, model_ready_mp,),
            daemon=True, name="Learning Thread"
        )

        t_detect = threading.Thread(
            target=self._run_async_detection,
            args=(model_ready, queue_or_mem,),
            daemon=True, name="Detection Thread"
        )

        t_learn.start()
        t_detect.start()
        return [t_learn, t_detect]

    def _run_async_learning(self, model_ready, model_ready_mp):
        """Wrapper synchrone pour la coroutine d'apprentissage."""
        try:
            asyncio.run(self._learning_coroutine(model_ready, model_ready_mp))
        except KeyboardInterrupt:
            logger.print("[INFO] Learning thread interrompu")
            self.stop_event.set()
            self.stop_event_mp.set()

    async def _learning_coroutine(self, model_ready, model_ready_mp):
        """Coroutine principale d'apprentissage du modèle."""
        while not self.monitor_ready.is_set():
            await asyncio.sleep(0.01)

        if self.do_not_fit:
            logger.print("[INFO] L'utilisateur spécifie de ne pas entrainer de modèle, nous allons vérifier son fichier pour décider !")
            if validate_model_file(self.model_file):
                logger.print("FICHIER validé, fit skippé, la détection sera lancé immédiatement !")
                model_ready.set()
                model_ready_mp.set()
                await self._switch_suricata_to_ids(ids_is_launch=False)
                return

            logger.print("FICHIER incompatible, le fit sera lancé !")

        logger.print(f"[INFO] Démarrage de Suricata en arrière-plan({self.ids_mode.upper()})...")
        suricata_thread = self.Utils.run_suricata_background(self.ids_mode, self.interface)
        await asyncio.sleep(2)
        logger.print(f"Suricata lancé dans le thread: {suricata_thread.name}")

        try:
            logger.print("[INFO] Collecte des paquets et préparation des features...")
            X_sequences, scaler, scaler_pkt, X_packets = await collect_and_process(
                duration=self.duration,
                save_interval=self.save_interval,
                ifaces=self.interface,
                maxsize=0,
                filename=CAPTURE_FILENAME,
                add_data_path=ADD_DATA_TO_CAPTURE_PATH
            )
            if X_sequences is None or X_packets is None:
                logger.print("[ERROR] Échec de la collecte ou traitement")
                self.stop_event.set()
                self.stop_event_mp.set()
                return

            n_seq, seq_len, n_seq_features = X_sequences.shape
            n_pkt_features = X_packets.shape[1]
            logger.print("\n📊 Dimensions des données :")
            logger.print(f"   Séquences : {X_sequences.shape}")
            logger.print(f"   Paquets : {X_packets.shape}")

            models = Models(lock=_lock)
            ae_seq, cnn_seq, if_seq, lof_seq, ae_pkt, if_pkt, lof_pkt = models.build_models(
                n_pkt=seq_len, n_seq_features=n_seq_features,
                n_pkt_features=n_pkt_features, mode=self.mode
            )
            ae_seq, cnn_seq, if_seq, lof_seq, ae_pkt, if_pkt, lof_pkt = models.fit_models(
                ae_seq=ae_seq, cnn_seq=cnn_seq, if_seq=if_seq, lof_seq=lof_seq,
                ae_pkt=ae_pkt, if_pkt=if_pkt, lof_pkt=lof_pkt,
                X_sequences=X_sequences, X_packets=X_packets,
                epochs=self.EPOCHS, batch_size=self.BATCH_SIZE, verbose=self.verbose
            )

            self.model = models

            model = {
                "ae_seq": ae_seq, "cnn_seq": cnn_seq,
                "if_seq": if_seq, "lof_seq": lof_seq,
                "ae_pkt": ae_pkt, "if_pkt": if_pkt,
                "lof_pkt": lof_pkt, "scaler_pkt": scaler_pkt,
                "scaler_seq": scaler,
            }
            save(dill.dumps(model), self.model_file)
            logger.print(f"[INFO] Modèle sauvegardé dans {self.model_file}")

            model_ready.set()
            model_ready_mp.set()

            await self._switch_suricata_to_ids()

        except Exception as e:
            logger.print(f"[ERROR] Exception dans _learning_coroutine : {e}")
            traceback.print_exc()
            self.stop_event.set()
            self.stop_event_mp.set()
            self._stop_suricata_safe()

    async def _switch_suricata_to_ids(self, ids_is_launch: bool = True):
        """Arrête Suricata actuel et le relance en mode IDS."""
        try:
            if ids_is_launch:
                logger.print("[INFO] Arret de Suricata(IPS)...")
                stop_ready = threading.Event()

                def stop():
                    self._stop_suricata_safe()
                    stop_ready.set()
                stop()
                logger.print('En attente de l\'arret ...')
                stop_ready.wait()
            logger.print('Lancement Suricata en mode IDS ')
            logger.print("[INFO] Démarrage de Suricata en arrière-plan(IDS)...")
            suricata_thread = self.Utils.run_suricata_background("ids", self.interface)
            await asyncio.sleep(2)
            logger.print(f"Suricata lancé dans le thread: {suricata_thread.name}")
        except Exception as e:
            logger.print("[ERREUR] Suricata lancement ids  : ", e)

    def _stop_suricata_safe(self):
        """Tente d'arrêter Suricata sans lever d'exception bloquante."""
        try:
            logger.print("[INFO] Arret de Suricata...")
            state.stop()
            self.Utils.stop_suricata()
        except Exception as e:
            logger.print("[ERREUR] Suricata task cancelling : ", e)

    def _start_refit_queue(self):
        self.RefitQueue.start()
        return self.RefitQueue

    def _stop_refit_queue(self):
        if hasattr(self, "RefitQueue"):
            if self.RefitQueue is not None:
                self.RefitQueue.stop()

    def _start_capture(self, queue_or_mem):
        logger.print()
        logger.print("=" * 60)
        logger.print("📡 DÉMARRAGE DE LA CAPTURE")
        logger.print("=" * 60)
        logger.print(f"   PID              : {os.getpid()}")
        logger.print(f"   Interfaces       : {self.interface}")
        logger.print(f"   Filtre           : {FILTER}")
        logger.print("=" * 60)
        logger.print()
        refitQueue = self._start_refit_queue()
        self.Capture = Capture(queue=queue_or_mem, backup_queue=refitQueue)
        self.Capture.capture(
            ifaces=self.interface,
            filter=FILTER,
        )
        logger.print("Capture Démaréé")
        return self.Capture

    def _stop_capture(self):
        if hasattr(self, "Capture"):
            if self.Capture is not None:
                self.Capture.stop(1)

    # ----------------------------------------------------------------------
    # Thread de détection
    # ----------------------------------------------------------------------
    def _run_refit_manager(self, model_ready_mp, mp_event):
        ignore_termination_signals()
        model_ready_mp.wait()
        if mp_event.is_set():
            return

        logger.print()
        logger.print("=" * 60)
        logger.print("🔄 DÉMARRAGE DU PROCESSUS DE REFIT (RÉ-APPRENTISSAGE)")
        logger.print("=" * 60)
        logger.print(f"   PID              : {os.getpid()}")
        logger.print(f"   Session ID       : {self.session_id}")
        logger.print(f"   Délai refit      : {self.ModelRefitMonitor.refit_delay // 3600} heures")
        logger.print("=" * 60)
        logger.print()
        self.ModelRefitMonitor.start()

    def _start_refit_manager_process(self, model_ready, mp_event):
        process = mp.Process(
            target=self._run_refit_manager,
            args=(model_ready, mp_event),
            daemon=True, name="Refit Manager Process",
        )
        process.start()
        return process

    def _run_async_detection(self, model_ready, queue_or_mem):
        """Wrapper synchrone pour la coroutine de détection."""
        try:
            asyncio.run(self._detection_coroutine(model_ready, queue_or_mem))
        except KeyboardInterrupt:
            logger.print("[INFO] Detection thread interrompu")
            self.stop_event.set()
            self.stop_event_mp.set()

    async def _detection_coroutine(self, model_ready, queue_or_mem):
        """Coroutine principale de détection en temps réel."""
        detector = None
        try:
            if graph:
                graph.control()
            detector = AnomalyDetector(
                enable_graph=GRAPH and graph is not None,
                graph=graph,
                Models_instance=self.model,
                interfaces=self.interface,
                clear_sets_at_exit=self.clear_sets_at_exit,
                unlock_at_exit=self.unlock_at_exit,
                mode=self.ids_mode,
                queue=queue_or_mem,
                whiltelist=self.whiltelist,
            )
            self.detector = detector

            detector._monitor_task = asyncio.create_task(
                detector.monitor_suricata_alerts(
                    verbose=self.verbose,
                    ready_event=self.monitor_ready
                )
            )

            logger.print()
            logger.print("=" * 60)
            logger.print("✅ DETECTOR CRÉÉ DANS LE PROCESSUS DE DÉTECTION")
            logger.print("=" * 60)
            logger.print(f"   PID du processus de détection : {os.getpid()}")
            logger.print(f"   Detector prêt                 : {self.detector is not None}")
            logger.print("=" * 60)
            logger.print()

            logger.print("[INFO] Attente du modèle pour démarrer la détection...")
            while not model_ready.is_set():
                if self.stop_event.is_set():
                    return
                await asyncio.sleep(0.5)

            self._start_capture(queue_or_mem)
            logger.print("[INFO] Lancement de la détection temps réel...")
            await self.detector.detect(
                self.model_file,
                combination_mode=self.combination_mode,
                packet_anomaly=self.packet_anomaly,
                verbose=self.verbose,
                new_model_available=self.ModelRefitMonitor.new_model_available,
                model_path=self.ModelRefitMonitor.model_path,
                refit_delay=self.ModelRefitMonitor.refit_delay
            )
        except Exception as e:
            logger.print(f"[ERROR] Exception dans _detection_coroutine : {e}")
            traceback.print_exc()
            self.stop_event.set()
            self.stop_event_mp.set()

        finally:
            if detector is not None and detector._monitor_task is not None and not detector._monitor_task.done():
                detector._monitor_task.cancel()
                try:
                    await detector._monitor_task
                except asyncio.CancelledError:
                    pass
                detector._monitor_task = None

    # ----------------------------------------------------------------------
    # Gestion des signaux et nettoyage
    # ----------------------------------------------------------------------
    def _setup_signal_handlers(self, process: list = None, threads: list = None):
        """Configure les gestionnaires de signaux pour un arrêt propre."""
        def signal_handler(*args, **kwargs):
            logger.print("\n[INFO] Interruption détectée. Arrêt des threads...")
            self.stop()
            if self.detector:
                print(self.detector.detect_start_time)
                print(self.detector.detect_end_time)
                print(self.detector.pkt_proccessed)
            self._cleanup(process or self.process, threads or self.threads)
            # sys.exit(0)
            # os._exit(0)

        if threading.main_thread() is threading.current_thread():
            signal_manager(signal_handler)

    async def _wait_for_stop(self):
        """Boucle d'attente jusqu'à ce que l'arrêt soit demandé."""
        try:
            while not (self.stop_event.is_set() or self.stop_event_mp.is_set()):
                await asyncio.sleep(1)

        except KeyboardInterrupt:
            logger.print("\n[INFO] Ctrl+C reçu dans _wait_for_stop")
            self.stop_event.set()
            self.stop_event_mp.set()

        except Exception as e:
            logger.print(f"\n[INFO] Erreur{str(e)} reçu dans _wait_for_stop")
            self.stop_event.set()
            self.stop_event_mp.set()

        finally:
            if self.detector:
                self.detector.stop()

            self._cleanup(self.process, self.threads)
    
    def _cleanup(self, process: list, threads: list):
        """Effectue toutes les opérations de nettoyage (sauvegardes, arrêt threads, etc.)."""
        with _lock:
            if self._cleaned:
                logger.info("Cleanup déjà effectué")
                return
        
            logger.info("Nettoyage en cours...")
            self._save_detector_state()
    
            logger.debug("Arrêt de Suricata...")
            try:
                self._stop_suricata_safe()
                logger.success("Suricata arrêté")
            except Exception as e:
                logger.error(f"stop_suricata a échoué : {e!r}")
    
            logger.debug("Arrêt de la capture...")
            try:
                self._stop_capture()
                logger.success("Capture arrêtée")
            except Exception as e:
                logger.error(f"_stop_capture a échoué : {e!r}")
    
            logger.debug("Arrêt de la refit queue...")
            try:
                self._stop_refit_queue()
                logger.success("Refit queue arrêtée")
            except Exception as e:
                logger.error(f"_stop_refit_queue a échoué : {e!r}")
    
            logger.debug("Arrêt de React (sig_manager)...")
            try:
                self.detector.React._sig_manager()
                logger.success("React arrêté")
            except Exception as e:
                logger.error(f"React._sig_manager a échoué : {e!r}")
    
            logger.debug("Arrêt du detector...")
            try:
                self.detector.stop()
                logger.success("Detector arrêté")
            except Exception as e:
                logger.error(f"detector.stop a échoué : {e!r}")
    
            logger.debug("Arrêt de state (sig_manager)...")
            try:
                state._sig_manager()
                logger.success("State arrêté")
            except Exception as e:
                logger.error(f"state._sig_manager a échoué : {e!r}")
    
            logger.debug("Arrêt du ModelRefitMonitor...")
            try:
                self.ModelRefitMonitor.stop()
                logger.success("ModelRefitMonitor arrêté")
            except Exception as e:
                logger.error(f"ModelRefitMonitor.stop a échoué : {e!r}")
    
            logger.debug("Notification API de fermeture...")
            try:
                self._notify_api_close()
                logger.success("API notifiée")
            except Exception as e:
                logger.error(f"_notify_api_close a échoué : {e!r}")
    
            process = process or self.process
            threads = threads or self.threads
    
            logger.info(f"Arrêt de {len(process)} process(es)...")
            for p in process:
                if p.is_alive():
                    try:
                        logger.debug(f"Process {p.name} (pid={p.pid}) : join(timeout=1)...")
                        p.join(timeout=1)
                        if p.is_alive():
                            logger.warning(f"Process {p.name} (pid={p.pid}) encore vivant après join, kill()")
                            p.kill()
                        else:
                            logger.success(f"Process {p.name} (pid={p.pid}) terminé")
                    except Exception as e:
                        logger.error(f"Process {p.name} : {e!r}")
    
            logger.info(f"Arrêt de {len(threads)} thread(s)...")
            for th in threads:
                if th.is_alive():
                    try:
                        logger.debug(f"Thread {th.name} : join(timeout=1)...")
                        th.join(1)
                        if th.is_alive():
                            logger.warning(f"Thread {th.name} toujours vivant après join (non tuable)")
                        else:
                            logger.success(f"Thread {th.name} terminé")
                    except Exception as e:
                        logger.error(f"Thread {th.name} : {e!r}")
    
            if hasattr(self, "memory"):
                logger.debug("Fermeture de memory...")
                try:
                    self.memory.close()
                    logger.success("Memory fermée")
                except Exception as e:
                    logger.error(f"memory.close a échoué : {e!r}")
    
            self._cleaned = True
            logger.success("Arrêt terminé.")
    
    
    def _save_detector_state(self):
        """Sauvegarde l'état du détecteur (whitelist, scores, etc.)."""
        if not hasattr(self, 'detector') or not self.detector:
            logger.debug("Pas de detector à sauvegarder, skip")
            return
    
        logger.debug("Sauvegarde de l'AnomalyScorer...")
        try:
            self.detector.AnomalyScorer.save(
                self.detector.AnomalyScorer.ip_score_dir,
                self.detector.AnomalyScorer.ip_data
            )
            logger.success("AnomalyScorer sauvegardé")
        except Exception as e:
            logger.error(f"AnomalyScorer.save a échoué : {e!r}")
    
        logger.debug("Sauvegarde de la whitelist...")
        try:
            self.detector.React.save_whitelist(
                self.detector.React.whitelist_filename,
                self.detector.React.whitelist
            )
            logger.success("Whitelist sauvegardée")
        except Exception as e:
            logger.error(f"save_whitelist a échoué : {e!r}")
    
        logger.debug("Sauvegarde de l'historique...")
        try:
            self.detector.React.save_history(
                self.detector.React.history_path,
                self.detector.React.blocked
            )
            logger.success("Historique sauvegardé")
        except Exception as e:
            logger.error(f"save_history a échoué : {e!r}")
    
    def _notify_api_close(self):
        """Envoie une requête de fermeture à l'API."""
        try:
            from ids_ips_ia.config.config_ids import API_CONFIG
            port = API_CONFIG.get('port')
            if port:
                from modules_utils.loop_utils import _run_async
                host = API_CONFIG.get('host', '0.0.0.0')
                url = f'http://{host}:{port}/api/close'
                _run_async(close_api, url)
        except Exception as e:
            logger.error(f"Erreur dans la fermeture de l'api avec _notify_api_close: {e!r}")

    def _emergency_cleanup(self):
        """Nettoyage d'urgence en cas d'exception fatale."""
        self.stop_event.set()
        self.stop_event_mp.set()
        self._stop_suricata_safe()
        logger.print("[INFO] Nettoyage d'urgence terminé.")


def all_threads():
    for thread in threading.enumerate():
        logger.print(f"Thread: {thread.name}")
        logger.print(f"  ID: {thread.ident}")
        logger.print(f"  Démarré: {thread.is_alive()}")
        logger.print(f"  Daemon: {thread.daemon}")
        logger.print("-" * 40)


def asyncio_threads():
    tasks = asyncio.all_tasks()
    logger.print(f"Tâches actives: {len(tasks)}")

    for task in tasks:
        logger.print(f"Task: {task.get_name()}")
        logger.print(f"  En cours: {not task.done()}")
        logger.print(f"  Annulée: {task.cancelled()}")
        logger.print(f"  Résultat: {task.result() if task.done() else 'En cours'}")