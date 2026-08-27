#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API et interface CLI pour le système Anti-Phishing.

Ce module contient :
- La classe Display pour l'affichage amélioré (Rich/Colorama/Print)
- La classe AntiPhishing qui orchestre l'analyse (IA + passive)
- L'API FastAPI avec endpoints REST
- Les fonctions de gestion du serveur et des threads

Le système combine un modèle ML (PhishingIA) et une analyse passive
(PassiveAnalyzer) pour détecter les URLs de phishing.

Auteur: HOUNSOU Samuel
Date: Octobre 2025
Version: 2.0.0
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
import threading
import atexit
import copy
import json
import uvicorn
import time
import asyncio
import aiohttp
import dill
import joblib
import pickle
import signal
from typing import List, Optional
from fastapi import FastAPI, Request, HTTPException, APIRouter
from fastapi import UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import concurrent.futures
from diskcache import Cache
from anti_phishing_ia import (
    REACT_EXISTS,
    REQUEST, DATA, DIRECTORY_REACT,
    ALLOWED_ORIGINS, PATH_REACT,
    features_name as FEATURES_NAME,
    PORT as port, HOST as host,
    INDEX_HTML, BUILD_DIR, BUILD_URL
)
from anti_phishing_ia.core.passive_analyzer import PassiveAnalyzer as PassivePhishingDetector
from anti_phishing_ia.core.features_extractor import (
    features_extractor_from_url, _clean_url, _features_extractor_from_url
)
from anti_phishing_ia.phishing_utils.utils import _get_domain as get_domain
from anti_phishing_ia.ml_model.phishing_ia import PhishingIA
from anti_phishing_ia.dl_model.mail_phishing_pipeline import MailPhishingPredict
from anti_phishing_ia.phishing_utils.legit_domain import _get_legitimate_domain
from anti_phishing_ia.analyze_mail import analyze_mail as _analyze_mail
from anti_phishing_ia.main_helper import Display, _console, _RICH_AVAILABLE, Table
from modules_utils.api_dependencies import get_loop
import nest_asyncio

# ============================================================================
# VARIABLES GLOBALES
# ============================================================================

REQUEST_NUMBER = 0          # Compteur de requêtes depuis le démarrage
ML_AVAILABLE = True        # Indique si le modèle ML est chargé
_global_ap_instance = None  # Instance singleton d'AntiPhishing
_global_lock = threading.Lock()  # Verrou pour l'accès à l'instance
BASEDIR = os.path.dirname(os.path.abspath(__file__))
BASEDIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.abspath(os.path.join(BASEDIR, "dl_model"))
# ============================================================================
# CONFIGURATION FASTAPI
# ============================================================================
import contextlib
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    print("API lancée !!!")
    _get_legitimate_domain()
    yield
    print("API fermé !!!")
    
app = FastAPI(
    title='Anti-Phishing',
    version="2.0",
    description="Détection de phishing avec interface React et ML",
    docs_url='/api/docs',
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "HEAD"],
    allow_headers=["*"],
)

router = APIRouter()

# Montage des fichiers statiques React si disponibles
if REACT_EXISTS:
    app.mount(PATH_REACT, StaticFiles(directory=DIRECTORY_REACT), name="static")
    app.mount(BUILD_URL, StaticFiles(directory=BUILD_DIR), name="build")

server = None
_dir_ = os.path.dirname(os.path.abspath(__file__))
cache_dir = os.path.join(_dir_, 'var', 'cache')
os.makedirs(cache_dir, exist_ok=True)
HISTORY_FILE = os.path.join(_dir_, "history")
os.makedirs(HISTORY_FILE, exist_ok=True)
dcache = Cache(directory=cache_dir)


def clear():
    """Vide le cache de l'application."""
    dcache.clear()


def load_model(model_path: str, mod: str = 'joblib'):
    """
    Charge un modèle depuis un fichier.

    Args:
        model_path (str): Chemin vers le fichier du modèle
        mod (str): Format du fichier ('joblib', 'dill', 'pickle')

    Returns:
        object: Modèle chargé

    Raises:
        ValueError: Si le mode est invalide
    """
    if mod == 'joblib':
        model = joblib.load(model_path)
    elif mod == 'dill':
        with open(model_path, 'rb') as f:
            model = dill.load(f)
    elif mod == 'pickle':
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
    else:
        raise ValueError("Mode invalide !")
    return model


def compare_phishing_ia_models(model1, model2, test_data, threshold=0.02):
    """
    Compare deux modèles PhishingIA et retourne le meilleur.

    Args:
        model1 (PhishingIA): Premier modèle (actuel)
        model2 (PhishingIA): Second modèle (nouveau)
        test_data (pd.DataFrame): Données de test avec colonne 'label'
        threshold (float): Seuil d'amélioration minimal (défaut: 0.02 = 2%)

    Returns:
        tuple: (meilleur_modèle, rapport_de_comparaison)
    """
    print("🔍 Début de la comparaison des modèles...")
    from sklearn.metrics import accuracy_score, f1_score

    X_test = test_data.drop(['label'], axis=1)
    y_test = model1.le.transform(test_data['label'].tolist())

    # Prédictions du modèle 1 (actuel)
    try:
        y_pred1 = model1.model.predict(X_test)

        acc1 = accuracy_score(y_test, y_pred1)
        f1_1 = f1_score(y_test, y_pred1, average='macro')

        print(f"📊 Modèle 1 (actuel): Accuracy={acc1:.4f}, F1={f1_1:.4f}")
    except Exception as e:
        print(f"❌ Erreur modèle 1: {e}")
        return model2, {"error": "Modèle 1 échoué", "winner": "model2"}

    # Prédictions du modèle 2 (nouveau)
    try:
        y_pred2 = model2.model.predict(X_test)

        acc2 = accuracy_score(y_test, y_pred2)
        f1_2 = f1_score(y_test, y_pred2, average='macro')

        print(f"📊 Modèle 2 (nouveau): Accuracy={acc2:.4f}, F1={f1_2:.4f}")
    except Exception as e:
        print(f"❌ Erreur modèle 2: {e}")
        return model1, {"error": "Modèle 2 échoué", "winner": "model1"}

    # Calcul de l'amélioration
    acc_improvement = acc2 - acc1
    f1_improvement = f1_2 - f1_1

    score1 = 0.6 * f1_1 + 0.4 * acc1
    score2 = 0.6 * f1_2 + 0.4 * acc2
    total_improvement = score2 - score1

    # Décision
    comparison = {
        "model1_accuracy": float(acc1),
        "model1_f1": float(f1_1),
        "model1_score": float(score1),
        "model2_accuracy": float(acc2),
        "model2_f1": float(f1_2),
        "model2_score": float(score2),
        "accuracy_improvement": float(acc_improvement),
        "f1_improvement": float(f1_improvement),
        "total_improvement": float(total_improvement),
        "threshold": threshold,
        "timestamp": datetime.now().isoformat()
    }

    # Vérifier si le nouveau modèle est significativement meilleur
    if total_improvement > threshold:
        print(f"✅ Modèle 2 est meilleur (+{total_improvement * 100:.2f}%)")
        comparison["winner"] = "model2"
        comparison["decision"] = "Mise à jour vers nouveau modèle"
        return model2, comparison

    elif total_improvement < -threshold:
        print(f"⚠️  Modèle 1 reste meilleur (+{-total_improvement * 100:.2f}%)")
        comparison["winner"] = "model1"
        comparison["decision"] = "Conservation du modèle actuel (régression détectée)"
        return model1, comparison

    else:
        print(f"📊 Différence non significative ({total_improvement * 100:.2f}%)")
        comparison["winner"] = "model1"
        comparison["decision"] = "Conservation du modèle actuel (amélioration < seuil)"
        return model1, comparison


# ============================================================================
# MODÈLES PYDANTIC POUR L'API
# ============================================================================

class AnalyzeUrlData(BaseModel):
    """
    Modèle de données pour la requête d'analyse.

    Attributes:
        url (str): URL à analyser
        check_blacklist (bool): Vérifier la blacklist externe
        check_right_click (bool): Vérifier le blocage du clic droit
        explain (bool): Retourner les explications détaillées
    """
    url: str
    check_blacklist: bool = False
    check_right_click: bool = False
    explain: bool = True


class Settings(BaseModel):
    """
    Paramètres modifiables par l'utilisateur uniquement.
    """
    check_blacklist: bool = False
    explain: bool = True
    check_right_click: bool = False


# ============================================================================
# CLASSE PRINCIPALE : AntiPhishing
# ============================================================================

class AntiPhishing:
    """
    Système Anti-Phishing combinant l'analyse par IA et l'analyse passive.

    Cette classe permet de :
        - Prédire si une URL est phishing ou légitime
        - Utiliser un modèle ML (PhishingIA) pour l'analyse intelligente
        - Utiliser un analyseur passif (PassiveAnalyzer) pour les heuristiques
        - Gérer le refit automatique du modèle
        - Sauvegarder l'historique des analyses

    Attributes:
        PhishingIA (PhishingIA): Instance du modèle d'IA
        PassiveAnalyzer (PassivePhishingDetector): Analyseur passif
        model_file (str): Chemin du fichier modèle
        model_dir (str): Dossier contenant les modèles
        refit_time (int): Nombre de requêtes avant refit
        lock (threading.Lock): Verrou pour le refit
        history_file (str): Chemin du fichier d'historique
    """

    def __init__(
        self, model_path, path_to_original_dataset=None,
        model_dir='model', refit_time: int = 1000,
        _all_=False, comparison_threshold=0.03,
        mail_model_dir="mail_model", mail_model_type="full",
        backup_models=True, features_name=FEATURES_NAME,
        n_features=len(FEATURES_NAME), refit=False
    ):
        """
        Initialise le système anti-phishing.

        Args:
            model_path (str): Chemin vers le modèle IA
            path_to_original_dataset (str, optional): Dataset original pour refit
            model_dir (str): Dossier du modèle
            refit_time (int): Délai de refit (nb requêtes)
            _all_ (bool): Mode complet
            comparison_threshold (float): Seuil de comparaison des modèles
            backup_models (bool): Sauvegarder les anciens modèles
            features_name (list): Noms des features
            n_features (int): Nombre de features
            refit (bool): Forcer le refit
        """
        global ML_AVAILABLE
        self.PhishingIA = PhishingIA(
            model_dir_=model_dir, model_file=model_path,
            features_name=features_name, n_features=n_features
        )
        self.mail_model_dir = os.path.join(MODELS_DIR, mail_model_dir)
        self.mail_model_type = "full" #mail_model_type
        self.MailPhishingPredict = MailPhishingPredict.from_directory(
            directory=self.mail_model_dir,
            model_type=self.mail_model_type
        )
        self.model_file = self.PhishingIA.model_file
        ML_AVAILABLE = self.PhishingIA.model is not None
        self.model_path = model_path
        self.model_dir = model_dir
        self.refit_time = refit_time
        self.PassiveAnalyzer = PassivePhishingDetector()
        self._all_ = _all_
        self.backup_models = backup_models
        self.lock = threading.Lock()
        self.comparison_threshold = comparison_threshold
        self.path_to_original_dataset = path_to_original_dataset
        self.refit_count = dcache.get('refit_count', default=0)
        self.refit_in_progress = False
        self.refit = refit
        self.close_cache(dcache)

        if self.refit:
            self.th = self.refit_model()
            self.close()

        # Initialisation du cache
        if 'pred' not in dcache:
            dcache.set("pred", {"count": 0, 'features': []}, expire=30 * 24 * 3600)
        if 'request_number' not in dcache:
            dcache.set('request_number', 0, expire=30 * 24 * 3600)
            dcache.set('all_request_number', 0)

        self.history_file = os.path.join(HISTORY_FILE, 'history.json')
        self._reload_lock = asyncio.Lock()
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=6,
            thread_name_prefix="anti_phishing_executor_"
        )
        
    async def load_models(self, what: str = "all"):
        what = what.lower()
        with self._reload_lock:
            if what == "all":
                self.PhishingIA.load_model(self.PhishingIA.model_file)
                mail_predict = MailPhishingPredict.from_directory(
                    directory=self.mail_model_dir,
                    model_type=self.mail_model_type
                )
                self.MailPhishingPredict = mail_predict
                
            elif what == "phishing":
                self.PhishingIA.load_model(self.PhishingIA.model_file)
                
            elif what == "mail":
               mail_predict = MailPhishingPredict.from_directory(
                   directory=self.mail_model_dir,
                   model_type=self.mail_model_type
               )
               self.MailPhishingPredict = mail_predict
           
           
    # ========================================================================
    # MÉTHODES CLI
    # ========================================================================

    @classmethod
    def from_cli(cls):
        """
        Crée une instance d'AntiPhishing à partir des arguments de ligne de commande.

        Cette méthode de classe parse les arguments avec argparse et retourne
        une instance configurée d'AntiPhishing.

        Returns:
            AntiPhishing: Instance configurée via les arguments CLI

        Example:
            >>> ap = AntiPhishing.from_cli()
            >>> ap.phishing_cli()
        """
        import argparse

        parser = argparse.ArgumentParser(
            prog="anti-phishing",
            description="Anti-Phishing - Détection de sites frauduleux par IA et analyse passive",
            epilog="Exemples:\n"
                   "  python main_phish.py -u https://google.com\n"
                   "  python main_phish.py -u https://paypal-verify.tk -b\n"
                   "  python main_phish.py --test\n"
                   "  python main_phish.py --api --port 8080"
        )

        # Arguments pour l'analyse
        parser.add_argument(
            '-u', '--url',
            type=str,
            help="URL à analyser"
        )
        parser.add_argument(
            '-b', '--check-blacklist',
            action='store_true',
            help="Vérifier la blacklist externe"
        )
        parser.add_argument(
            '-c', '--check-right-click',
            action='store_true',
            help="Vérifier le blocage du clic droit"
        )
        parser.add_argument(
            '--no-explain',
            action='store_true',
            help="Ne pas afficher les explications détaillées"
        )

        # Arguments pour le modèle
        parser.add_argument(
            '--model-path',
            type=str,
            default='model_phish.pkl',
            help="Chemin du modèle (défaut: model_phish.pkl)"
        )
        parser.add_argument(
            '--model-dir',
            type=str,
            default='model',
            help="Dossier du modèle (défaut: model)"
        )
        parser.add_argument(
            '--refit',
            action='store_true',
            help="Forcer le refit du modèle"
        )
        parser.add_argument(
            '--refit-time',
            type=int,
            default=1000,
            help="Nombre de requêtes avant refit (défaut: 1000)"
        )
        
        # Ajouter ces arguments
        parser.add_argument(
            '-e', '--email',
            type=str,
            help="Email brut à analyser (entre guillemets)"
        )
        parser.add_argument(
            '--eml',
            type=str,
            help="Chemin vers un fichier .eml à analyser"
        )

        # Arguments pour l'API
        parser.add_argument(
            '--api',
            action='store_true',
            help="Lancer l'API FastAPI"
        )
        parser.add_argument(
            '--host',
            type=str,
            default='0.0.0.0',
            help="Hôte pour l'API (défaut: 0.0.0.0)"
        )
        parser.add_argument(
            '--port',
            type=int,
            default=8000,
            help="Port pour l'API (défaut: 8000)"
        )

        # Arguments de test
        parser.add_argument(
            '--test', '-t',
            action='store_true',
            help="Lancer les tests sur les URLs prédéfinies"
        )
        parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help="Mode verbeux pour les tests"
        )

        # Arguments utilitaires
        parser.add_argument(
            '--clear-cache',
            action='store_true',
            help="Vider le cache au démarrage"
        )
        parser.add_argument(
            '--version',
            action='version',
            version='Anti-Phishing v2.0.0'
        )

        args = parser.parse_args()

        # Vider le cache si demandé
        if args.clear_cache:
            clear()
            Display.print_success("Cache vidé")

        # Création de l'instance avec les arguments
        instance = cls(
            model_path=args.model_path,
            model_dir=args.model_dir,
            refit_time=args.refit_time,
            refit=args.refit
        )

        # Stockage des arguments dans l'instance pour usage ultérieur
        instance._cli_args = args

        return instance

    def phishing_cli(self):
        """
        Point d'entrée CLI pour l'analyse anti-phishing.

        Cette méthode utilise les arguments stockés par from_cli() pour :
            - Lancer l'API si --api est présent
            - Exécuter les tests si --test est présent
            - Analyser une URL unique si --url est présent
            - Afficher l'aide si aucun argument n'est fourni

        Returns:
            dict or None: Résultat de l'analyse si mode URL unique, None sinon
        """
        args = getattr(self, '_cli_args', None)

        if args is None:
            Display.print_error("Aucun argument trouvé. Utilisez from_cli() d'abord.")
            return None

        # Mode API
        if args.api:
            self._run_api(args.host, args.port)
            return None

        # Mode test
        if args.test:
            self._run_tests(args.verbose)
            return None

        # Mode analyse unique
        if args.url:
            result = self._analyze_and_display(
                url=args.url,
                check_blacklist=args.check_blacklist,
                check_right_click=args.check_right_click,
                explain=not args.no_explain
            )
            return result
        
        # Mode analyse email (texte brut)
        if args.email:
            result = self.predict_email(args.email, check_blacklist=args.check_blacklist)
            Display.print_result_table_mail(result)
            return result
        
        # Mode analyse email (fichier .eml)
        if args.eml:
            if not os.path.exists(args.eml):
                Display.print_error(f"Fichier non trouvé : {args.eml}")
                return None
            result = self.predict_email_from_file(args.eml, check_blacklist=args.check_blacklist)
            Display.print_result_table_mail(result)
            return result

        # Aucun mode spécifique → afficher l'aide
        Display.print_warning("Aucune action spécifiée. Utilisez --help pour l'aide.")
        Display.print_info("Exemples :")
        Display.print_info("  python main_phish.py -u https://google.com")
        Display.print_info("  python main_phish.py --api")
        Display.print_info("  python main_phish.py --test")
        return None

    def _analyze_and_display(
        self,
        url: str,
        check_blacklist: bool = False,
        check_right_click: bool = False,
        explain: bool = True
    ) -> dict:
        """
        Analyse une URL et affiche les résultats avec un affichage amélioré.

        Args:
            url (str): URL à analyser
            check_blacklist (bool): Vérifier la blacklist
            check_right_click (bool): Vérifier le clic droit
            explain (bool): Afficher les explications

        Returns:
            dict: Résultat de l'analyse
        """
        Display.print_header(f"Analyse de l'URL : {url[:60]}...")

        try:
            start_time = time.time()
            result = self.predict_url(
                url=url,
                check_blacklist=check_blacklist,
                explain=explain,
                check_right_click=check_right_click
            )
            elapsed = time.time() - start_time

            # Affichage amélioré des résultats
            Display.print_result_table(result)

            # Message de temps
            Display.print_info(f"Analyse terminée en {elapsed:.2f} secondes")

            return result

        except Exception as e:
            Display.print_error(f"Erreur lors de l'analyse : {str(e)}")
            return {"error": str(e), "url": url}

    def _run_api(self, host: str = "0.0.0.0", port: int = 8000):
        """
        Lance l'API FastAPI.

        Args:
            host (str): Hôte d'écoute
            port (int): Port d'écoute
        """
        global server

        Display.print_header("Démarrage de l'API Anti-Phishing")
        Display.print_info(f"Hôte: {host}")
        Display.print_info(f"Port: {port}")
        Display.print_info(f"Documentation: http://{host}:{port}/api/docs")

        # Configuration de la fermeture
        target = f'http://{host}:{port}/api/close'
        # close_api_atexit(target)

        def signal_handler(sig, frame):
            print('Signal envoyé : ', sig)
            try:
                from modules_utils.loop_utils import _run_async
                _run_async(close_api, target)
            except Exception:
                pass
            # sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGQUIT, signal_handler)

        # Démarrage du serveur
        config = uvicorn.Config(app, host=host, port=port, workers=10, loop='uvloop')
        server = uvicorn.Server(config)

        try:
            Display.print_success("Serveur démarré. Appuyez sur Ctrl+C pour arrêter.")
            server.run()
        except KeyboardInterrupt:
            Display.print_warning("Arrêt du serveur demandé...")
        finally:
            Display.print_success("Serveur arrêté.")

    def _run_tests(self, verbose: bool = False):
        """
        Lance les tests unitaires sur les URLs prédéfinies.

        Args:
            verbose (bool): Mode verbeux
        """
        Display.print_header("Exécution des tests anti-phishing")

        test_urls = [
            ("https://www.google.com", "safe"),
            ("https://accounts.google.com/", "safe"),
            ("https://www.paypal.com/signin/", "safe"),
            ("https://github.com/login", "safe"),
            ("https://www.netflix.com/", "safe"),
            ("http://192.168.1.1/login.php", "phishing"),
            ("https://paypal-verification-security.com/account/update", "phishing"),
            ("https://xn--mcrosoft-8g0a.com/security/", "phishing"),
            ("http://goog1e.com/login/", "phishing"),
            ("https://secure-amazon-update.xyz/verify/", "phishing"),
        ]

        correct = 0
        total = len(test_urls)
        results = []

        for i, (url, expected) in enumerate(test_urls, 1):
            Display.print_info(f"Test {i}/{total}: {url[:60]}...")

            try:
                result = self.predict_url(url, explain=False)
                predicted = result.get('final_decision', 'unknown')
                is_correct = (predicted == expected)

                if is_correct:
                    correct += 1
                    if verbose:
                        Display.print_success(f"  ✓ {expected} → {predicted}")
                else:
                    if verbose:
                        Display.print_error(f"  ✗ attendu: {expected}, obtenu: {predicted}")

                results.append({
                    "url": url[:50],
                    "expected": expected,
                    "predicted": predicted,
                    "correct": is_correct
                })

            except Exception as e:
                Display.print_error(f"  Erreur: {str(e)}")
                results.append({
                    "url": url[:50],
                    "expected": expected,
                    "predicted": "ERROR",
                    "correct": False
                })

        # Résumé des tests
        Display.print_header("RÉSULTATS DES TESTS")

        if _RICH_AVAILABLE:
            table = Table(title=f"Tests : {correct}/{total} corrects ({correct / total * 100:.1f}%)")
            table.add_column("URL", style="cyan")
            table.add_column("Attendu", style="blue")
            table.add_column("Prédit", style="yellow")
            table.add_column("Status", style="green")

            for r in results:
                status = "✅" if r["correct"] else "❌"
                pred_style = "green" if r["predicted"] == r["expected"] else "red"
                table.add_row(r["url"], r["expected"], f"[{pred_style}]{r['predicted']}[/{pred_style}]", status)

            _console.print(table)
        else:
            print(f"\nTests : {correct}/{total} corrects ({correct / total * 100:.1f}%)\n")
            for r in results:
                status = "✅" if r["correct"] else "❌"
                print(f"  {status} {r['url']} → attendu: {r['expected']}, obtenu: {r['predicted']}")

        if correct == total:
            Display.print_success(f"Tests réussis ! {correct}/{total}")
        else:
            Display.print_warning(f"Tests partiellement réussis : {correct}/{total}")

    # ========================================================================
    # FIN DES MÉTHODES CLI
    # ========================================================================

    def _clean_url(self, url: str):
        """Nettoie une URL (wrapper autour de _clean_url)."""
        return _clean_url(url)

    def close_cache(self, cache: Cache):
        """Enregistre la fermeture du cache à la sortie du programme."""
        def _close_cache():
            if hasattr(cache, 'close'):
                cache.close()
            # sys.exit(0)
        atexit.register(_close_cache)
    
    async def _run_async(self, func, *args):
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                self.executor,
                func,
                *args,
            )
        except RuntimeError:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                return await loop.run_in_executor(
                    self.executor,
                    func,
                    *args,
                )
            except Exception:
                return await asyncio.to_thread(func, *args)


    def predict_with_ia(self, url, features_func=None):
        """
        Prédit le label d'une URL avec le modèle IA.

        Args:
            url (str): URL à analyser
            features_func (callable, optional): Fonction d'extraction de features

        Returns:
            dict: Résultat de la prédiction IA
        """
        if features_func:
            features = features_func(url)
        else:
            features = features_extractor_from_url(url)
        if 'label' in features:
            features.pop('label')
        if not isinstance(features, list):
            features = [features]
        ia_pred = self.PhishingIA.predict(features)
        return ia_pred
    
    async def predict_with_ia_async(self, url: str, features_func=None) -> dict:
        """
        Version async de predict_with_ia.

        Extrait les features et prédit via PhishingIA sans bloquer l'event loop.

        Args:
            url (str): URL à analyser
            features_func (callable, optional): Fonction custom d'extraction

        Returns:
            dict: Résultat de la prédiction IA
        """
        if features_func:
            features = await self._run_async(features_func, url)
        else:
            # _features_extractor_from_url est déjà async
            features = await _features_extractor_from_url(url)

        if 'label' in features:
            features.pop('label')
        if not isinstance(features, list):
            features = [features]

        # PhishingIA.predict est sync donc to_thread
        ia_pred = await self._run_async(self.PhishingIA.predict, features)
        return ia_pred

    def predict_passive_analyze(
            self, 
            url, 
            check_blacklist: bool = False, 
            explain: bool = False, 
            check_right_click: bool = False
        ):
        """
        Analyse passive d'une URL.

        Args:
            url (str): URL à analyser
            check_blacklist (bool): Vérifier la blacklist
            explain (bool): Retourner les explications
            check_right_click (bool): Vérifier le blocage du clic droit

        Returns:
            dict: Résultat de l'analyse passive
        """
        tup = asyncio.run(self.PassiveAnalyzer.analyze(url, check_blacklist, check_right_click))
        dic = dict(zip(["risk_level", "risk_score", "is_phishing", "flags"], tup))
        if not explain:
            dic.pop('flags')
        return dic
    
    async def predict_passive_analyze_async(
        self,
        url: str,
        check_blacklist: bool = False,
        explain: bool = False,
        check_right_click: bool = False
    ) -> dict:
        """
        Version async de predict_passive_analyze.

        Appelle directement PassiveAnalyzer.analyze() avec await
        au lieu de asyncio.run() — compatible FastAPI/uvicorn.

        Args:
            url (str): URL à analyser
            check_blacklist (bool): Vérifier la blacklist
            explain (bool): Retourner les flags
            check_right_click (bool): Vérifier le clic droit

        Returns:
            dict: Résultat de l'analyse passive
        """
        tup = await self.PassiveAnalyzer.analyze(url, check_blacklist, check_right_click)
        dic = dict(zip(["risk_level", "risk_score", "is_phishing", "flags"], tup))
        if not explain:
            dic.pop('flags', None)
        return dic
    
    def final_decision(self, domain, predicts):
        """
        Prend la décision finale en combinant IA et analyse passive.

        Implémente une logique à plusieurs niveaux :
        1. Whitelist → safe
        2. IA très confiante safe (>85%) → safe
        3. IA très confiante phishing (>80%) → phishing ou suspicious selon passive
        4. Passive safe → safe ou suspicious selon IA
        5. Passive phishing → phishing ou suspicious selon IA
        6. Fallback → safe

        Args:
            domain (str): Domaine extrait de l'URL
            predicts (dict): Dictionnaire contenant 'ia_pred' et 'passive_pred'

        Returns:
            dict: Décision finale avec confidence, source et breakdown
        """
        # CAS 1: DOMAINE DANS LA WHITELIST
        if domain in _get_legitimate_domain():
            return {
                'final_decision': 'safe',
                'confidence': 1.0,
                'source': 'whitelist',
                'breakdown': {},
            }

        ia_pred = predicts.get('ia_pred', {})
        _proba_map = ia_pred.get('predict_proba', {})
        ia_prob = _proba_map.get('0') or _proba_map.get(0)
        passive_pred = predicts.get('passive_pred', {})
        risk_level = passive_pred.get('risk_level', 'CRITIQUE').lower()
        risk_score = passive_pred.get('risk_score', 30)
        prob_passive = risk_score / 100
        
        if not isinstance(ia_prob, dict) or 'phishing' not in ia_prob or 'safe' not in ia_prob:
            is_phishing = any(c in risk_level for c in ('élevé', 'critique'))
            return {
                'final_decision': 'phishing' if is_phishing else 'safe',
                'confidence': prob_passive,
                'source': 'passive_only (ia_pred indisponible)',
                'breakdown': {
                    'passive_analyze_prob': float(f'{prob_passive:.3f}'),
                    'passive_analyze_level': risk_level.upper(),
                    'ia_pred': {"safe": 0.5, "phishing": 0.5}
                }
            }
        # CAS 2: IA très confiante SAFE (>85%)
        if ia_prob['safe'] >= 0.85:
            return {
                'final_decision': 'safe',
                'confidence': ia_prob['safe'],
                'source': 'ia_prediction(haut confiance)',
                'breakdown': {
                    'ia_pred_proba': float(f"{ia_prob['safe']:.3f}"),
                    'ia_pred': ia_pred['predict'].get('0', None) or ia_pred['predict'].get(0, None),
                    'passive_analyze': None
                }
            }

        # CAS 3: IA très confiante PHISHING (>80%)
        if ia_prob['phishing'] >= 0.80:
            # CAS 3-1: Passive aussi phishing → phishing
            if any(c in risk_level for c in ('élevé', 'critique')):
                confidence = (ia_prob['phishing'] * 0.6) + (0.4 * prob_passive)
                return {
                    'final_decision': 'phishing',
                    'confidence': float(f'{confidence:.2f}'),
                    'source': 'ia_prediction(confiance_moyenne) && passive_analyse',
                    'breakdown': {
                        'ia_pred_proba': float(f"{ia_prob['phishing']:.3f}"),
                        'ia_pred': ia_pred['predict'].get('0', None) or ia_pred['predict'].get(0, None),
                        'passive_analyze_prob': float(f'{prob_passive:.3f}'),
                        'passive_analyze_level': risk_level.upper()
                    }
                }
            # CAS 3-2: Passive safe → suspicious
            if any(c in risk_level for c in ('moyen', 'faible', 'negligeable')):
                confidence = max(ia_prob["phishing"], prob_passive)
                return {
                    'final_decision': 'suspicious',
                    'advice': 'Faites attention, ne divulguez pas d\'informations trop personnelles à moins d\'avoir confiance',
                    'confidence': float(f'{confidence:.2f}'),
                    'source': 'ia_prediction(confiance_moyenne) && passive_analyse',
                    'breakdown': {
                        'ia_pred_proba_phishing': float(f"{ia_prob['phishing']:.3f}"),
                        'ia_pred_proba_safe': float(f"{ia_prob['safe']:.3f}"),
                        'ia_pred': ia_pred['predict'].get('0', None) or ia_pred['predict'].get(0, None),
                        'passive_analyze_prob': float(f'{prob_passive:.3f}'),
                        'passive_analyze_level': risk_level.upper()
                    }
                }

        # CAS 4: Passive safe
        if any(c in risk_level for c in ('moyen', 'faible', 'negligeable')):
            # CAS 4-1: IA aussi safe → safe
            if ia_prob['safe'] >= 0.60:
                confidence = (ia_prob["safe"] * 0.6) + (0.4 * prob_passive)
                return {
                    'final_decision': 'safe',
                    'confidence': float(f'{confidence:.2f}'),
                    'source': 'ia_prediction(confiance moyenne) && passive_analyse',
                    'breakdown': {
                        'ia_pred_proba': None,
                        'ia_pred': None,
                        'passive_analyze_prob': float(f"{prob_passive:.3f}"),
                        'passive_analyze_level': risk_level.upper()
                    }
                }
            # CAS 4-2: IA incertain → suspicious
            else:
                confidence = max(ia_prob["safe"], prob_passive)
                return {
                    'final_decision': 'suspicious',
                    'advice': 'Faites attention, ne divulguez pas d\'informations trop personnelles à moins d\'avoir confiance',
                    'confidence': float(f'{confidence:.2f}'),
                    'source': 'ia_prediction(confiance_faible) && passive_analyse',
                    'breakdown': {
                        'ia_pred_proba_phishing': float(f"{ia_prob['phishing']:.3f}"),
                        'ia_pred_proba_safe': float(f"{ia_prob['safe']:.3f}"),
                        'ia_pred': ia_pred['predict'].get('0', None) or ia_pred['predict'].get(0, None),
                        'passive_analyze_prob': float(f'{prob_passive:.3f}'),
                        'passive_analyze_level': risk_level.upper()
                    }
                }

        # CAS 5: Passive phishing
        if any(c in risk_level for c in ('élevé', 'critique')):
            # CAS 5-1: IA aussi phishing → phishing
            if ia_prob['phishing'] >= 0.7:
                confidence = (ia_prob["phishing"] * 0.5) + (0.5 * prob_passive)
                return {
                    'final_decision': 'phishing',
                    'confidence': float(f'{confidence:.2f}'),
                    'source': 'ia_prediction(confiance_moyenne) && passive_analyse',
                    'breakdown': {
                        'ia_pred_proba': float(f"{ia_prob['phishing']:.3f}"),
                        'ia_pred': ia_pred['predict'].get('0', None) or ia_pred['predict'].get(0, None),
                        'passive_analyze_prob': float(f'{prob_passive:.3f}'),
                        'passive_analyze_level': risk_level.upper()
                    }
                }
            # CAS 5-2: IA incertain → suspicious
            else:
                confidence = max(ia_prob["phishing"], prob_passive)
                return {
                    'final_decision': 'suspicious',
                    'advice': 'Faites attention, ne divulguez pas d\'informations trop personnelles à moins d\'avoir confiance',
                    'confidence': float(f'{confidence:.2f}'),
                    'source': 'ia_prediction(confiance_faible) && passive_analyse',
                    'breakdown': {
                        'ia_pred_proba_phishing': float(f"{ia_prob['phishing']:.3f}"),
                        'ia_pred_proba_safe': float(f"{ia_prob['safe']:.3f}"),
                        'ia_pred': ia_pred['predict'].get('0', None) or ia_pred['predict'].get(0, None),
                        'passive_analyze_prob': float(f'{prob_passive:.3f}'),
                        'passive_analyze_level': risk_level.upper()
                    }
                }

        # FALLBACK SAFE
        return {
            'final_decision': 'safe',
            "advice": "Faites attention ",
            'confidence': (ia_prob["phishing"] * 0.6) + (0.5 * prob_passive),
            'source': 'default_safe',
            'breakdown': {
                'ia_pred_proba': float(f"{ia_prob['safe']:.3f}"),
                'ia_pred': ia_pred['predict'].get('0', None) or ia_pred['predict'].get(0, None),
                'passive_analyze_prob': float(f'{prob_passive:.3f}'),
                'passive_analyze_level': risk_level.upper()
            }
        }

    def predict_url(self, url: str, check_blacklist: bool = False, explain: bool = False,
                    features_func=None, check_right_click: bool = False):
        """
        Point d'entrée principal pour l'analyse d'une URL.

        Orchestration complète :
        1. Nettoyage et vérification du cache
        2. Vérification whitelist
        3. Prédiction IA + analyse passive
        4. Décision finale
        5. Mise en cache et historique

        Args:
            url (str): URL à analyser
            check_blacklist (bool): Vérifier la blacklist externe
            explain (bool): Retourner les explications détaillées
            features_func (callable, optional): Fonction d'extraction de features
            check_right_click (bool): Vérifier le blocage du clic droit

        Returns:
            dict: Résultat complet de l'analyse avec décision, confiance, etc.
        """
        global REQUEST_NUMBER

        url = self._clean_url(url)
        cache_key = f"pred_{url}_{check_blacklist}_{explain}"
        cached_result = dcache.get(cache_key)

        if cached_result:
            self.keep_history(cached_result)
            return cached_result

        domain = get_domain(url)

        if domain in _get_legitimate_domain():
            start = time.time()
            result = {
                'url': url,
                'ia_pred': {
                    'predict_proba': {'0': {'phishing': 0.0, 'safe': 1.0}},
                    'predict': {'0': 'safe'},
                    'true_labels': {}
                },
                'passive_pred': {
                    'risk_score': 0,
                    'is_phishing': False,
                    'risk_level': '✅ DOMAINE VÉRIFIÉ',
                    'flag': 'Domaine reconnu et sûr' if explain else ""
                }
            }

            predicts = copy.deepcopy(result)
            end = time.time()

        else:
            start = time.time()
            pred_ia = {}

            if self.PhishingIA is not None:
                if self.PhishingIA.model is None:
                    self.PhishingIA.load_model(self.model_file)
                pred_ia = self.predict_with_ia(url, features_func)

            passive_pred = self.predict_passive_analyze(
                url, check_blacklist=check_blacklist, explain=explain,
                check_right_click=check_right_click
            )
            end = time.time()

            if features_func:
                features = features_func(url)
            else:
                features = features_extractor_from_url(url)

            result = {
                'url': url,
                'ia_pred': pred_ia,
                'passive_pred': passive_pred
            }

            predicts = copy.deepcopy(result)
            with self.lock:
                cce = dcache.get("pred", default={"count": 0, 'features': []})
                new_data = {
                    "count": cce["count"] + 1,
                    "features": cce["features"] + [features]
                }

                dcache.set('pred', new_data, expire=10 * 30 * 24 * 3600)
                rq_number = dcache.get('request_number', default=0)
                dcache.set('request_number', rq_number + 1, expire=30 * 24 * 3600)

                rq_number = dcache.get('all_request_number', default=0)
                dcache.set('all_request_number', rq_number + 1, expire=30 * 24 * 3600)

        result.update(self.final_decision(domain, predicts))
        result.update({'date': datetime.now().strftime('%d/%m/%Y à %H:%M:%S'), 'elapsed': float(f"{end - start:.2f}")})
        dcache.set(cache_key, result, expire=7 * 24 * 3600)
        self.keep_history(result)
        REQUEST_NUMBER += 1
        return result

    async def predict_url_async(
        self,
        url: str,
        check_blacklist: bool = False,
        explain: bool = False,
        features_func=None,
        check_right_click: bool = False
    ) -> dict:
        """
        Version async de predict_url — à utiliser depuis FastAPI.

        Identique à predict_url() mais 100% async :
        - Pas de asyncio.run() imbriqué
        - Pas de nest_asyncio
        - Compatible uvicorn/uvloop

        Orchestration :
            1. Nettoyage + cache
            2. Whitelist check
            3. IA async + passive async (concurrents)
            4. Décision finale
            5. Cache + historique

        Args:
            url (str): URL à analyser
            check_blacklist (bool): Vérifier la blacklist externe
            explain (bool): Retourner les explications détaillées
            features_func (callable, optional): Fonction custom d'extraction
            check_right_click (bool): Vérifier le blocage du clic droit

        Returns:
            dict: Résultat complet — même format que predict_url()
        """
        global REQUEST_NUMBER

        url = self._clean_url(url)
        cache_key = f"pred_{url}_{check_blacklist}_{explain}"
        cached_result = dcache.get(cache_key)

        if cached_result:
            self.keep_history(cached_result)
            return cached_result

        domain = get_domain(url)
        print("VERIF WHITELIST", time.time())
        if domain in _get_legitimate_domain():
            start = time.time()
            result = {
                'url': url,
                'ia_pred': {
                    'predict_proba': {'0': {'phishing': 0.0, 'safe': 1.0}},
                    'predict': {'0': 'safe'},
                    'true_labels': {}
                },
                'passive_pred': {
                    'risk_score': 0,
                    'is_phishing': False,
                    'risk_level': '✅ DOMAINE VÉRIFIÉ',
                    'flag': 'Domaine reconnu et sûr' if explain else ""
                }
            }
            predicts = copy.deepcopy(result)
            end = time.time()
            print("FIN VERIF WHITELIST", time.time())
        else:
            start = time.time()

            if self.PhishingIA is not None and self.PhishingIA.model is None:
                await self._run_async(self.PhishingIA.load_model, self.model_file)
            
            print('DEBUT TACHES', time.time())
            ia_task = asyncio.create_task(
                self.predict_with_ia_async(url, features_func)
            )
            passive_task = asyncio.create_task(
                    self.predict_passive_analyze_async(
                    url,
                    check_blacklist=check_blacklist,
                    explain=explain,
                    check_right_click=check_right_click
                )
            )
            pred_ia, passive_pred = await asyncio.gather(ia_task, passive_task)
            print('FIN TACHE IA PRED', time.time())
            end = time.time()

            if features_func:
                features = await self._run_async(features_func, url)
            else:
                features = await _features_extractor_from_url(url)

            result = {
                'url': url,
                'ia_pred': pred_ia or {},
                'passive_pred': passive_pred
            }
            predicts = copy.deepcopy(result)

            with self.lock:
                cce = dcache.get("pred", default={"count": 0, 'features': []})
                dcache.set('pred', {
                    "count":    cce["count"] + 1,
                    "features": cce["features"] + [features]
                }, expire=10 * 30 * 24 * 3600)

                rq = dcache.get('request_number', default=0)
                dcache.set('request_number', rq + 1, expire=30 * 24 * 3600)

                rq_all = dcache.get('all_request_number', default=0)
                dcache.set('all_request_number', rq_all + 1, expire=30 * 24 * 3600)

        result.update(self.final_decision(domain, predicts))
        result.update({
            'date':    datetime.now().strftime('%d/%m/%Y à %H:%M:%S'),
            'elapsed': float(f"{end - start:.2f}")
        })

        dcache.set(cache_key, result, expire=7 * 24 * 3600)
        self.keep_history(result)
        REQUEST_NUMBER += 1
        return result
    
    def predict_email(self, email_text: str, check_blacklist: bool = False) -> dict:
        """
        Analyse un email complet (texte brut).
        
        Args:
            email_text: Contenu brut de l'email
            check_blacklist: Vérifier les blacklists sur les URLs
        
        Returns:
            dict: Résultat de l'analyse
        """
        
        try:
            loop = asyncio.get_running_loop()
            task = _analyze_mail(
                raw_mail=email_text,
                anti_phishing_instance=self,
                history_dir=HISTORY_FILE,
                check_blacklist=check_blacklist
            )
            result = loop.run_until_complete(task)
        except RuntimeError:
            result = asyncio.run(_analyze_mail(
                raw_mail=email_text,
                anti_phishing_instance=self,
                history_dir=HISTORY_FILE,
                check_blacklist=check_blacklist
            ))
        
        return result
    
    async def predict_email_async(self, email_text: str, check_blacklist: bool = False) -> dict:
        """
        Analyse un email complet (texte brut).
        
        Args:
            email_text: Contenu brut de l'email
            check_blacklist: Vérifier les blacklists sur les URLs
        
        Returns:
            dict: Résultat de l'analyse
        """
        
        return await _analyze_mail(
            raw_mail=email_text,
            check_blacklist=check_blacklist, 
            history_dir=HISTORY_FILE,
            anti_phishing_instance=self,
        )
    
    def predict_email_from_file(self, eml_path: str, check_blacklist: bool = False) -> dict:
        """
        Analyse un email depuis un fichier .eml.
        
        Args:
            eml_path: Chemin vers le fichier .eml
            check_blacklist: Vérifier les blacklists sur les URLs
        
        Returns:
            dict: Résultat de l'analyse
        """
        with open(eml_path, 'r', encoding='utf-8', errors='replace') as f:
            email_text = f.read()
        return self.predict_email(email_text, check_blacklist)
    
    async def predict_email_from_file_async(self, eml_path: str, check_blacklist: bool = False) -> dict:
        """
        Analyse un email depuis un fichier .eml.
        
        Args:
            eml_path: Chemin vers le fichier .eml
            check_blacklist: Vérifier les blacklists sur les URLs
        
        Returns:
            dict: Résultat de l'analyse
        """
        with open(eml_path, 'r', encoding='utf-8', errors='replace') as f:
            email_text = f.read()
        return await self.predict_email_async(email_text, check_blacklist)
    
    def _refit(self, cce):
        """
        Ré-entraîne le modèle avec les nouvelles données collectées.

        Args:
            cce (dict): Données collectées (features)

        Returns:
            bool: True si le modèle a été mis à jour, False sinon
        """
        print("🔄 Début du refit...")
        self.refit_in_progress = True
        fitted = False
        import pandas as pd
        from sklearn.model_selection import train_test_split as tts

        try:
            if cce['count'] >= self.refit_time:
                data = pd.DataFrame(cce['features'])
                if self.path_to_original_dataset and os.path.exists(self.path_to_original_dataset):
                    data1 = pd.DataFrame(joblib.load(self.path_to_original_dataset))
                    data = pd.concat([data1, data], axis=0)

                for i in ('.joblib', '.pkl'):
                    if i in self.PhishingIA.dataset_file:
                        dataset_file = self.PhishingIA.dataset_file.replace(i, f"_temp{i}")

                new_model = PhishingIA(
                    model_dir_=self.model_dir + '_refit_mod_temp',
                    model_file=self.model_path,
                    dataset_file=dataset_file,
                    cv=2
                )
                train, test = tts(data, test_size=0.1)

                new_model.fit(train, _all_=self._all_, smote=False)
                fitted = True
                best_model, comparison = self.compare(
                    self.PhishingIA,
                    new_model,
                    test,
                    threshold=self.comparison_threshold
                )

                self._save_comparison_report(comparison)
                if comparison['winner'] == 'model2' and self.backup_models:
                    self._backup_current_model()

                if comparison['winner'] == 'model2':
                    print("✅ Mise à jour vers le nouveau modèle")
                    self.PhishingIA = best_model
                    self.last_refit_time = datetime.now()
                    return True
                else:
                    print("⚠️  Conservation du modèle actuel")
                    return False

        except Exception as e:
            print(f"❌ Erreur pendant le refit: {e}")
            import traceback
            traceback.print_exc()
            fitted = False
            return False

        finally:
            if fitted:
                with self.lock:
                    dcache.set('pred', {"count": 0, 'features': []}, expire=30 * 24 * 3600)
            self.refit_in_progress = False

    def compare(self, mod1: PhishingIA, mod2: PhishingIA, test, threshold):
        """Compare deux modèles PhishingIA."""
        return compare_phishing_ia_models(mod1, mod2, test, threshold)

    def _backup_current_model(self):
        """Sauvegarde de backup du modèle actuel."""
        import shutil
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{self.model_file}.backup_{timestamp}"
        try:
            shutil.copy2(self.model_file, backup_path)
            print(f"💾 Backup sauvegardé: {backup_path}")
        except Exception as e:
            print(f"⚠️  Erreur backup: {e}")

    def _save_comparison_report(self, comparison):
        """Sauvegarde le rapport de comparaison."""
        report_path = f"refit_reports/comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs("refit_reports", exist_ok=True)

        try:
            with open(report_path, 'w') as f:
                json.dump(comparison, f, indent=2)
            print(f"📄 Rapport sauvegardé: {report_path}")
        except Exception as e:
            print(f"⚠️  Erreur sauvegarde rapport: {e}")

    def refit_model(self):
        """
        Lance le thread de surveillance pour le refit automatique.

        Returns:
            threading.Thread: Thread de surveillance
        """
        self.event = threading.Event()

        def monitor(event):
            while not event.is_set():
                try:
                    time.sleep(0.5)
                    with self.lock:
                        cce = dcache.get("pred", default={"count": 0, 'features': []})
                    if cce['count'] >= self.refit_time:
                        print('Refit enclenché, veuillez ne pas fermer l\'app !')
                        success = self._refit(cce)
                        if success:
                            print("✅ Refit terminé avec succès!")
                        else:
                            print("⚠️  Refit terminé, modèle conservé")
                except KeyboardInterrupt:
                    print('\n🛑 Interruption détectée dans le thread de surveillance')
                    self.event.set()
                    time.sleep(5)
                except Exception as e:
                    print(f'⚠️ Erreur dans le monitor: {e}')

        print("Lancement du thread de surveillance")
        th = threading.Thread(target=monitor, args=(self.event,), daemon=False)
        th.start()
        return th

    def close(self):
        """Arrêt propre du système."""
        def _close():
            # Attendre la fin du refit si en cours
            if self.refit_in_progress:
                print("⏳ Attente de la fin du refit...")
                i = 0
                while self.refit_in_progress:
                    time.sleep(1)
                    print(f'{i} secondes', end='\r')
                    i += 1
            # Arrêter le thread de monitoring
            self.event.set()
            self.th.join(timeout=10)
            print("✅ Système arrêté proprement")

        atexit.register(_close)

    def keep_history(self, result: dict):
        """
        Sauvegarde l'historique des analyses.

        Args:
            result (dict): Résultat de l'analyse
        """
        current_json = []
        current_txt = ''
        text_file = str(self.history_file).replace('.json', '.txt')

        if os.path.exists(self.history_file):
            with open(self.history_file, "r", encoding='utf-8') as f:
                try:
                    current_json = json.load(f)
                except Exception as e:
                    print('Erreur lors de la lecture du fichier historique json actuel : ', e)

            with open(text_file, "r", encoding='utf-8') as f:
                try:
                    current_txt = f.read()
                except Exception as e:
                    print('Erreur lors de la lecture du fichier historique txt actuel : ', e)

        current_json.append(result)

        txt = []
        txt.append("=" * 100)
        txt.append('\n')
        txt.append(f'URL : {result.get("url", "")}')
        txt.append(f"  -Décision finale : {result.get('final_decision', '')}")
        txt.append(f"  -Source : {result.get('source', '')}")
        txt.append(f"  -Confiance : {result.get('confidence', '')}")
        txt.append(f"  -Date d'analyse : {result.get('date', '')}")
        txt.append(f"  -Date actuelle : {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}")
        txt.append(f"  -Durée : {result.get('elapsed', '')} {'secondes' if (result.get('elapsed', '') >= 2) else 'seconde'}")

        r = result.get('breakdown', {}).get('ia_pred_proba', 0)
        txt.append(f"  -Confiance IA  : {r}")

        r = result.get('breakdown', {}).get('ia_pred', '')
        txt.append(f"  -Décision IA : {r}")

        r = result.get('breakdown', {}).get('passive_analyze_prob', 0)
        txt.append(f"  -Confiance analyse passive  : {r}")

        r = result.get('breakdown', {}).get('passive_analyze_level', '')
        txt.append(f"  -Décision analyse passive : {r} \n")

        texte = "\n".join(txt)
        txt.append("=" * 100)

        count = current_txt.count("URL")
        mot1 = f"TOTAL : {count} \n"

        mot = f'\nCeci est juste un résumé, pour plus d\'info, consultez le résumé json à {self.history_file} '
        current_txt = current_txt.replace(mot1, '')

        new_txt = (current_txt.replace(mot, '')) + f'\n {texte}' + mot

        count = new_txt.count("URL")
        mot1 = f"TOTAL : {count} \n"
        new_txt = mot1 + (current_txt.replace(mot, '')) + f'\n {texte}' + mot

        js = False
        with open(self.history_file, encoding="utf-8", mode="w") as f:
            try:
                json.dump(current_json, f, indent=2, ensure_ascii=False)
                js = True
                print('Historique dans : ', self.history_file)
            except Exception as e:
                print('Erreur lors de la sauvegarde du fichier historique json : ', e)

        with open(text_file, encoding="utf-8", mode="w") as f:
            try:
                f.write(new_txt)
                print('Historique dans : ', text_file)
            except Exception as e:
                print('Erreur lors de la sauvegarde du fichier historique json : ', e)

        return {
            'json': self.history_file if js else '',
            'txt': text_file,
        }

    def get_history(self, mode='all'):
        """
        Récupère l'historique des analyses.

        Args:
            mode (str): 'all', 'json', ou 'txt'

        Returns:
            dict: Historique dans le format demandé
        """
        text_file = str(self.history_file).replace('.json', '.txt')
        mode = mode.lower()
        current_txt = ''
        current_json = []
        error = []

        if mode == 'all' or mode not in ('txt', 'json'):
            if os.path.exists(self.history_file):
                with open(self.history_file, "r", encoding='utf-8') as f:
                    try:
                        current_json = json.load(f)
                    except Exception as e:
                        print('Erreur lors de la lecture du fichier historique json actuel : ', e)
                        error.append(e)
                with open(text_file, "r", encoding='utf-8') as f:
                    try:
                        current_txt = f.read()
                    except Exception as e:
                        print('Erreur lors de la lecture du fichier historique txt actuel : ', e)
                        error.append(e)

            return {
                'json': current_json,
                'txt': current_txt,
                "mode": "all",
                "error": error
            }
        if mode == 'json':
            if os.path.exists(self.history_file):
                with open(self.history_file, "r", encoding='utf-8') as f:
                    try:
                        current_json = json.load(f)
                    except Exception as e:
                        print('Erreur lors de la lecture du fichier historique json actuel : ', e)
                        error.append(e)
            return {
                'json': current_json,
                'txt': current_txt,
                "mode": "all",
                "error": error
            }
        else:
            if os.path.exists(self.history_file):
                with open(text_file, "r", encoding='utf-8') as f:
                    try:
                        current_txt = f.read()
                    except Exception as e:
                        print('Erreur lors de la lecture du fichier historique txt actuel : ', e)
                        error.append(e)
            return {
                'json': current_json,
                'txt': current_txt,
                "mode": "all",
                "error": error
            }


# ============================================================================
# FONCTIONS DE GESTION DU SERVEUR
# ============================================================================

def start(app, host, port):
    """
    Démarre le serveur FastAPI dans un thread séparé.

    Args:
        app (FastAPI): Application FastAPI
        host (str): Hôte d'écoute
        port (int): Port d'écoute

    Returns:
        tuple: (thread, server)
    """
    global server
    config = uvicorn.Config(app, host=host, port=port, workers=10, loop=get_loop(), use_colors=True)
    server = uvicorn.Server(config=config)
    th = threading.Thread(target=server.run, daemon=True)
    return th, server


def get_ap_instance(lock=_global_lock, *args, **kwargs):
    """
    Retourne l'instance singleton d'AntiPhishing.
    Lit la configuration depuis DATA (config.py).

    Returns:
        AntiPhishing: Instance unique d'AntiPhishing
    """
    global _global_ap_instance
    from anti_phishing_ia.config import DATA
    with lock:
        if _global_ap_instance is None:
            _global_ap_instance = AntiPhishing(
                model_dir=DATA['model_dir'],
                model_path=DATA['model_path'],
                refit_time=DATA['refit_time'],
                features_name=DATA['features_name'],
                n_features=DATA['n_features'],
                backup_models=DATA['backup_models'],
                path_to_original_dataset=DATA['path_to_original_dataset'],
                comparison_threshold=DATA['comparison_threshold'],
                _all_=DATA['_all_'],
                refit=DATA['refit'],
                mail_model_dir=DATA["mail_model_dir"],
                mail_model_type=DATA["mail_model_type"]
            )
        else:
            # Mettre à jour les paramètres légers sans recréer
            _global_ap_instance.refit_time = DATA['refit_time']
            _global_ap_instance.comparison_threshold = DATA['comparison_threshold']
            _global_ap_instance.backup_models = DATA['backup_models']
        return _global_ap_instance


def stop(th, timeout=5):
    """
    Arrête un thread.

    Args:
        th (threading.Thread): Thread à arrêter
        timeout (int): Timeout en secondes
    """
    print('Arrêt des threads...')
    th.join(timeout)
    print('Threads arrêtés')


# ============================================================================
# CONFIGURATION DU LIMITER
# ============================================================================

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Gestionnaire d'exception pour le rate limiting."""
    return JSONResponse(
        status_code=429,
        content={
            "error": "Trop rapide!",
            "message": f"{REQUEST} requêtes max par minute",
            "retry_after": 60
        }
    )


# ============================================================================
# ENDPOINTS API
# ============================================================================

@router.post(path='/settings')
@limiter.limit(f"{REQUEST}/minute")
def _set_settings(request: Request, setting: Settings):
    """
    Met à jour les paramètres globaux de l'application.

    Args:
        request (Request): Requête FastAPI
        setting (Settings): Nouveaux paramètres

    Returns:
        dict: Statut de l'opération
    """
    try:
        if setting:
            import anti_phishing_ia.config as AC
            DATA = AC.DATA
            DATA.update(setting)
            AC.DATA = DATA

            return {
                "message": "Paramètres reçus correctement !",
                "status": "Succès",
                "settings": setting,
                "errors": []
            }
        else:
            return {
                "message": "Paramètres non reçus correctement !",
                "status": "Erreur",
                "settings": setting,
                "errors": ["settings absents !"]
            }

    except Exception as e:
        return {
            "message": "Paramètres non reçus correctement !",
            "status": "Erreur",
            "settings": setting,
            "errors": [e]
        }


@router.get(path='/get_settings')
@limiter.limit(f"{REQUEST}/minute")
def _get_setting(request: Request):
    """
    Récupère les paramètres actuels de l'application.

    Args:
        request (Request): Requête FastAPI

    Returns:
        dict: Paramètres actuels
    """
    try:
        from anti_phishing_ia.config import DATA
        return dict(DATA)
    except Exception:
        to_return = {
            'url': '',
            'model_dir': 'model',
            'model_path': 'model_phish.pkl',
            'check_blacklist': False,
            "check_right_click": False,
            'explain': False,
            'refit_time': 3,
            '_all_': False,
            'backup_models': True,
            'path_to_original_dataset': DATA["path_to_original_dataset"],
            'comparison_threshold': 0.03,
            "features_name": FEATURES_NAME,
            'n_features': len(FEATURES_NAME),
            'refit': False,
        }
    
        return to_return


@router.get(path='/history')
@limiter.limit(f"{REQUEST}/minute")
def _get_history(request: Request, mode: str = "all"):
    """
    Récupère l'historique des analyses.

    Args:
        request (Request): Requête FastAPI

    Returns:
        dict: Historique des analyses
    """
    global _global_ap_instance

    if _global_ap_instance:
        return _global_ap_instance.get_history(mode)
    else:
        return {
            "json": [],
            'txt': "",
            "mode": mode,
            "error": ["AntiPhishing instance indisponible ! "]
        }


@router.post(path='/analyze')
@limiter.limit(f"{REQUEST}/minute")
async def _analyze_url(request: Request, data: AnalyzeUrlData):
    """
    Analyse une URL pour détecter du phishing.

    Endpoint principal de l'API.

    Args:
        request (Request): Requête FastAPI
        data (AnalyzeUrlData): Données contenant l'URL et les paramètres

    Returns:
        dict: Résultat de l'analyse
    """
    try:
        AP = get_ap_instance()

        print(f"Analyse demandée par {request.client.host} pour {data.url}  à {time.ctime()}")
        predict = await AP.predict_url_async(
            url=data.url,
            explain=data.explain,
            features_func=None,
            check_blacklist=data.check_blacklist,
            check_right_click=data.check_right_click,
        )
        # return await asyncio.to_thread(
        #     AP.predict_url,
        #     **dict(
        #         url=data.url,
        #         explain=data.explain,
        #         features_func=None,
        #         check_blacklist=data.check_blacklist,
        #         check_right_click=data.check_right_click,)
        # )
        return predict
    except Exception as e:
        return {
            'error': str(e),
            'ia_pred': {'predict': {'0': 'error'}},
            'passive_pred': {'risk_level': '❌ ERREUR'}
        }


@router.post(path="/analyze_mail")
@limiter.limit(f"{REQUEST}/minute")
async def _analyze_mail_route(
    request: Request,
    files: Optional[List[UploadFile]] = File(default=None),
    mails: Optional[List[str]]        = Form(default=None),
    check_blacklist: bool             = Form(default=False),
):
    """
    Analyse un ou plusieurs emails pour détecter du phishing.

    Accepte :
        - files : liste de fichiers .eml uploadés
        - mails : liste de textes bruts (mail collé directement)
        - Les deux simultanément

    Au moins un des deux doit être fourni.

    Returns:
        dict: {
            'results': list,   # Un résultat par mail analysé
            'total': int,
            'phishing_count': int,
            'safe_count': int,
            'suspicious_count': int,
        }
    """
    global REQUEST_NUMBER
    REQUEST_NUMBER += 1
    # Validation : au moins un input
    has_files = files and any(f.filename for f in files)
    has_mails = mails and any(m.strip() for m in mails)

    if not has_files and not has_mails:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=422,
            detail="Fournissez au moins un fichier .eml ou un texte de mail."
        )

    AP = get_ap_instance()

    raw_mails = []

    # Lire les fichiers uploadés
    if has_files:
        for f in files:
            if not f.filename:
                continue
            try:
                content = await f.read()
                raw_mails.append(content.decode("utf-8", errors="replace"))
            except Exception as e:
                print(f"Erreur lecture fichier {f.filename} : {e}")

    # Ajouter les textes bruts
    if has_mails:
        for m in mails:
            if m and m.strip():
                raw_mails.append(m.strip())

    if not raw_mails:
        raise HTTPException(
            status_code=422,
            detail="Aucun mail valide trouvé dans les inputs."
        )

    # Analyser chaque mail
    results = []
    for raw in raw_mails:
        try:
            result = await _analyze_mail(
                raw_mail=raw,
                anti_phishing_instance=AP,
                history_dir=HISTORY_FILE,
                check_blacklist=check_blacklist,
            )
            results.append(result)
        except Exception as e:
            import traceback
            traceback.print_exc()
            results.append({
                "final_decision": "error",
                "error": str(e),
                "date": datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
            })

    # Statistiques globales
    phishing_count   = sum(1 for r in results if r.get("final_decision") == "phishing")
    safe_count       = sum(1 for r in results if r.get("final_decision") == "safe")
    suspicious_count = sum(1 for r in results if r.get("final_decision") == "suspicious")

    print(
        f"Analyse mail — {request.client.host} — "
        f"{len(results)} mail(s) — "
        f"{phishing_count} phishing / {safe_count} safe / {suspicious_count} suspicious"
        f" à {time.ctime()}"
    )

    return {
        "results":          results,
        "total":            len(results),
        "phishing_count":   phishing_count,
        "safe_count":       safe_count,
        "suspicious_count": suspicious_count,
    }

@router.get(path="/history_mail")
@limiter.limit(f"{REQUEST}/minute")
def _get_history_mail(request: Request, mode: str = "all"):
    """
    Récupère l'historique des analyses mail.

    Args:
        mode: 'all' | 'json' | 'txt'

    Returns:
        dict: Historique dans le format demandé
    """
    json_file = os.path.join(HISTORY_FILE, "history_mail.json")
    txt_file  = os.path.join(HISTORY_FILE, "history_mail.txt")

    current_json = []
    current_txt  = ""
    errors       = []

    if mode in ("all", "json"):
        if os.path.exists(json_file):
            with open(json_file, "r", encoding="utf-8") as f:
                try:
                    current_json = json.load(f)
                except Exception as e:
                    errors.append(str(e))

    if mode in ("all", "txt"):
        if os.path.exists(txt_file):
            with open(txt_file, "r", encoding="utf-8") as f:
                try:
                    current_txt = f.read()
                except Exception as e:
                    errors.append(str(e))

    return {
        "json":   current_json,
        "txt":    current_txt,
        "mode":   mode,
        "errors": errors,
    }

@router.get("/rate-limit-status")
@limiter.limit(f"{REQUEST}/minute")
async def rate_limit_status(request: Request):
    """
    Retourne le statut du rate limiting.

    Args:
        request (Request): Requête FastAPI

    Returns:
        dict: Statut du rate limiting
    """
    return {
        "ip": get_remote_address(request),
        "limit": f"{REQUEST}/minute"
    }


@router.get('/close')
def _close_api():
    """
    Ferme proprement l'API.

    Returns:
        dict: Message de confirmation
    """
    global server
    if server is None:
        print('Serveur non lancé !')
        return {
            "message ": "Serveur non lancé !"
        }
    else:
        server.should_exit = True
        print('Serveur fermé.')
        return {
            "message ": 'Serveur fermé.'
        }


@router.get("/debug-mount")
async def debug_mount():
    """
    Endpoint de debug pour vérifier les montages React.

    Returns:
        dict: Informations de debug
    """
    from pathlib import Path

    directory_react = DIRECTORY_REACT
    build_dir = BUILD_DIR if 'BUILD_DIR' in globals() else "Non défini"

    static_dir = Path(directory_react)
    js_dir = static_dir / "js"
    main_js = js_dir / "main.993485cd.js"

    mounts = []
    for route in app.routes:
        if hasattr(route, 'path') and hasattr(route, 'app'):
            mounts.append({
                "path": route.path,
                "name": getattr(route, 'name', 'N/A')
            })

    return {
        "DIRECTORY_REACT": str(directory_react),
        "BUILD_DIR": str(build_dir),
        "static_dir_exists": static_dir.exists(),
        "js_dir_exists": js_dir.exists(),
        "main_js_exists": main_js.exists(),
        "main_js_path": str(main_js),
        "js_files": [f.name for f in js_dir.glob("*.js")] if js_dir.exists() else [],
        "mounts": mounts,
        "all_routes": [{"path": r.path, "name": getattr(r, 'name', 'N/A')} for r in app.routes[:10]]
    }


@router.get("/health")
def health(request: Request):
    """
    Endpoint de health check.

    Args:
        request (Request): Requête FastAPI

    Returns:
        dict: État de santé de l'API
    """
    dic = {
        "status": "healthy",
        "date": datetime.now().isoformat(),
        "ml_available": ML_AVAILABLE,
        "react": REACT_EXISTS,
        "rate_limit": REQUEST,
        "current_request_number": REQUEST_NUMBER,
        "month_request_number": dcache.get('request_number', default=0),
        "all_request_number": dcache.get("all_request_number", default=0)
    }
    return dic


@router.get("/debug-files")
async def debug_files():
    """
    Endpoint de debug pour lister les fichiers React.

    Returns:
        dict: Liste des fichiers React
    """
    import os
    react_files = []
    for root, dirs, files in os.walk(DIRECTORY_REACT):
        for file in files:
            react_files.append(os.path.join(root, file))

    return {
        "react_exists": REACT_EXISTS,
        "build_path": str(DIRECTORY_REACT),
        "files": react_files[:20],
        "index.html_exists": os.path.exists(DIRECTORY_REACT / "index.html")
    }


# ============================================================================
# INCLUSION DU ROUTER
# ============================================================================

app.include_router(router, prefix="/api")


# ============================================================================
# ROUTES PRINCIPALES
# ============================================================================

@app.get("/")
async def serve_react_app():
    """
    Sert l'application React (point d'entrée).

    Returns:
        FileResponse or dict: Interface React ou message d'erreur
    """
    if REACT_EXISTS:
        return FileResponse(INDEX_HTML)
    else:
        return {
            "message": "API Anti-Phishing - Interface React non disponible",
            "instructions": "Build React manquant. Exécutez: npm run build dans le dossier frontend",
            "api_available": True,
            "api_docs": "/api/docs",
            "endpoints": {
                "POST /api/analyze": "Analyse une URL",
                "GET /api/close": "Ferme le serveur",
                "POST /api/health": "Etat de santé et stats",
                "GET /api/rate-limit-status": "Obtenir la limitation de requête par minute",
                "GET /api/docs": "Documentation FastAPI",
                "GET /api/redoc": "Documentation FastAPI",
                "GET /api/openapi.json": "Info sur l'api actuellement",
                "POST api/settings": "Mettre a jour les paramètres d'analyse",
                "GET /api/history": "Obtenir l'historique des analyses",
                "GET /api/get_settings": "Obtenir les paramètres actuels",
            },
            "rate_limit": f"{REQUEST} requêtes/minute"
        }


@app.get("/{full_path:path}")
async def catch_all(full_path: str):
    """
    Capture toutes les routes pour React Router (SPA).

    Args:
        full_path (str): Chemin demandé

    Returns:
        FileResponse or HTTPException: Fichier React ou erreur 404
    """
    excluded_prefixes = ["api/", "docs", "redoc", "openapi.json"]

    print(full_path)
    if any(full_path.startswith(prefix) for prefix in excluded_prefixes):
        raise HTTPException(404, detail="Route non trouvée")

    if full_path.startswith("static/"):
        return FileResponse(os.path.join(BUILD_DIR, full_path))

    if REACT_EXISTS:
        return FileResponse(INDEX_HTML)

    raise HTTPException(status_code=404, detail="Route non trouvée")


# ============================================================================
# FONCTIONS UTILITAIRES POUR LA FERMETURE
# ============================================================================

async def analyze_url(url, data: dict, session):
    """Analyse une URL via l'API (utilitaire)."""
    async with session:
        async with session.post(url, json=data) as response:
            resp = await response.json()
            return resp, response


async def close_api(url):
    """Ferme l'API (utilitaire)."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            print('Statut : ', response.status)


def close_api_atexit(url):
    """Enregistre la fermeture de l'API à la sortie."""
    def _close():
        try:
            from modules_utils.loop_utils import _run_async
            _run_async(close_api, url)
        except Exception:
            pass
        # asyncio.run(close_api(url))
    atexit.register(_close)


async def run(host: str, port: str, app: FastAPI, url: str):
    """
    Exécute une analyse unique via l'API.

    Args:
        host (str): Hôte de l'API
        port (str): Port de l'API
        app (FastAPI): Application FastAPI
        url (str): URL à analyser

    Returns:
        dict: Résultat de l'analyse
    """
    try:
        from anti_phishing.config import DATA
    except Exception:
        raise ModuleNotFoundError("DATA manquant dans anti_phishing.config, veuillez le créer !")

    th, _ = start(app, host, port)
    th.start()
    time.sleep(2)

    try:
        result = {"error": []}
        target = f'http://{host}:{port}/api/analyze'
        async with aiohttp.ClientSession() as session:
            DATA["url"] = url
            try:
                async with session.post(target, json=DATA) as response:
                    if response.status == 200:
                        result1 = await response.json()
                        result.update(result1)
                        try:
                            result = json.dumps(result, indent=2, ensure_ascii=False)
                        except Exception:
                            pass
                        print(f"✅ Résultat: {result}")
                    else:
                        error_text = await response.text()
                        print(f"❌ Erreur HTTP {response.status}: {error_text}")
                        result['error'].append(f"❌ Erreur HTTP {response.status}: {error_text}")

            except Exception as e:
                print(f"❌ Erreur: {e}")
                result['error'].append(f"❌ Erreur: {e}")

    except KeyboardInterrupt:
        print("\n⏹️ Analyse interrompue par l'utilisateur")

    finally:
        input("Fermé ? ")
        stop(th, 2)
        await close_api(target.replace('/analyze', "/close"))
        return result


# ============================================================================
# POINT D'ENTRÉE PRINCIPAL
# ============================================================================

if __name__ == '__main__':
    nest_asyncio.apply()
    test_urls0 = [
        # URLs malveillantes (devraient scorer haut)
        "http://192.168.1.1/login.php",
        "https://paypal-verification-security.com/account/update",
        "https://xn--mcrosoft-8g0a.com/security/",

        # URLs légitimes (devraient scorer bas)
        "https://www.amazon.com/",
        "https://accounts.google.com/",
        "https://www.paypal.com/signin/",
    ]
    test_urls1 = [
        # Légitimes
        "https://www.amazon.com/",
        "https://accounts.google.com/",
        "https://www.paypal.com/signin/",
        "https://github.com/login",
        "https://www.netflix.com/",

        # Phishing
        "http://192.168.1.1/login.php",
        "https://paypal-verification-security.com/account/update",
        "https://xn--mcrosoft-8g0a.com/security/",
        "http://goog1e.com/login/",
        "https://secure-amazon-update.xyz/verify/",
    ]
    test_urls = list(set(test_urls0 + test_urls1))

    target = f'http://{host}:{port}/api/analyze'
    close_api_atexit(target.replace('/analyze', '/close'))

    def run_tests(test_urls):
        AP = AntiPhishing('model_phish.pkl', model_dir='model')
        print("\n" + "=" * 60)
        print("🧪 LANCEMENT DES TESTS ANTI-PHISHING")
        print("=" * 60)
        for i, u in enumerate(test_urls, 1):
            print(f"\n📊 Test {i}/{len(test_urls)}: {u}")
            try:
                print(json.dumps(AP.predict_url(url=u, explain=True), indent=2, ensure_ascii=False))
            except Exception:
                print(AP.predict_url(u))
        print("\n" + "=" * 60)
        print("✅ TESTS TERMINÉS")
        print("=" * 60)

    def test_fast_api(app, host, port):
        js = {
            'url': '',
            'model_dir': 'model',
            'model_path': 'model_phish.pkl',
            'check_blacklist': False,
            "check_right_click": False,
            'explain': True,
            'refit_time': 3,
            '_all_': False,
            'backup_models': True,
            'path_to_original_dataset': DATA["path_to_original_dataset"],
            'comparison_threshold': 0.03,
            "features_name": FEATURES_NAME,
            'n_features': len(FEATURES_NAME),
            'refit': False,
        }
        th, _ = start(app, host, port)
        th.start()
        time.sleep(2)

        print('✅ Serveur démarré, début des tests...')
        print('Hi')

        async def _tests():
            async with aiohttp.ClientSession() as session:
                for i, u in enumerate(test_urls, 1):
                    print(f"\n🔍 Test API {i}/{len(test_urls)}: {u}")
                    js_ = js.copy()
                    js_['url'] = u
                    try:
                        async with session.post(target, json=js_) as response:
                            if response.status == 200:
                                result = await response.json()
                                try:
                                    result = json.dumps(result, indent=2, ensure_ascii=False)
                                except Exception:
                                    pass
                                print(f"✅ Résultat: {result}")
                            else:
                                error_text = await response.text()
                                print(f"❌ Erreur HTTP {response.status}: {error_text}")
                    except Exception as e:
                        print(f"❌ Erreur: {e}")

        try:
            asyncio.run(_tests())
        except KeyboardInterrupt:
            print("\n⏹️ Tests interrompus par l'utilisateur")
        finally:
            input("Fermé ? ")
            stop(th, 3)
            asyncio.run(close_api(target.replace('/analyze', "/close")))

    print(test_fast_api(app, host=host, port=port))
    print()
    input()
    print()
    run_tests(test_urls)