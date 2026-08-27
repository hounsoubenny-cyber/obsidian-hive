#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trainer pour la détection de phishing dans les emails.
Adapté pour MailEncoder (sortie 3D uniquement) - sans features, sans ml_features.

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import torch
import torch.nn as nn
import torchmetrics
import numpy as np
from matplotlib import pyplot as plt
from tqdm import tqdm
from anti_phishing_ia.dl_model.callbacks import EarlyStopping
from anti_phishing_ia.phishing_utils.logger import get_logger
from anti_phishing_ia.dl_model.mail_encoder import MailEncoder
from anti_phishing_ia.dl_model.amp_mixin import AMPMixin

logger = get_logger()
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

CHECKPOINTS_DIR = os.path.join(os.path.dirname(__file__), "checkpoints_model")
os.makedirs(CHECKPOINTS_DIR, exist_ok=True)

class MailPhishingTrainer(AMPMixin, nn.Module):
    """
    Trainer pour MailPhishing
    
    Utilise:
    - MailEncoder pour les embeddings (sortie 3D)
    - MailPhishing pour la classification
    """
    
    def __init__(
        self,
        model,                     # MailPhishing
        loss,
        optimizer,
        scheduler,
        mail_encoder: MailEncoder,
        task: str = "binary",
        num_classe: int = 2,
        each_epochs: bool = True,
        compile_model: bool = True,
        compile_loss: bool = True,
        compile_steps: bool = False,
        use_amp: bool = None,
    ):
        super().__init__()
        self._init_amp(use_amp) 
        self.model = model
        self.loss = loss
        self.optimizer = optimizer
        self.scheduler = scheduler
        self.task = task
        self.each_epochs = each_epochs
        self.mail_encoder = mail_encoder
        
        if compile_model:
            self.model = torch.compile(model)
            self.mail_encoder = torch.compile(mail_encoder)
        if compile_loss:
            self.loss = torch.compile(loss)
        if compile_steps:
            self.train_step = torch.compile(self.train_step)
            self.val_step = torch.compile(self.val_step)
            
        self.num_classe = num_classe
        
        self.metrics = nn.ModuleDict({
            # Accuracy
            "accuracy_macro": torchmetrics.Accuracy(task=self.task, num_classes=num_classe, average="macro"),
            "accuracy_micro": torchmetrics.Accuracy(task=self.task, num_classes=num_classe, average="micro"),
            "accuracy_weighted": torchmetrics.Accuracy(task=self.task, num_classes=num_classe, average="weighted"),
            
            # Precision
            "precision_macro": torchmetrics.Precision(task=self.task, num_classes=num_classe, average="macro"),
            "precision_micro": torchmetrics.Precision(task=self.task, num_classes=num_classe, average="micro"),
            "precision_weighted": torchmetrics.Precision(task=self.task, num_classes=num_classe, average="weighted"),
            
            # Recall
            "recall_macro": torchmetrics.Recall(task=self.task, num_classes=num_classe, average="macro"),
            "recall_micro": torchmetrics.Recall(task=self.task, num_classes=num_classe, average="micro"),
            "recall_weighted": torchmetrics.Recall(task=self.task, num_classes=num_classe, average="weighted"),
            
            # F1Score
            "f1_macro": torchmetrics.F1Score(task=self.task, num_classes=num_classe, average="macro"),
            "f1_micro": torchmetrics.F1Score(task=self.task, num_classes=num_classe, average="micro"),
            "f1_weighted": torchmetrics.F1Score(task=self.task, num_classes=num_classe, average="weighted"),
            
            # Confusion matrix
            "confusion_matrix": torchmetrics.ConfusionMatrix(task=self.task, num_classes=num_classe),
            
            # Jaccard score
            'jaccard_macro': torchmetrics.JaccardIndex(task=self.task, num_classes=num_classe, average='macro'),
            'jaccard_micro': torchmetrics.JaccardIndex(task=self.task, num_classes=num_classe, average='micro'),
            
            # Hamming Loss
            'hamming': torchmetrics.HammingDistance(task=self.task, num_classes=num_classe)
        })
        self.to(device)

    def train_step(self, tokenizer_output, y):
        """
        Étape d'entraînement.
        MailEncoder retourne directement des embeddings 3D.
        """
        y = y.to(device)
        
        if isinstance(self.loss, torch.nn.CrossEntropyLoss):
            y = y.long()
        elif isinstance(self.loss, (torch.nn.BCELoss, torch.nn.BCEWithLogitsLoss)):
            y = y.float()   
        else:
            if self.task == "multiclass":
                y = y.long()
            else:
                y = y.float()   
        self.optimizer.zero_grad()
        with self.amp_autocast():
            # Embedding via MailEncoder (sortie 3D uniquement)
            embedding = self.mail_encoder.predict(tokenizer_output, cache=False, output2d=False)
            embedding = embedding.to(device)
            logits = self.model(embedding)
            loss = self.loss(logits, y)

        self.amp_backward(loss)
        torch.nn.utils.clip_grad.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
        self.amp_step(self.optimizer)
        
        if not self.each_epochs:
            self.scheduler.step()
            
        return loss.item()

    def val_step(self, tokenizer_output, y):
        """
        Étape de validation.
        """
        y = y.to(device)
        
        if isinstance(self.loss, torch.nn.CrossEntropyLoss):
            y = y.long()
        elif isinstance(self.loss, (torch.nn.BCELoss, torch.nn.BCEWithLogitsLoss)):
            y = y.float()   
        else:
            if self.task == "multiclass":
                y = y.long()
            else:
                y = y.float()   
        
        
        with self.amp_autocast():
            embedding = self.mail_encoder.predict(tokenizer_output, cache=False, output2d=False)
            embedding = embedding.to(device)
            
            logits = self.model(embedding)
            probs = torch.softmax(logits, dim=-1)
            pred = torch.argmax(probs, dim=-1).long().to(device)
            loss = self.loss(logits, y)
            
        return loss.item(), pred

    def train_on_epoch(self, dataloader):
        loop = tqdm(dataloader, desc="🚀 Entraînement")
        loss_list = []
        self.model.train()
        self.mail_encoder.train()
        
        for batch in loop:
            batch = dict(batch)
            y = batch["label"]
            batch.pop("label")
            tokenizer_output = dict(batch)
            
            loss = self.train_step(tokenizer_output, y)
            loss_list.append(loss)
            loop.set_postfix(loss=f"{loss:.4f}")
            
        if self.each_epochs:
            self.scheduler.step()
            
        return torch.tensor(loss_list).to(device).mean()

    def evaluate(self, valloader):
        self.model.eval()
        self.mail_encoder.eval()
        loop = tqdm(valloader, desc="🔍 Validation")

        total_loss = 0.0
        num_batches = 0

        # Réinitialiser les métriques
        for metric in self.metrics.values():
            metric.reset()

        with torch.no_grad():
            for batch in loop:
                batch = dict(batch)
                y = batch["label"].to(device)
                batch.pop("label")
                tokenizer_output = dict(batch)
                
                loss, pred = self.val_step(tokenizer_output, y)
                total_loss += loss
                num_batches += 1
                
                for metric in self.metrics.values():
                    metric(pred, y)
                    
                loop.set_postfix(loss=f"{loss:.4f}")

        loss_mean = total_loss / max(num_batches, 1)

        # Affichage structuré des résultats
        logger.print("\n" + "=" * 80)
        logger.print(f"{'📊 RÉSULTATS DE LA VALIDATION':^80}")
        logger.print("=" * 80)
        logger.print(f"  🔹 Loss moyenne         : {loss_mean:.6f}")
        logger.print(f"  🔹 Nombre de batches    : {num_batches}")
        logger.print("-" * 80)

        metric_families = {
            "Accuracy": ["accuracy_macro", "accuracy_micro", "accuracy_weighted"],
            "Precision": ["precision_macro", "precision_micro", "precision_weighted"],
            "Recall": ["recall_macro", "recall_micro", "recall_weighted"],
            "F1-Score": ["f1_macro", "f1_micro", "f1_weighted"],
            "Jaccard": ["jaccard_macro", "jaccard_micro"],
            "Hamming": ["hamming"]
        }

        for family, names in metric_families.items():
            logger.print(f"\n  📈 {family}")
            for name in names:
                if name not in self.metrics:
                    continue
                try:
                    value = self.metrics[name].compute()
                    val = value.item() if hasattr(value, 'item') else float(value)
                    logger.print(f"     • {name.replace(family.lower()+'_', ''):12s} : {val:.4f}")
                except Exception as e:
                    logger.print(f"     • {name:20s} : erreur ({e})")

        # Matrice de confusion
        if "confusion_matrix" in self.metrics:
            try:
                cm = self.metrics["confusion_matrix"].compute()
                cm_np = cm.detach().cpu().numpy().astype(int)

                logger.print("\n  📊 MATRICE DE CONFUSION")
                max_val = cm_np.max()
                cell_width = max(4, len(str(max_val))) + 1
                header = "     " + "".join([f"{j:>{cell_width}}" for j in range(cm_np.shape[1])])
                logger.print(header)
                for i, row in enumerate(cm_np):
                    row_str = f"  {i:>2} │" + "".join([f"{val:>{cell_width}}" for val in row])
                    logger.print(row_str)
            except Exception as e:
                logger.print(f"\n  ⚠️ Matrice de confusion non disponible : {e}")

        logger.print("\n" + "=" * 80 + "\n")
        return loss_mean

    def val_on_epoch(self, valloader):
        """Appel à evaluate sans double affichage (renvoie seulement la loss)"""
        self.model.eval()
        loss = self.evaluate(valloader)
        return loss
    
    def save_checkpoint(self, epoch: int):
        return torch.save(
            {
                "model": self.model.state_dict(),
                "optimizer": self.optimizer.state_dict(),
                "epoch": epoch,
                "loss": self.loss,
                **self.amp_state_dict()
            },
            os.path.join(CHECKPOINTS_DIR, "checkpoint_" + str(epoch))
        )
    
    def load_checkpoint(self, path):
        ckpt = torch.load(path, map_location=device)
        self.model.load_state_dict(self._clean_state_dict(ckpt["model"]))
        self.optimizer.load_state_dict(self._clean_state_dict(ckpt["optimizer"]))
        self.amp_load_state_dict(ckpt)
        return ckpt["epoch"], ckpt["loss"]
    
    def _clean_state_dict(self, state_dict: dict, prefix = "_orig_mod.") -> dict:
        return {
            str(k).removeprefix(prefix) : v
            for k, v in state_dict.items()
        }

    def fit(self, dataloader, valloader=None, epochs=50, plot_history=True, early_stopping=None, multiple_of: int = 5):
        history = {"val_loss": [], "train_loss": []}
        best_weights = {}
        best_epoch = 0
        effective_epochs = 0
        best_metric = float("inf")

        for epoch in range(epochs):
            logger.print(f"\n🔁 Epoch {epoch+1}/{epochs}")
            train_loss = self.train_on_epoch(dataloader)
            history["train_loss"].append(train_loss.item())
            logger.print(f"  📉 Train loss : {train_loss:.6f}")

            if valloader is not None:
                val_loss = self.val_on_epoch(valloader)
                history["val_loss"].append(val_loss)
                logger.print(f"  📈 Val loss   : {val_loss:.6f}")
                current_metric = val_loss
            else:
                current_metric = train_loss

            effective_epochs += 1

            if not best_weights or current_metric < best_metric:
                best_metric = current_metric
                best_weights = {k: v.clone().cpu() for k, v in self.model.state_dict().items()}
                best_epoch = epoch
                logger.print("  💾 Meilleur modèle sauvegardé (en mémoire)")
                self.save_checkpoint("best")
                
            if early_stopping:
                should_stop = early_stopping(current_metric)
                if should_stop:
                    logger.print(f"\n🛑 Early stopping déclenché à l'epoch {epoch+1}")
                    break
            
            if epoch % max(multiple_of, 5) == 0 and epoch != 0:
                logger.print(f"Checkpoint epoch: {epoch}")
                self.save_checkpoint("epoch")
        # Restauration du meilleur modèle
        if best_weights:
            logger.print(f"\n🏆 Chargement du meilleur modèle (epoch {best_epoch+1})")
            self.model.load_state_dict(best_weights)

        logger.print("\n✅ Entraînement terminé.")
        if plot_history:
            self.plot_trainer_history(history, effective_epochs)
        return history

    def plot_trainer_history(self, history, effective_epochs):
        arange = np.arange(effective_epochs)
        plt.figure(figsize=(12, 5))
        
        plt.subplot(1, 2, 1)
        plt.plot(arange, history["train_loss"], label="Train Loss", marker='o')
        if history["val_loss"]:
            plt.plot(arange[:len(history["val_loss"])], history["val_loss"], label="Val Loss", marker='s')
        plt.xlabel("Epoch")
        plt.ylabel("Loss")
        plt.title("Courbes d'apprentissage")
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.7)

        if history["val_loss"]:
            plt.subplot(1, 2, 2)
            min_len = min(len(history["train_loss"]), len(history["val_loss"]))
            gap = np.array(history["train_loss"][:min_len]) - np.array(history["val_loss"][:min_len])
            plt.plot(arange[:min_len], gap, label="Gap (Train - Val)", color='red')
            plt.axhline(0.05, linestyle='--', color='gray', label="Seuil 5%")
            plt.axhline(0.10, linestyle='--', color='gray', alpha=0.5, label="Seuil 10%")
            plt.xlabel("Epoch")
            plt.ylabel("Gap")
            plt.title("Écart Train/Validation")
            plt.legend()
            plt.grid(True, linestyle='--', alpha=0.7)

        plt.tight_layout()
        plt.show()


