#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trainer pour MailEncoder avec contrastive learning.
Version originale avec output2d=True pour la loss contrastive.

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import torch
import torch.nn as nn
import numpy as np
from sklearn.metrics import davies_bouldin_score, silhouette_score
from matplotlib import pyplot as plt
from tqdm import tqdm
from anti_phishing_ia.dl_model.callbacks import EarlyStopping
from anti_phishing_ia.phishing_utils.logger import get_logger
from anti_phishing_ia.dl_model.mail_encoder import MailEncoder
from anti_phishing_ia.dl_model.constrative_loss import SupervisedConstrativeLoss
from anti_phishing_ia.dl_model.amp_mixin import AMPMixin

logger = get_logger()
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

CHECKPOINTS_DIR = os.path.join(os.path.dirname(__file__), "checkpoints_encoder")
os.makedirs(CHECKPOINTS_DIR, exist_ok=True)

class MailEncoderTrainer(AMPMixin, nn.Module):
    """
    Trainer pour MailEncoder avec contrastive learning.
    Utilise output2d=True pour obtenir des embeddings 2D pour la loss.
    """
    
    def __init__(
        self,
        model: MailEncoder,
        loss: SupervisedConstrativeLoss,
        optimizer,
        scheduler,
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
        self.each_epochs = each_epochs
        
        if compile_model:
            self.model = torch.compile(model)
        if compile_loss:
            self.loss = torch.compile(loss)
        if compile_steps:
            self.train_step = torch.compile(self.train_step)
            self.val_step = torch.compile(self.val_step)
            
        self.to(device)

    def train_step(self, tokenizer_output: dict, y: torch.Tensor):
        y = y.to(device)
        y = y.long()
        
        self.optimizer.zero_grad()
        # output2d=True pour loss contrastive
        with self.amp_autocast():                     
            embeddings = self.model(tokenizer_output, output2d=True)
            loss = self.loss(embeddings, y)

        self.amp_backward(loss)
        torch.nn.utils.clip_grad.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
        self.amp_step(self.optimizer)
        
        
        if not self.each_epochs:
            self.scheduler.step()
            
        return loss.item()

    def val_step(self, tokenizer_output, y):
        y = y.to(device)
        y = y.long()
        
        with self.amp_autocast():
            embeddings = self.model(tokenizer_output, output2d=True)
            loss = self.loss(embeddings, y)
            
        return loss.item(), embeddings

    def train_on_epoch(self, dataloader):
        loop = tqdm(dataloader, desc="🚀 Entraînement MailEncoder")
        loss_list = []
        self.model.train()
        
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
        loop = tqdm(valloader, desc="🔍 Validation Contrastive")
    
        total_loss = 0.0
        num_batches = 0
        all_embeddings = []
        all_labels_list = []
    
        with torch.no_grad():
            for batch in loop:
                batch = dict(batch)
                y = batch["label"].to(device)
                batch.pop("label")
                tokenizer_output = dict(batch)
                
                loss, embeddings = self.val_step(tokenizer_output, y)
                
                total_loss += loss
                num_batches += 1
                
                # embeddings déjà 2D car output2d=True
                if embeddings.ndim == 3:
                    embeddings = embeddings[:, 0, :]
                    
                all_embeddings.extend(embeddings.cpu().tolist())
                all_labels_list.extend(y.cpu().tolist())
                
                loop.set_postfix(loss=f"{loss:.4f}")
    
        loss_mean = total_loss / max(num_batches, 1)
    
        embeddings_np = np.array(all_embeddings)
        labels_np = np.array(all_labels_list)
        
        # Normalisation pour les métriques
        embeddings_norm = embeddings_np / (np.linalg.norm(embeddings_np, axis=1, keepdims=True) + 1e-8)
    
        # Métriques
        results = {}
        
        if len(np.unique(labels_np)) >= 2 and len(embeddings_np) > 1:
            results['silhouette'] = silhouette_score(embeddings_norm, labels_np)
            results['davies_bouldin'] = davies_bouldin_score(embeddings_norm, labels_np)
        else:
            results['silhouette'] = 0.0
            results['davies_bouldin'] = 0.0
        
        unique_labels = np.unique(labels_np)
        distances_intra = []
        for label in unique_labels:
            mask = labels_np == label
            emb_cls = embeddings_norm[mask]
            if len(emb_cls) > 1:
                dist = np.linalg.norm(emb_cls - emb_cls.mean(axis=0), axis=1).mean()
                distances_intra.append(dist)
        results['intra_distance'] = np.mean(distances_intra) if distances_intra else 0
        
        means = [embeddings_norm[labels_np == label].mean(axis=0) for label in unique_labels]
        results['inter_distance'] = np.linalg.norm(means[0] - means[1]) if len(means) >= 2 else 0
        results['separation_ratio'] = results['inter_distance'] / (results['intra_distance'] + 1e-8)
        
        sim_matrix = embeddings_norm @ embeddings_norm.T
        mask_intra = (labels_np[:, None] == labels_np[None, :]) * (1 - np.eye(len(labels_np), dtype=bool))
        mask_inter = (labels_np[:, None] != labels_np[None, :]) * (1 - np.eye(len(labels_np), dtype=bool))
        results['cosine_intra'] = sim_matrix[mask_intra.astype(bool)].mean() if mask_intra.any() else 0
        results['cosine_inter'] = sim_matrix[mask_inter.astype(bool)].mean() if mask_inter.any() else 0
    
        # Affichage
        logger.print("\n" + "=" * 80)
        logger.print(f"{'📊 RÉSULTATS DE LA VALIDATION':^80}")
        logger.print("=" * 80)
        logger.print(f"  🔹 Loss moyenne         : {loss_mean:.6f}")
        logger.print(f"  🔹 Nombre de batches    : {num_batches}")
        logger.print(f"  🔹 Échantillons         : {len(labels_np)}")
        logger.print("-" * 80)
        logger.print("\n  📈 MÉTRIQUES DE SÉPARATION")
        logger.print(f"     • Silhouette Score    : {results['silhouette']:.4f}  {'✅' if results['silhouette'] > 0.5 else '⚠️'}")
        logger.print(f"     • Davies-Bouldin      : {results['davies_bouldin']:.4f}  {'✅' if results['davies_bouldin'] < 1.0 else '⚠️'}")
        logger.print(f"     • Ratio Inter/Intra   : {results['separation_ratio']:.2f}  {'✅' if results['separation_ratio'] > 3 else '⚠️'}")
        logger.print("\n  📈 DISTANCES")
        logger.print(f"     • Intra-classe (↓)    : {results['intra_distance']:.4f}")
        logger.print(f"     • Inter-classe (↑)    : {results['inter_distance']:.4f}")
        logger.print("\n  📈 SIMILARITÉ COSINUS")
        logger.print(f"     • Intra-classe (↑)    : {results['cosine_intra']:.4f}  {'✅' if results['cosine_intra'] > 0.8 else '⚠️'}")
        logger.print(f"     • Inter-classe (↓)    : {results['cosine_inter']:.4f}  {'✅' if results['cosine_inter'] < 0.2 else '⚠️'}")
        logger.print("\n" + "=" * 80 + "\n")
        
        return loss_mean

    def val_on_epoch(self, valloader):
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
    
    def fit(
        self, 
        dataloader, 
        valloader=None,
        epochs=50, 
        plot_history=True, 
        early_stopping: EarlyStopping | None = None,
        multiple_of: int = 5,
    ):
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