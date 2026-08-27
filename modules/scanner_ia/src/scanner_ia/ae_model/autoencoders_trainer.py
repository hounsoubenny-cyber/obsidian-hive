#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May 31 03:41:17 2026

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
from scanner_ia.ae_model.callbacks import EarlyStopping
from scanner_ia.ae_model.autoencoders import AutoEncoder, AELoss
from scanner_ia.scanner_utils.logger import get_logger

logger = get_logger()
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

CHECKPOINTS_DIR = os.path.join(os.path.dirname(__file__), "checkpoints_model")
os.makedirs(CHECKPOINTS_DIR, exist_ok=True)

class Trainer(nn.Module):
    def __init__(
        self,
        model: AutoEncoder,
        loss: AELoss,
        optimizer,
        scheduler,
        each_epochs: bool = True,
        compile_model: bool = True,
        compile_loss: bool = True,
        compile_steps: bool = False,
        
    ):
        super().__init__()
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
    
    def train_step(self, texts: list[str]):
        x = self.model.prepare_input(texts)  # [batch, 5, hidden_size]
        x = x.to(device, dtype=torch.float)
    
        self.optimizer.zero_grad()
        logits = self.model(x)               
        loss = self.loss(logits, x)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
        self.optimizer.step()
        if not self.each_epochs:
            self.scheduler.step()
        return loss.item()
    
    def val_step(self, texts: list[str]):
        x = self.model.prepare_input(texts)
        x = x.to(device, dtype=torch.float)
        logits = self.model(x)
        loss = self.loss(logits, x)
        mse, mae = self.model.compute_mse_and_mae(x, logits)
        return loss.item(), mse.item(), mae.item()
    
    def train_on_epoch(self, dataloader):
        loop = tqdm(dataloader, desc="🚀 Entraînement")
        loss_list = []
        self.model.train()
        for batch in loop:
            texts = batch["text"]
            loss = self.train_step(texts)
            loss_list.append(loss)
            loop.set_postfix(loss=f"{loss:.4f}")
    
        if self.each_epochs:
            self.scheduler.step()
    
        return torch.tensor(loss_list).to(device).mean()
    
    def evaluate(self, valloader):
        self.model.eval()
        loop = tqdm(valloader, desc="🔍 Validation")
        total_loss = 0.0
        total_mse = 0.0
        total_mae = 0.0
        num_batches = 0
    
        with torch.no_grad():
            for batch in loop:
                texts = batch["text"]
                loss, mse, mae = self.val_step(texts)
                total_loss += loss
                total_mse += mse
                total_mae += mae
                num_batches += 1
                loop.set_postfix(loss=f"{loss:.4f}")
    
        loss_mean = total_loss / max(num_batches, 1)
        mse_mean  = total_mse  / max(num_batches, 1)
        mae_mean  = total_mae  / max(num_batches, 1)
    
        logger.print("\n" + "=" * 80)
        logger.print(f"{'📊 RÉSULTATS VALIDATION - AUTOENCODEUR':^80}")
        logger.print("=" * 80)
        logger.print(f"  🔹 Loss : {loss_mean:.6f}")
        logger.print(f"  🔹 MSE  : {mse_mean:.6f}")
        logger.print(f"  🔹 MAE  : {mae_mean:.6f}")
        logger.print(f"  🔹 RMSE : {np.sqrt(mse_mean):.6f}")
        logger.print("=" * 80 + "\n")
    
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
                "loss": self.loss
            },
            os.path.join(CHECKPOINTS_DIR, "checkpoint_" + str(epoch))
        )
    
    def load_checkpoint(self, path):
        ckpt = torch.load(path, map_location=device, weights_only=False)
        self.model.load_state_dict(self._clean_state_dict(ckpt["model"]))
        self.optimizer.load_state_dict(ckpt["optimizer"])
        return ckpt["epoch"], ckpt["loss"]
    
    def _clean_state_dict(self, state_dict: dict, prefix = "_orig_mod.") -> dict:
        return {
            str(k).removeprefix(prefix) : v
            for k, v in state_dict.items()
        }
    
    def fit(self, dataloader, valloader=None, epochs=50, plot_history=True, early_stopping: EarlyStopping = None, multiple_of:int = 5):
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
                best_weights = {k: v.clone() for k, v in self.model.state_dict().items()}
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

def compute_threshold(history: dict):
    loss = history.get("val_loss", history.get("train_loss", None))
    if loss is None:
        return None
    loss = np.array(loss)
    return {
        "score": loss.mean() + 2 * loss.std(), 
        "mean": loss.mean(), 
        "std": loss.std(),
        "loss": loss
    }