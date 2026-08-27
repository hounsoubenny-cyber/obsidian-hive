#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

import torch
import torch.nn as nn
import torchmetrics
import numpy as np
from matplotlib import pyplot as plt
from tqdm import tqdm
from model.callbacks import EarlyStopping

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class Trainer(nn.Module):
    def __init__(
            self,
            model,
            loss,
            optimizer,
            scheduler,
            task: str = "binary",
            num_classe: int = 2,
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
        self.task = task
        self.each_epochs = each_epochs
        if compile_model:
            self.model = torch.compile(model)
        if compile_loss:
            self.loss = torch.compile(loss)
            
        if compile_steps:
            self.train_step = torch.compile(self.train_step)
            self.val_step = torch.compile(self.val_step)

        self.metrics = nn.ModuleDict({
            #Accuracy
            "accuracy_macro": torchmetrics.Accuracy(task=self.task, num_classes=num_classe, average="macro"),
            "accuracy_micro": torchmetrics.Accuracy(task=self.task, num_classes=num_classe, average="micro"),
            "accuracy_weighted": torchmetrics.Accuracy(task=self.task, num_classes=num_classe, average="weighted"),
            
            #Precision
            "precision_macro": torchmetrics.Precision(task=self.task, num_classes=num_classe, average="macro"),
            "precision_micro": torchmetrics.Precision(task=self.task, num_classes=num_classe, average="micro"),
            "precision_weighted": torchmetrics.Precision(task=self.task, num_classes=num_classe, average="weighted"),
            
            #Recall
            "recall_macro": torchmetrics.Recall(task=self.task, num_classes=num_classe, average="macro"),
            "recall_micro": torchmetrics.Recall(task=self.task, num_classes=num_classe, average="micro"),
            "recall_weighted": torchmetrics.Recall(task=self.task, num_classes=num_classe, average="weighted"),
            
            #F1Score
            "f1_macro": torchmetrics.F1Score(task=self.task, num_classes=num_classe, average="macro"),
            "f1_micro": torchmetrics.F1Score(task=self.task, num_classes=num_classe, average="micro"),
            "f1_weighted": torchmetrics.F1Score(task=self.task, num_classes=num_classe, average="weighted"),
            
            #Confusion matrice
            "confusion_matrix": torchmetrics.ConfusionMatrix(task=self.task, num_classes=num_classe),
            
            #Jaccard score
            'jaccard_macro': torchmetrics.JaccardIndex(task=self.task, num_classes=num_classe, average='macro'),
            'jaccard_micro': torchmetrics.JaccardIndex(task=self.task, num_classes=num_classe, average='micro'),
            
            #Hamming Loss
            'hamming': torchmetrics.HammingDistance(task=self.task, num_classes=num_classe)
        })
        self.to(device)

    def train_step(self, X, y):
        X, y = X.to(device) if hasattr(X, "to") else X, y.to(device) if hasattr(y,"to") else y
        if self.task == "multiclass":
            y = y.long()
        else:
            y = y.float()
        self.optimizer.zero_grad()
        logits = self.model(X)
        loss = self.loss(logits, y)
        loss.backward()
        torch.nn.utils.clip_grad.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
        self.optimizer.step()
        if not self.each_epochs:
            self.scheduler.step()
        return loss.item()

    def val_step(self, X, y):
        X, y = X.to(device) if hasattr(X, "to") else X, y.to(device) if hasattr(y,"to") else y
        if self.task == "multiclass":
            y = y.long()
        else:
            y = y.float()
        logits = self.model(X)
        loss = self.loss(logits, y)
        return loss.item(), self.model.predict(X, logits)[1]

    def train_on_epoch(self, dataloader):
        loop = tqdm(dataloader, desc="🚀 Entraînement")
        loss_list = []
        self.model.train()
        for x, y in loop:
            loss = self.train_step(x, y)
            loss_list.append(loss)
            loop.set_postfix(loss=f"{loss:.4f}")
        if self.each_epochs:
            self.scheduler.step()
        return torch.tensor(loss_list).to(device).mean()

    def evaluate(self, valloader):
        self.model.eval()
        loop = tqdm(valloader, desc="🔍 Validation")

        total_loss = 0.0
        num_batches = 0

        with torch.no_grad():
            for x, y in loop:
                loss, pred = self.val_step(x, y)
                total_loss += loss
                num_batches += 1
                for metric in self.metrics.values():
                    metric(pred, y)
                loop.set_postfix(loss=f"{loss:.4f}")

        loss_mean = total_loss / max(num_batches, 1)

        # --- Affichage structuré des résultats ---
        print("\n" + "=" * 80)
        print(f"{'📊 RÉSULTATS DE LA VALIDATION':^80}")
        print("=" * 80)
        print(f"  🔹 Loss moyenne         : {loss_mean:.6f}")
        print(f"  🔹 Nombre de batches    : {num_batches}")
        print("-" * 80)

        metric_families = {
            "Accuracy": ["accuracy_macro", "accuracy_micro", "accuracy_weighted"],
            "Precision": ["precision_macro", "precision_micro", "precision_weighted"],
            "Recall"   : ["recall_macro", "recall_micro", "recall_weighted"],
            "F1-Score" : ["f1_macro", "f1_micro", "f1_weighted"],
            "Jaccard"  : ["jaccard_macro", "jaccard_micro"],
            "Hamming"  : ["hamming"]
        }

        for family, names in metric_families.items():
            print(f"\n  📈 {family}")
            for name in names:
                if name not in self.metrics:
                    continue
                try:
                    value = self.metrics[name].compute()
                    self.metrics[name].reset()
                    val = value.item() if hasattr(value, 'item') else float(value)
                    print(f"     • {name.replace(family.lower()+'_', ''):12s} : {val:.4f}")
                except Exception as e:
                    print(f"     • {name:20s} : erreur ({e})")

        # Matrice de confusion 
        if "confusion_matrix" in self.metrics:
            try:
                cm = self.metrics["confusion_matrix"].compute()
                self.metrics["confusion_matrix"].reset()
                cm_np = cm.detach().cpu().numpy().astype(int)

                print("\n  📊 MATRICE DE CONFUSION")
                # Calcul de la largeur nécessaire
                max_val = cm_np.max()
                cell_width = max(4, len(str(max_val))) + 1
                # En-tête des colonnes
                header = "     " + "".join([f"{j:>{cell_width}}" for j in range(cm_np.shape[1])])
                print(header)
                for i, row in enumerate(cm_np):
                    row_str = f"  {i:>2} │" + "".join([f"{val:>{cell_width}}" for val in row])
                    print(row_str)
            except Exception as e:
                print(f"\n  ⚠️ Matrice de confusion non disponible : {e}")

        print("\n" + "=" * 80 + "\n")
        return loss_mean

    def val_on_epoch(self, valloader):
        """Appel à evaluate sans double affichage (renvoie seulement la loss)"""
        self.model.eval()
        loss = self.evaluate(valloader)
        return loss

    def fit(self, dataloader, valloader=None, epochs=50, plot_history=True, early_stopping=None):
        history = {"val_loss": [], "train_loss": []}
        best_weights = {}
        best_epoch = 0
        effective_epochs = 0

        for epoch in range(epochs):
            print(f"\n🔁 Epoch {epoch+1}/{epochs}")
            train_loss = self.train_on_epoch(dataloader)
            history["train_loss"].append(train_loss.item())
            print(f"  📉 Train loss : {train_loss:.6f}")

            if valloader is not None:
                val_loss = self.val_on_epoch(valloader) 
                history["val_loss"].append(val_loss)
                print(f"  📈 Val loss   : {val_loss:.6f}")
                current_metric = val_loss
            else:
                current_metric = train_loss

            effective_epochs += 1

            if early_stopping:
                should_stop = early_stopping(current_metric)
                if should_stop:
                    print(f"\n🛑 Early stopping déclenché à l'epoch {epoch+1}")
                    break
                if not best_weights or current_metric < min(history["val_loss"]):
                    best_weights = {k: v.clone() for k, v in self.model.state_dict().items()}
                    best_epoch = epoch
                    print("  💾 Meilleur modèle sauvegardé (en mémoire)")

        # Restauration du meilleur modèle
        if best_weights:
            print(f"\n🏆 Chargement du meilleur modèle (epoch {best_epoch+1})")
            self.model.load_state_dict(best_weights)

        print("\n✅ Entraînement terminé.")
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