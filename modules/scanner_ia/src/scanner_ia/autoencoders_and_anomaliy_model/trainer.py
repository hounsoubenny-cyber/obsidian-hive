#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar 20 06:18:31 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
import torch
from tqdm import tqdm
import numpy as np
from matplotlib import pyplot as plt

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
torch.set_num_threads(os.cpu_count())
try:
    torch.set_num_interop_threads(os.cpu_count())
except RuntimeError:
    pass

class Trainer:
    def __init__(
            self, 
            model,
            loss_func,
            optimizer,
            scheduler = None,
            early_stopping = None,
            compile_model:bool = True,
            compile_step:bool = False,
            compile_loss_func:bool = False,
            each_epoch:bool = True,
        ):
        self.model = model
        self.optimizer = optimizer
        self.scheduler = scheduler
        self.early_stopping = early_stopping
        self.loss_func = loss_func
        self.compile_model = compile_model
        self.compile_step = compile_step
        self.compile_loss_func = compile_loss_func
        self.each_epoch = each_epoch
        if self.compile_model:
            self.model = torch.compile(self.model)
        
        if self.compile_loss_func:
            self.loss_func = torch.compile(self.loss_func)
        
        if self.compile_step:
            self.train_step = torch.compile(self.train_step)
            self.val_step = torch.compile(self.val_step)
        
        self.best_weights = {}
    
    def train_step(self, X, y):
        self.optimizer.zero_grad()
        logits = self.model(X)
        loss = self.loss_func(logits, y)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
        self.optimizer.step()
        if not self.each_epoch:
            self.scheduler.step()
        return loss.item(), self.model.predict(X, logits)
    
    def train_epoch(self, dataloder):
        loop = tqdm(dataloder, desc="Fit autoencoder")
        loss_list = []
        errors = torch.tensor([])
        self.model.train()
        for x, y in loop:
            x, y = x.to(device), y.to(device)
            loss, error = self.train_step(x, y)
            loss_list.append(loss)
            errors = torch.concat((errors, error), dim=0)
            loop.set_postfix(loss=loss)
        if self.each_epoch:
            self.scheduler.step()
        e_mean = errors.mean().item()
        print("Erreur de reconstruction sur tout le data de train : ", e_mean)
        print()
        return torch.mean(torch.tensor(loss_list)).item(), e_mean
    
    def val_step(self, X, y):
        logits = self.model(X)
        loss = self.loss_func(logits, y)
        return loss.item(), self.model.predict(X, logits)
    
    def val_epoch(self, valloader):
        loop = tqdm(valloader, desc="Evaluation autoencoder")
        loss_list = []
        errors = torch.tensor([])
        self.model.eval()
        with torch.no_grad():
            for x, y in loop:
                x, y = x.to(device), y.to(device)
                loss, error = self.val_step(x, y)
                loss_list.append(loss)
                errors = torch.concat((errors, error), dim=0)
                loop.set_postfix(loss=loss)
        e_mean = errors.mean().item()
        print("Erreur de reconstruction sur tout le data de validation : ", e_mean)
        print()
        return torch.mean(torch.tensor(loss_list)).item(), e_mean
    
    def fit(
            self, 
            dataloader,
            valloader = None,
            epochs:int = 50,
            plot_history:bool = True,
    ):
        history = {
            "val_loss": [],
            "train_loss": [],
            "val_error": [],
            "train_error": [],
            }
        
        early_value = None
        effective_epoch = 0
        best_epoch = 0
        for i in range(epochs):
            print(f"Epoch {i}/{epochs}")    
            train_loss, train_error = self.train_epoch(dataloader)
            history["train_loss"].append(train_loss)
            history["train_error"].append(train_error)
            early_value = train_loss
            
            if valloader is not None:
                val_loss, val_error = self.val_epoch(valloader)
                history["val_loss"].append(val_loss)
                history["val_error"].append(val_error)
                early_value = val_loss
            
            if self.early_stopping is not None:
                should_continue = self.early_stopping(early_value)
                if should_continue:
                    if self.early_stopping.is_best():
                        print("Amelioration, sauvegarde du best state dict en mémoire")
                        best_epoch = i
                        self.best_weights = {k: v.clone() for k, v in self.model.state_dict().items()}
                else:
                    print("Fit arrêter par early stopping à l'epoch :", i)
                    print()
                    effective_epoch += 1
                    break
            effective_epoch += 1
            
        if self.best_weights:
            print(f"Chargement du meilleur état (epoch {best_epoch})")
            self.model.load_state_dict(self.best_weights)
        
        if plot_history:
            self.plot_trainer_history(history, effective_epoch)
        return history

    def plot_trainer_history(self, history:dict, effective_epoch:int):
        arange = np.arange(effective_epoch)
        plt.figure(figsize=(10, 10))
        plt.subplot(221)
        plt.plot(arange, np.array(history["val_loss"]), label="val_loss")
        plt.plot(arange, np.array(history["train_loss"]), label="train_loss")
        plt.plot(arange, np.array(history["train_loss"]) - np.array(history["val_loss"]), label="gap")
        plt.axhline(0.05, label="gap à 5%")
        plt.axhline(0.5, label="gap à 10%")
        plt.grid(True)
        plt.legend()
        try:
            plt.subplot(222)
            plt.plot(arange, np.array(history["val_error"]), label="val_error")
            plt.plot(arange,np.array(history["train_error"]),  label="train_error")
            plt.plot(arange, np.array(history["train_error"]) - np.array(history["val_error"]), label="gap")
            plt.axhline(0.05, label="gap à 5%")
            plt.axhline(0.5, label="gap à 10%")
            plt.legend()
            plt.grid(True)
            
        except Exception as e:
            print("Erreur plotting : ", str(e))
            
        plt.tight_layout()
        plt.show()
            
    
if __name__ == "__main__":
    from autoencoders.autoencoder_x_torch import AutoencoderX
    from autoencoders.callbacks import EarlyStopping
    N, F = 10000, 1000
    epochs = 100
    model = AutoencoderX(num_features=F)
    X = torch.rand(N, F)
    X_val = torch.rand(1000, F)
    dataloader = torch.utils.data.DataLoader(torch.utils.data.TensorDataset(X, X), batch_size=128, shuffle=True)
    valloader = torch.utils.data.DataLoader(torch.utils.data.TensorDataset(X_val, X_val), batch_size=128, shuffle=True)
    ea = EarlyStopping(patience=5)
    loss_func = torch.nn.HuberLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.OneCycleLR(
        optimizer,
        max_lr=1e-2,
        epochs=epochs,
        steps_per_epoch=len(dataloader)
        )
    trainer = Trainer(model, loss_func, optimizer, scheduler, each_epoch=False, early_stopping=ea)
    h = trainer.fit(dataloader, valloader, epochs, True)
    # print(h)
            
            
        
    
    