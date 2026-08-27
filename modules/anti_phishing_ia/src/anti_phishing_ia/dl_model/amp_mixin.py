#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mixin pour ajouter le support mixed precision (FP16) aux trainers existants.

Usage :
    class MailEncoderTrainer(AMPMixin, nn.Module):
        def __init__(self, ..., use_amp: bool = None):
            super().__init__()
            ...
            self._init_amp(use_amp)

        def train_step(self, tokenizer_output, y):
            y = y.to(device).long()
            self.optimizer.zero_grad()

            with self.amp_autocast():
                embeddings = self.model(tokenizer_output, output2d=True)
                loss = self.loss(embeddings, y)

            self.amp_backward(loss)
            torch.nn.utils.clip_grad.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            self.amp_step(self.optimizer)

            if not self.each_epochs:
                self.scheduler.step()

            return loss.item()

@author: hounsousamuel (adapté)
"""

import torch
from torch.amp import autocast, GradScaler


class AMPMixin:
    """
    Mixin mixed precision — n'affecte rien si CUDA absent ou use_amp=False.
    Le trainer hérite de ce mixin EN PREMIER : class XTrainer(AMPMixin, nn.Module)
    """

    def _init_amp(self, use_amp: bool = None):
        """
        Args:
            use_amp: None → auto (True si CUDA dispo), True/False → forcé
        """
        if use_amp is None:
            use_amp = torch.cuda.is_available()
        self.use_amp = use_amp and torch.cuda.is_available()
        self.scaler = GradScaler("cuda", enabled=self.use_amp)
        if self.use_amp:
            print("⚡ Mixed precision (FP16) activé")
        else:
            print("🐢 Mixed precision désactivé (CPU ou use_amp=False)")

    def amp_autocast(self):
        """Context manager — autocast si activé, no-op sinon."""
        return autocast(enabled=self.use_amp)

    def amp_backward(self, loss):
        """Backward — scalé si AMP actif, normal sinon."""
        self.scaler.scale(loss).backward()

    def amp_step(self, optimizer):
        """Step optimizer — gère unscale + update du scaler."""
        self.scaler.step(optimizer)
        self.scaler.update()

    def amp_state_dict(self) -> dict:
        """Pour save_checkpoint — ajoute juste cette clé au dict existant."""
        return {"scaler": self.scaler.state_dict()}
    
    def _clean_state_dict(self, state_dict: dict, prefix = "_orig_mod.") -> dict:
        return {
            str(k).removeprefix(prefix) : v
            for k, v in state_dict.items()
        }
    
    def amp_load_state_dict(self, checkpoint: dict):
        """Pour load_checkpoint — restaure le scaler si présent."""
        if "scaler" in checkpoint:
            self.scaler.load_state_dict(self._clean_state_dict(checkpoint["scaler"]))