#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 30 21:02:39 2026

@author: hounsousamuel
"""

import torch
import torch.utils.data as tdata
import numpy as np

class SandBoxDataset(tdata.Dataset):
    def __init__(
        self,
        X: np.ndarray | torch.Tensor,
        y: np.ndarray | torch.Tensor,
        X_ebd: np.ndarray | torch.Tensor,
    ):
        super().__init__()
        self.X = torch.tensor(X)
        self.y = torch.tensor(y)
        self.X_ebd = torch.tensor(X_ebd)
        
    def __len__(self):
        return self.X.shape[0]
    
    def __getitem__(self, index):
        x = self.X[index].float()
        y = self.y[index].float()
        x_ebd = self.X_ebd[index].float()
        return {
            "x": x,
            "x_ebd": x_ebd,
            "y": y
        }
        