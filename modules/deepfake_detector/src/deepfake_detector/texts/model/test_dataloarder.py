#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May  7 08:06:09 2026

@author: hounsousamuel
"""

import torch
class MyDataset(torch.utils.data.Dataset):
    def __init__(self):
        super().__init__()
        self.x = torch.rand(*(100, 123))
        self.y = torch.rand(*(100, 1))
    
    def __len__(self):
        return self.x.shape[0]
    
    def __getitem__(self, index):
        return {
            "x": self.x[index],
            "y": self.y[index].item()
            }

class Model(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.model = torch.nn.Sequential(
            torch.nn.BatchNorm1d(123),
            torch.nn.Linear(123, 64),
            torch.nn.ReLU(),
            torch.nn.Dropout(0.2),
            torch.nn.Linear(64, 2)
        )
    def forward(self, x):
        return self.model(x)
    

model = Model()
criterion = torch.nn.CrossEntropyLoss()
opt = torch.optim.Adam(model.parameters())

dloader = torch.utils.data.DataLoader(MyDataset(), batch_size=32)
for batch in dloader:
    print(type(batch))
    print(batch["x"].shape)
    print(batch["y"].shape)
    # opt.zero_grad()
    # logits = model(batch["x"])
    # loss = criterion(logits, batch["y"].long())
    # loss.backward()
    # opt.step()
    # print("LOSS :", loss.item())