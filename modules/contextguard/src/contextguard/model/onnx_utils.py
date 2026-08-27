#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr  5 11:11:04 2026

@author: hounsousamuel
"""

import os, sys
import onnxruntime as ort
import torch

class ONNXUtils:
    def __init__(self):
        self.file = None
        self.session = None
    
    @staticmethod
    def export(
          model,
          dummy_input,
          output_file,
          export_params = True,
        ):
        try:
            exported = torch.onnx.export(
                model,
                dummy_input,
                output_file,
                input_names=["input", "attention_mask"],
                output_names=["output"],
                dynamic_shapes={
                    "input_ids":        {0: "batch_size"},
                    "attention_mask": {0: "batch_size"},
                    # "output": {0: "batch_size"},
                    },
                artifacts_dir="./onnx_artifacts",
                export_params=export_params,
            )   
            print("Export réussi :", exported)
        except Exception as e:
            print("Erreur durant export :", str(e))
    
    def inference(self, file:str, data, output_names:list|None = ["output"]):
        if not os.path.exists(file):
            raise FileNotFoundError(f"Modèle {file} introuvable")
            
        if self.file is None:
            self.file == file
        
        if self.session:
            if file == self.file:
                session = self.session
        else:
            session = ort.InferenceSession(file)
        result = session.run(output_names, {session.get_inputs()[0].name: data[0], session.get_inputs()[1].name: data[1]})
        if output_names is None:
            return result
        return tuple(result[0:len(output_names) + 1])
    
    def reset(self):
        self.file = None
        self.session = None

