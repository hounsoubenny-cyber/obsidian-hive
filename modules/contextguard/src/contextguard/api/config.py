# -*- coding: utf-8 -*-
"""
Created on Tue Jan 20 19:24:01 2026

@author: hounsousamuel
"""

import os
from dotenv import load_dotenv

load_dotenv()


MATCH = {
	0 : "safe",
	1 : "injection",
	2 : "jailbreak",
	3 : "exfiltration",
}
SAFE_CLASSE = "safe"

NOT_BEFORE = 0.1
EXP = 60 * 8
LIMITE = 30
IP = "0.0.0.0"
PORT = 8000
USE_ONNX = False

MODEL_BASENAME = "contextguard2"
BASEDIR = os.path.dirname(os.path.abspath(__file__))
TOKENIZER_PATH = os.path.join(BASEDIR, "..", "model", "models", "tokenizer")
MODEL_PATH = os.path.join(BASEDIR, "..", "model", "models", f"{MODEL_BASENAME}.pt")
ONNX_PATH =  os.path.join(BASEDIR, "..", "model", "models", f"{MODEL_BASENAME}.onnx")
# print(os.path.exists(TOKENIZER_PATH))
STATIC_RULES_PATH = os.path.join(BASEDIR, "..", "model", "static_rule", "static_patterns.json")
CONTEXTGUARD_JWT_SECRET = os.environ.get("CONTEXTGUARD_JWT_SECRET", None)
if not CONTEXTGUARD_JWT_SECRET:
    raise RuntimeError("Jwt key is missing !")
