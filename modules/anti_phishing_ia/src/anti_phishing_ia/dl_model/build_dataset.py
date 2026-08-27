#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 13 23:59:51 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", '..'))
import pandas as pd
from anti_phishing_ia.phishing_utils.mail_extractor_utils import parse_email, build_bert_input

def prepare_caes(df: pd.DataFrame, result: list):
    for row in df.itertuples():
        raw_mail = f"From: {row.sender}\nSubject: {row.subject}\n\n{row.body}"
        text = build_bert_input(parse_email(raw_mail))
        result.append({"text": text, "label": int(row.label)})
    return result

def prepare_enron(df: pd.DataFrame, result: list):
    for row in df.itertuples():
        raw_mail = f"Subject: {row.subject}\n\n{row.body}"
        text = build_bert_input(parse_email(raw_mail))
        result.append({"text": text, "label": int(row.label)})
    return result

def prepare_ling(df: pd.DataFrame, result: list):
    return prepare_enron(df, result)

def prepare_nazario(df: pd.DataFrame, result: list):
    return prepare_caes(df, result)

def prepare_nigerian_fraud(df: pd.DataFrame, result: list):
    return prepare_caes(df, result)

def prepare_phishing_email(df: pd.DataFrame, result: list):
    for row in df.itertuples():
        raw_mail = str(row.text_combined)
        text = build_bert_input(parse_email(raw_mail))
        result.append({"text": text, "label": int(row.label)})
    return result

def prepare_spam_assasin(df: pd.DataFrame, result: list):
    return prepare_caes(df, result)

def prepare_spam_emails_data(df: pd.DataFrame, result: list):
    MAPPING = {"spam": 1, "ham": 0}
    for row in df.itertuples():
        raw_mail = str(row.text)
        text = build_bert_input(parse_email(raw_mail))
        result.append({"text": text, "label": MAPPING[str(row.label).lower()]})
    return result

ALL_FUNCTIONS = {
    "CEAS_08.csv": prepare_caes,
    "Enron.csv": prepare_enron,
    "Ling.csv": prepare_ling,
    "Nazario.csv": prepare_nazario,
    "Nigerian_Fraud.csv": prepare_nigerian_fraud,
    "phishing_email.csv": prepare_phishing_email,
    "SpamAssasin.csv": prepare_spam_assasin,
    "spam_Emails_data.csv": prepare_spam_emails_data,
}
def to_snake_case(string: str):
    if not string:
        return string
    
    new_string = ""
    for letter in string:
        if letter.isupper():
            if not new_string:
                new_string += letter.lower()
            elif new_string[-1] == "_":
                new_string += letter.lower()
            else:
                new_string += "_" + letter.lower()
        else:
            new_string += letter
        
    return new_string.strip("_")

def build(path: str = ".", save_path = "./dataset.csv") -> pd.DataFrame:
    result = []
    for root_path, _, files in os.walk(path or "."):
        for file in files:
            print(file)
            full_file_path = os.path.join(root_path, file)
            try:
                func = ALL_FUNCTIONS[file]
                func(
                    pd.DataFrame(pd.read_csv(full_file_path)),
                    result
                )
            except KeyError as e:
                print("Erreur:", str(e))
    df = pd.DataFrame(result)
    df = df.drop_duplicates(subset="text")
    df.to_csv(save_path, index=False)
    return df

df = build("./datasets")

    