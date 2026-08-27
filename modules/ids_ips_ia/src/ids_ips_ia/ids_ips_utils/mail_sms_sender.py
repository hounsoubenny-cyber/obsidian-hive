#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jan  3 12:08:16 2026

@author: hounsousamuel
"""
import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import joblib
import smtplib as smt
from email.mime.text import MIMEText as MT
from email.mime.multipart import MIMEMultipart as MP
from twilio.rest import Client
from time import time
from ids_ips_ia.ids_ips_utils.logger import get_logger
logger = get_logger()


dir_ = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'text')

class Text:
    def __init__(self, nom: str, prenom: str):
        self.nom = nom
        self.prenom = prenom
        self.filename = f'{nom}_{prenom}.txt'
        self.doc = {}
        self.have_send = False
        self.dir = os.path.join(dir_, self.filename)
        self.current_mail_id = 1
        self.current_sms_id = 1
        # self.server = smt.SMTP('smtp.gmail.com', 587)

    def save(self, text, type, time):
        '''Permet d'avoir une historique des messages envoyés'''
        id = self.current_sms_id if type == 'sms' else self.current_mail_id
        if self.have_send:
            data = []
            try:
                data = list(joblib.load(self.dir))
            except Exception:
                pass
            
            try:
                data.append({'type': type, 'id': id, 'text': text, 'durée': time})
                joblib.dump(data, self.dir)
                logger.print("Texte sauvegardé")
                logger.print("Chemin de stockage : ", self.dir)
                logger.print('Numéro : ', id)
            except Exception as e:
                logger.print('Erreur survenue, ', e)
        else:
            logger.print('Aucun message envoyé')

    def send_mail(self, text, sender_address, receiver_address, password, subject='INFO'):
        li = [text, sender_address, receiver_address, password]
        if all(li) and all(str(l).strip() for l in li):
            try:
                # Lancement du server et préparation mail
                self.server = smt.SMTP('smtp.gmail.com', 587)
                self.server.starttls()
                t = time()
                m = MP()
                m['From'] = sender_address
                m['To'] = receiver_address
                m['Subject'] = subject
                m.attach(MT(text, 'plain'))
                self.server.login(sender_address, password)
                self.server.sendmail(sender_address, receiver_address, m.as_string())
                self.server.quit()
                t1 = time() - t
                self.have_send = True
                self.save(text, 'mail', t1)
                self.current_mail_id += 1
                logger.print(f'Message envoyé de {sender_address} à {receiver_address} en {t1} secondes')
                logger.print(f"Destinataire : {self.nom} {self.prenom}")
            except Exception as e:
                logger.print("Erreur survenue, ", e)
        else:
            logger.print('Données invalides')

    def send_sms(self, text, account_sid, auth_token, sender_num, receiver_num):
        li = [account_sid, auth_token, sender_num, receiver_num]
        if all(li) and all(str(l).strip() for l in li):
            try:
                t = time()
                client = Client(account_sid, auth_token)
                sms = client.messages.create(
                    body=text,
                    from_=sender_num,
                    to=receiver_num
                )
                t1 = time() - t
                self.have_send = True
                self.save(text, 'sms', t1)
                self.current_sms_id += 1
                logger.print(f'Message envoyé de {sender_num} à {receiver_num} en {t1} secondes')
                logger.print(f"Destinataire : {self.nom} {self.prenom}")
                logger.print(f"Statut: {sms.status}")
                logger.print(f"SID: {sms.sid}")
            except Exception as e:
                logger.print("Erreur survenue, ", e)
        else:
            logger.print('Données invalides')
