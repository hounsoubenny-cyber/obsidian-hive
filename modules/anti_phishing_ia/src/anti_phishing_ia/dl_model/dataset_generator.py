#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
create_email_dataset.py

Génère un dataset d'emails labellisés pour l'entraînement.
Équilibré entre phishing et légitimes.

Auteur: HOUNSOU Samuel
"""

import pandas as pd
import random
import re
from sklearn.model_selection import train_test_split
from datetime import datetime, timedelta

# ============================================================================
# TEMPLATES D'EMAILS PHISHING
# ============================================================================

PHISHING_TEMPLATES = [
    # Banque / Compte bancaire
    {
        "subject": "URGENT: Sécurité de votre compte bancaire",
        "body": """
Bonjour,

Nous avons détecté une activité suspecte sur votre compte bancaire.
Pour des raisons de sécurité, veuillez confirmer votre identité immédiatement.

🔗 Confirmer mon identité : {url}

Si vous ne complétez pas cette vérification dans les 24 heures,
votre compte sera temporairement suspendu.

Cordialement,
Service Sécurité {bank_name}
""",
        "category": "bank"
    },
    {
        "subject": "Votre relevé bancaire est disponible",
        "body": """
Cher client,

Votre relevé bancaire du mois dernier est maintenant disponible.

📎 Télécharger mon relevé : {url}

Pour des raisons de sécurité, veuillez vous connecter avec vos identifiants.

Merci de votre confiance.
""",
        "category": "bank"
    },
    
    # PayPal / Paiement en ligne
    {
        "subject": "PayPal: Vérification requise",
        "body": """
Bonjour,

Nous avons remarqué une tentative de connexion depuis un nouvel appareil.
Pour protéger votre compte, veuillez vérifier votre identité.

✅ Vérifier mon compte PayPal : {url}

Si vous n'êtes pas à l'origine de cette tentative, ignorez ce message.

L'équipe PayPal
""",
        "category": "paypal"
    },
    {
        "subject": "Paiement en attente de confirmation",
        "body": """
Bonjour,

Un paiement de {amount}€ est en attente de validation.
Pour finaliser cette transaction, cliquez sur le lien ci-dessous :

💳 Confirmer le paiement : {url}

Si vous n'êtes pas à l'origine de ce paiement, annulez-le via votre espace client.

Merci,
Service Clients
""",
        "category": "payment"
    },
    
    # Amazon / E-commerce
    {
        "subject": "Amazon: Problème avec votre commande",
        "body": """
Bonjour,

Nous rencontrons un problème avec votre commande #{order_id}.
Votre colis ne peut pas être livré à l'adresse indiquée.

📦 Mettre à jour mon adresse de livraison : {url}

Veuillez mettre à jour vos informations dans les 48 heures.

Cordialement,
Amazon Logistics
""",
        "category": "amazon"
    },
    {
        "subject": "Votre compte Amazon a été verrouillé",
        "body": """
Bonjour,

Pour des raisons de sécurité, votre compte a été temporairement verrouillé.
Plusieurs tentatives de connexion échouées ont été détectées.

🔓 Déverrouiller mon compte : {url}

Service Client Amazon
""",
        "category": "amazon"
    },
    
    # Microsoft / Email / Cloud
    {
        "subject": "Microsoft: Action requise pour votre compte",
        "body": """
Bonjour,

Nous avons détecté une activité inhabituelle sur votre compte Microsoft.
Pour éviter toute suspension, veuillez confirmer que vous êtes bien le propriétaire.

🔐 Vérifier mon compte : {url}

L'équipe Microsoft Security
""",
        "category": "microsoft"
    },
    {
        "subject": "Votre boîte de réception est presque pleine",
        "body": """
Bonjour,

Votre boîte de réception utilise {percent}% de l'espace alloué.
Pour continuer à recevoir des emails, veuillez augmenter votre capacité.

📊 Gérer mon espace : {url}

Merci,
L'équipe technique
""",
        "category": "storage"
    },
    
    # Livraison / Colis
    {
        "subject": "Chronopost: Livraison impossible",
        "body": """
Bonjour,

Notre livreur n'a pas pu déposer votre colis.
Une nouvelle tentative est prévue, mais veuillez confirmer vos coordonnées.

📮 Programmer une nouvelle livraison : {url}

Chronopost
""",
        "category": "delivery"
    },
    {
        "subject": "Votre colis est bloqué en douane",
        "body": """
Bonjour,

Votre colis est actuellement bloqué en douane.
Des frais de dédouanement sont requis pour finaliser la livraison.

💶 Payer les frais de douane : {url}

Service Colis International
""",
        "category": "delivery"
    },
    
    # Factures / Impôts
    {
        "subject": "Facture impayée - Action requise",
        "body": """
Bonjour,

Nous constatons un impayé sur votre facture du {date}.
Veuillez régulariser votre situation dans les plus brefs délais.

💰 Payer ma facture : {url}

Service Client
""",
        "category": "invoice"
    },
    {
        "subject": "Avis de contravention - Paiement en ligne",
        "body": """
Bonjour,

Vous avez reçu une contravention le {date}.
Le paiement en ligne est disponible jusqu'au {due_date}.

🚗 Payer mon amende : {url}

ANTAI - Service Public
""",
        "category": "invoice"
    },
]

# ============================================================================
# TEMPLATES D'EMAILS LÉGITIMES (SAFE)
# ============================================================================

SAFE_TEMPLATES = [
    # Newsletters
    {
        "subject": "Votre newsletter hebdomadaire",
        "body": """
Bonjour,

Voici les actualités de la semaine :

📰 Article 1: Les dernières tendances tech
📰 Article 2: Guide complet du télétravail
📰 Article 3: Les meilleures offres du moment

Pour vous désabonner, cliquez ici : {unsubscribe_link}

À la semaine prochaine !
""",
        "category": "newsletter"
    },
    {
        "subject": "Offres exclusives pour nos abonnés",
        "body": """
Bonjour,

Profitez de -20% sur toute la collection avec le code : PROMO20

Valable jusqu'au {expiry_date}.

🎁 Voir les offres : {url}

L'équipe
""",
        "category": "promo"
    },
    
    # Confirmation de commande
    {
        "subject": "Confirmation de votre commande #{order_id}",
        "body": """
Bonjour,

Nous vous remercions pour votre commande passée le {date}.

📦 Récapitulatif :
- Produit: {product}
- Quantité: {quantity}
- Montant: {amount}€

Suivre ma commande : {tracking_url}

Service Client
""",
        "category": "order"
    },
    {
        "subject": "Votre colis a été expédié",
        "body": """
Bonjour,

Votre commande #{order_id} a été expédiée.

📮 Numéro de suivi: {tracking_number}
🚚 Transporteur: {carrier}
📅 Livraison estimée: {delivery_date}

Suivre mon colis : {tracking_url}

Merci de votre confiance.
""",
        "category": "shipping"
    },
    
    # Rendez-vous / Confirmation
    {
        "subject": "Confirmation de votre rendez-vous",
        "body": """
Bonjour,

Votre rendez-vous du {date} à {time} est confirmé.

📍 Adresse: {address}
👤 Avec: {contact}

Modifier mon rendez-vous : {booking_url}

À bientôt !
""",
        "category": "appointment"
    },
    {
        "subject": "Rappel: Votre rendez-vous demain",
        "body": """
Bonjour,

Ceci est un rappel pour votre rendez-vous de demain à {time}.

N'oubliez pas d'apporter vos documents.

Voir les détails : {url}

Bonne journée.
""",
        "category": "reminder"
    },
    
    # Facture / Reçu légitime
    {
        "subject": "Votre facture du mois {month}",
        "body": """
Bonjour,

Votre facture du mois de {month} est disponible.

📄 Montant: {amount}€
📅 Date d'échéance: {due_date}

Télécharger ma facture : {invoice_url}

Service Client
""",
        "category": "invoice"
    },
    {
        "subject": "Reçu de votre paiement",
        "body": """
Bonjour,

Nous vous remercions pour votre paiement de {amount}€ du {date}.

📎 Télécharger mon reçu : {receipt_url}

Bonne journée.
""",
        "category": "receipt"
    },
    
    # Alertes légitimes
    {
        "subject": "Nouvelle connexion détectée",
        "body": """
Bonjour,

Une nouvelle connexion a été détectée sur votre compte.

🖥️ Appareil: {device}
📍 Localisation: {location}
📅 Date: {date}

Si ce n'est pas vous, modifiez immédiatement votre mot de passe : {security_url}

L'équipe sécurité
""",
        "category": "security"
    },
    
    # Réinitialisation de mot de passe
    {
        "subject": "Réinitialisation de votre mot de passe",
        "body": """
Bonjour,

Une demande de réinitialisation de mot de passe a été effectuée.

🔑 Réinitialiser mon mot de passe : {reset_url}

Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.

Ce lien expire dans 24 heures.
""",
        "category": "password"
    },
]

# ============================================================================
# GÉNÉRATEUR DE DATASET
# ============================================================================

class EmailDatasetGenerator:
    """
    Générateur de dataset d'emails pour entraînement.
    """
    
    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.phishing_templates = PHISHING_TEMPLATES
        self.safe_templates = SAFE_TEMPLATES
        
        # URLs de phishing (variées)
        self.phishing_urls = [
            "https://secure-login-verify.tk",
            "https://paypal-verification-security.com",
            "https://amazon-account-update.xyz",
            "https://microsoft-security-alert.cf",
            "https://banque-en-ligne-securisee.ga",
            "https://apple-id-verification.icu",
            "https://netflix-billing-update.top",
            "https://dhl-delivery-failed.xyz",
            "https://facture-impayee-online.cf",
            "https://colissimo-livraison.ga",
        ]
        
        # URLs légitimes
        self.safe_urls = [
            "https://www.amazon.fr/gp/help/customer/account",
            "https://www.paypal.com/fr/signin",
            "https://login.microsoftonline.com",
            "https://appleid.apple.com/sign-in",
            "https://www.boursorama.com/connexion",
            "https://www.netflix.com/login",
            "https://github.com/login",
            "https://accounts.google.com",
            "https://www.laposte.fr/suivi",
            "https://www.impots.gouv.fr/portail",
        ]
        
        # Noms de banques
        self.bank_names = ["BNP Paribas", "Société Générale", "Crédit Agricole", "LCL", "CIC", "Banque Populaire"]
        
        # Produits
        self.products = ["iPhone 15 Pro", "MacBook Air", "Samsung TV", "Nike Air Max", "Cafetière Nespresso"]
        
        # Transporteurs
        self.carriers = ["Colissimo", "Chronopost", "DPD", "UPS", "Mondial Relay", "Amazon Logistics"]
        
        # Villes
        self.cities = ["Paris", "Lyon", "Marseille", "Bordeaux", "Lille", "Toulouse", "Nantes", "Strasbourg"]
    
    def _generate_url(self, is_phishing: bool) -> str:
        """Génère une URL aléatoire."""
        if is_phishing:
            return random.choice(self.phishing_urls) + f"/{random.randint(1000,9999)}"
        else:
            return random.choice(self.safe_urls)
    
    def _generate_date(self, days_ago: int = None) -> str:
        """Génère une date aléatoire."""
        if days_ago is None:
            days_ago = random.randint(1, 30)
        date = datetime.now() - timedelta(days=days_ago)
        return date.strftime("%d/%m/%Y")
    
    def _generate_email(self, template: dict, is_phishing: bool) -> str:
        """Génère un email à partir d'un template."""
        url = self._generate_url(is_phishing)
        
        # Variables dynamiques
        vars = {
            "url": url,
            "bank_name": random.choice(self.bank_names),
            "amount": f"{random.randint(10, 500):.2f}",
            "order_id": f"{random.randint(10000, 99999)}",
            "percent": random.randint(85, 99),
            "date": self._generate_date(),
            "due_date": self._generate_date(days_ago=-random.randint(1, 15)),
            "expiry_date": self._generate_date(days_ago=-random.randint(1, 7)),
            "product": random.choice(self.products),
            "quantity": str(random.randint(1, 3)),
            "tracking_number": f"{random.randint(1000000000, 9999999999)}",
            "carrier": random.choice(self.carriers),
            "delivery_date": self._generate_date(days_ago=random.randint(1, 7)),
            "tracking_url": url + "/tracking",
            "booking_url": url + "/booking",
            "address": f"{random.randint(1, 200)} rue de {random.choice(self.cities)}",
            "contact": random.choice(["Service Client", "Support Technique", "Votre conseiller"]),
            "time": f"{random.randint(8, 18)}h{random.randint(0, 59):02d}",
            "month": datetime.now().strftime("%B"),
            "invoice_url": url + "/invoice",
            "receipt_url": url + "/receipt",
            "device": random.choice(["Windows PC", "MacBook", "iPhone", "Android"]),
            "location": random.choice(self.cities),
            "security_url": url + "/security",
            "reset_url": url + "/reset-password",
            "unsubscribe_link": url + "/unsubscribe",
        }
        
        # Remplacer les variables dans le template
        email = template["body"]
        for key, value in vars.items():
            email = email.replace("{" + key + "}", str(value))
        
        # Nettoyer et formater
        email = re.sub(r'\n{3,}', '\n\n', email)  # Supprimer les lignes vides multiples
        email = email.strip()
        
        subject = template["subject"]
        for key, value in vars.items():
            subject = subject.replace("{" + key + "}", str(value))
        
        return {
            "text": f"Objet: {subject}\n\n{email}",
            "category": template["category"],
            "is_phishing": is_phishing
        }
    
    def generate_dataset(self, n_phishing: int = 5000, n_safe: int = 5000) -> pd.DataFrame:
        """
        Génère un dataset équilibré.
        
        Args:
            n_phishing: Nombre d'emails phishing à générer
            n_safe: Nombre d'emails légitimes à générer
        
        Returns:
            DataFrame avec colonnes ['text', 'label', 'category']
        """
        data = []
        
        # Générer les emails phishing
        print(f"📧 Génération de {n_phishing} emails phishing...")
        for i in range(n_phishing):
            template = random.choice(self.phishing_templates)
            email = self._generate_email(template, is_phishing=True)
            data.append({
                "text": email["text"],
                "label": 1,  # 1 = phishing
                "category": email["category"]
            })
            if (i + 1) % 1000 == 0:
                print(f"   {i+1}/{n_phishing} générés")
        
        # Générer les emails légitimes
        print(f"📧 Génération de {n_safe} emails légitimes...")
        for i in range(n_safe):
            template = random.choice(self.safe_templates)
            email = self._generate_email(template, is_phishing=False)
            data.append({
                "text": email["text"],
                "label": 0,  # 0 = safe
                "category": email["category"]
            })
            if (i + 1) % 1000 == 0:
                print(f"   {i+1}/{n_safe} générés")
        
        # Mélanger
        random.shuffle(data)
        
        df = pd.DataFrame(data)
        print(f"\n✅ Dataset généré: {len(df)} emails")
        print(f"   Phishing: {(df['label']==1).sum()}")
        print(f"   Safe: {(df['label']==0).sum()}")
        print(f"   Catégories: {df['category'].value_counts().to_dict()}")
        
        return df
    
    def save_dataset(self, df: pd.DataFrame, output_dir: str = "./data/email_dataset"):
        """Sauvegarde le dataset."""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        # Split train/val
        train_df, val_df = train_test_split(df, test_size=0.2, stratify=df['label'], random_state=42)
        
        train_df.to_csv(os.path.join(output_dir, "train.csv"), index=False)
        val_df.to_csv(os.path.join(output_dir, "val.csv"), index=False)
        
        print(f"\n💾 Dataset sauvegardé dans {output_dir}")
        print(f"   Train: {len(train_df)} emails")
        print(f"   Val: {len(val_df)} emails")
        
        return train_df, val_df


# ============================================================================
# EXEMPLE D'UTILISATION
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("📧 GÉNÉRATEUR DE DATASET EMAILS PHISHING/SAFE")
    print("=" * 60)
    
    # Créer le générateur
    generator = EmailDatasetGenerator(seed=42)
    
    # Générer 2000 emails (1000 phishing + 1000 safe) pour test rapide
    # Pour l'entraînement final, utiliser 10000 ou plus
    df = generator.generate_dataset(n_phishing=1000, n_safe=1000)
    
    # Sauvegarder
    train_df, val_df = generator.save_dataset(df, output_dir="./data/email_dataset")
    
    # Afficher quelques exemples
    print("\n" + "=" * 60)
    print("📧 EXEMPLES D'EMAILS")
    print("=" * 60)
    
    print("\n🔴 EXEMPLE PHISHING:")
    phishing_example = df[df['label'] == 1].iloc[0]
    print(phishing_example['text'])
    print(f"\nCatégorie: {phishing_example['category']}")
    
    print("\n" + "-" * 40)
    
    print("\n🟢 EXEMPLE SAFE:")
    safe_example = df[df['label'] == 0].iloc[0]
    print(safe_example['text'])
    print(f"\nCatégorie: {safe_example['category']}")