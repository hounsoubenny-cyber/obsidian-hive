#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utilitaires d'extraction et de préparation des emails pour la détection de phishing.

Ce module fournit :
- parse_email()      : parsing structuré d'un .eml brut en 3 couches
- build_bert_input() : construction du texte enrichi pour BERT
- extract_urls()     : extraction des URLs du mail (pour AntiPhishing.predict_url)
- get_spf_status()   : interprétation du header SPF
- get_dkim_status()  : présence/absence DKIM

Auteur: HOUNSOU Samuel
Version: 1.0.0
"""

import os
import re
import email
import quopri
import base64
from email import policy
from email.header import decode_header
from urllib.parse import urlparse
from typing import Optional


# ============================================================================
# CONSTANTES
# ============================================================================

# Tags utilisés pour structurer l'input BERT
BERT_TAGS = {
    "from":     "[FROM]",
    "reply_to": "[REPLY_TO]",
    "subject":  "[SUBJECT]",
    "spf":      "[SPF]",
    "dkim":     "[DKIM]",
    "urls":     "[URLS]",
    "body":     "[BODY]",
}

# Nombre max d'URLs à inclure dans l'input BERT (évite le débordement des 512 tokens)
MAX_URLS_BERT = 10

# Longueur max du body dans l'input BERT
MAX_BODY_BERT = 300

# Regex URLs (couvre http/https, ignore les artefacts HTML)
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)

# Headers SPF courants
SPF_PASS_VALUES    = ("pass",)
SPF_FAIL_VALUES    = ("fail", "softfail", "hardfail")
SPF_NEUTRAL_VALUES = ("neutral", "none", "permerror", "temperror")


# ============================================================================
# FONCTIONS UTILITAIRES INTERNES
# ============================================================================

def _decode_header_value(raw_value: str) -> str:
    """
    Décode un header email encodé (RFC 2047 : =?utf-8?...?=).

    Args:
        raw_value: Valeur brute du header

    Returns:
        str: Valeur décodée en texte lisible
    """
    if not raw_value:
        return ""
    parts = decode_header(raw_value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            try:
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            except Exception:
                decoded.append(part.decode("utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return " ".join(decoded).strip()


def _extract_text_from_part(part) -> str:
    """
    Extrait le texte brut d'une partie MIME.

    Gère les encodages quoted-printable et base64.

    Args:
        part: Partie MIME (email.message.Message)

    Returns:
        str: Texte décodé
    """
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        return ""


def _clean_body(raw_body: str) -> str:
    """
    Nettoie le body texte : supprime balises HTML résiduelles,
    espaces multiples, lignes vides consécutives.

    Args:
        raw_body: Texte brut potentiellement pollué

    Returns:
        str: Texte nettoyé
    """
    # Supprimer balises HTML résiduelles
    text = re.sub(r"<[^>]+>", " ", raw_body)
    # Supprimer entités HTML (&nbsp; &amp; etc.)
    text = re.sub(r"&[a-zA-Z]{2,6};", " ", text)
    # Supprimer URLs (elles sont extraites séparément)
    text = URL_PATTERN.sub(" [URL] ", text)
    # Normaliser espaces
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ============================================================================
# FONCTIONS PRINCIPALES
# ============================================================================

def get_spf_status(spf_header: str) -> str:
    """
    Interprète le header Received-SPF et retourne un statut lisible.

    Args:
        spf_header: Valeur brute du header Received-SPF

    Returns:
        str: 'pass' | 'fail' | 'neutral' | 'absent'

    Example:
        >>> get_spf_status("pass (google.com: domain of x@gmail.com designates ...)")
        'pass'
    """
    if not spf_header:
        return "absent"
    lower = spf_header.lower()
    if any(v in lower for v in SPF_PASS_VALUES):
        return "pass"
    if any(v in lower for v in SPF_FAIL_VALUES):
        return "fail"
    return "neutral"


def get_dkim_status(dkim_header: str) -> str:
    """
    Retourne la présence/absence de la signature DKIM.

    Args:
        dkim_header: Valeur brute du header DKIM-Signature

    Returns:
        str: 'present' | 'absent'
    """
    return "present" if dkim_header else "absent"


def extract_urls(text: str, unique: bool = True) -> list[str]:
    """
    Extrait toutes les URLs HTTP/HTTPS d'un texte.

    Args:
        text: Texte source (body, headers, HTML...)
        unique: Si True, déduplique les URLs

    Returns:
        list[str]: Liste d'URLs trouvées

    Example:
        >>> extract_urls("Visit http://paypal-verify.tk/login for your account")
        ['http://paypal-verify.tk/login']
    """
    urls = URL_PATTERN.findall(text)
    # Nettoyer les caractères parasites de fin
    cleaned = []
    for url in urls:
        url = url.rstrip(".,;:!?\"'")
        if url:
            cleaned.append(url)

    if unique:
        seen = set()
        result = []
        for url in cleaned:
            if url not in seen:
                seen.add(url)
                result.append(url)
        return result

    return cleaned


def parse_email(raw_eml: str) -> dict:
    """
    Parse un email brut (.eml) en 3 couches structurées.

    Couche 1 — Headers critiques :
        from, reply_to, subject, spf, dkim

    Couche 2 — Body texte propre :
        Texte extrait des parties text/plain et text/html,
        nettoyé des balises et encodages.

    Couche 3 — URLs :
        Toutes les URLs HTTP/HTTPS trouvées dans le mail
        (body + headers), dédupliquées.

    Args:
        raw_eml: Contenu brut du fichier .eml

    Returns:
        dict: {
            "headers": {
                "from": str,
                "reply_to": str,
                "subject": str,
                "spf": str,          # statut interprété : pass|fail|neutral|absent
                "dkim": str,         # present|absent
                "spf_raw": str,      # valeur brute du header
                "dkim_raw": str,
                "date": str,
                "message_id": str,
            },
            "body": str,             # texte propre, sans HTML ni URLs
            "body_html": str,        # HTML brut si disponible
            "urls": list[str],       # URLs extraites (dédupliquées)
            "is_multipart": bool,
            "has_attachment": bool,
            "attachment_names": list[str],
        }

    Example:
        >>> with open("phishing.eml") as f:
        ...     raw = f.read()
        >>> parsed = parse_email(raw)
        >>> print(parsed["headers"]["spf"])
        'fail'
        >>> print(parsed["urls"])
        ['http://paypal-verify.tk/login']
    """
    msg = email.message_from_string(raw_eml, policy=policy.compat32)

    # ── Couche 1 : Headers ───────────────────────────────────────────────────
    spf_raw  = msg.get("Received-SPF", "") or msg.get("Authentication-Results", "")
    dkim_raw = msg.get("DKIM-Signature", "")

    headers = {
        "from":       _decode_header_value(msg.get("From", "")),
        "reply_to":   _decode_header_value(msg.get("Reply-To", "")),
        "subject":    _decode_header_value(msg.get("Subject", "")),
        "spf":        get_spf_status(spf_raw),
        "dkim":       get_dkim_status(dkim_raw),
        "spf_raw":    spf_raw,
        "dkim_raw":   dkim_raw,
        "date":       _decode_header_value(msg.get("Date", "")),
        "message_id": msg.get("Message-ID", ""),
    }

    # ── Couche 2 : Body ──────────────────────────────────────────────────────
    body_plain = ""
    body_html  = ""
    attachment_names = []
    has_attachment = False

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition  = str(part.get("Content-Disposition", ""))

            # Pièces jointes
            if "attachment" in disposition:
                has_attachment = True
                filename = part.get_filename()
                if filename:
                    attachment_names.append(_decode_header_value(filename))
                continue

            if content_type == "text/plain":
                body_plain += _extract_text_from_part(part)
            elif content_type == "text/html":
                body_html += _extract_text_from_part(part)
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            body_plain = _extract_text_from_part(msg)
        elif content_type == "text/html":
            body_html = _extract_text_from_part(msg)

    # Priorité : text/plain, sinon on nettoie le HTML
    raw_body = body_plain if body_plain.strip() else body_html
    body_clean = _clean_body(raw_body)

    # ── Couche 3 : URLs ──────────────────────────────────────────────────────
    # Chercher dans body plain + body html + headers From/Reply-To/Subject
    full_text_for_urls = " ".join([
        body_plain,
        body_html,
        headers["from"],
        headers["reply_to"],
        headers["subject"],
    ])
    urls = extract_urls(full_text_for_urls, unique=True)

    return {
        "headers":          headers,
        "body":             body_clean,
        "body_html":        body_html,
        "urls":             urls,
        "is_multipart":     msg.is_multipart(),
        "has_attachment":   has_attachment,
        "attachment_names": attachment_names,
    }


def build_bert_input(parsed: dict) -> str:
    """
    Construit le texte structuré à fournir à BERT pour la classification.

    Le texte suit un format balisé qui guide l'attention du modèle
    vers les zones importantes du mail (expéditeur, sujet, SPF/DKIM, URLs).

    Args:
        parsed: Dictionnaire retourné par parse_email()

    Returns:
        str: Texte balisé, tronqué pour tenir dans les 512 tokens BERT

    Example:
        >>> parsed = parse_email(raw_eml)
        >>> text = build_bert_input(parsed)
        >>> print(text)
        "[FROM] support@paypa1.tk [SUBJECT] URGENT verify [SPF] fail
         [DKIM] absent [URLS] http://paypa1.tk/login [BODY] Click here ..."
    """
    h = parsed["headers"]

    # URLs : on prend les MAX_URLS_BERT premières, domaine seulement pour économiser les tokens
    urls_short = []
    for url in parsed["urls"][:MAX_URLS_BERT]:
        try:
            domain = urlparse(url).netloc
            urls_short.append(domain if domain else url)
        except Exception:
            urls_short.append(url)

    urls_str  = " ".join(urls_short) if urls_short else "none"
    body_str  = parsed["body"][:MAX_BODY_BERT]

    parts = [
        f"{BERT_TAGS['from']} {h['from']}",
        f"{BERT_TAGS['reply_to']} {h['reply_to']}" if h["reply_to"] else "",
        f"{BERT_TAGS['subject']} {h['subject']}",
        f"{BERT_TAGS['spf']} {h['spf']}",
        f"{BERT_TAGS['dkim']} {h['dkim']}",
        f"{BERT_TAGS['urls']} {urls_str}",
        f"{BERT_TAGS['body']} {body_str}",
    ]

    return " ".join(p for p in parts if p).strip()


def parse_email_from_file(path: str) -> dict:
    """
    Wrapper : parse un fichier .eml depuis son chemin.

    Args:
        path: Chemin vers le fichier .eml

    Returns:
        dict: Résultat de parse_email()

    Example:
        >>> parsed = parse_email_from_file("emails/phishing_001.eml")
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    return parse_email(raw)


def parse_mail_and_build_bert_input(mail_or_path: str, is_file: bool = False) -> str:
    if is_file:
        if not os.path.exists(mail_or_path):
            raise FileNotFoundError(f"Fichier introuvable : {mail_or_path}")
        with open(mail_or_path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    else:
        raw = mail_or_path
        
    return build_bert_input(parse_email(raw))

# ============================================================================
# TEST RAPIDE
# ============================================================================

if __name__ == "__main__":
    SAMPLE_EML = """From: support@paypa1-secure.tk
Reply-To: noreply@fake-paypal.ru
To: victim@gmail.com
Subject: =?utf-8?q?URGENT=3A_Verify_your_PayPal_account?=
Date: Mon, 25 May 2026 10:00:00 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=paypa1-secure.tk; ...
Received-SPF: fail (google.com: domain of support@paypa1-secure.tk does not
    designate 185.220.101.1 as permitted sender)
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear Customer,</p>
<p>Your account has been <b>limited</b>. Click below to verify:</p>
<a href="http://paypa1-secure.tk/login?token=ABC123">Verify Now</a>
<br>
<a href="http://steal-credentials.xyz/paypal">Alternative link</a>
</body></html>
"""

    parsed = parse_email(SAMPLE_EML)

    print("=" * 60)
    print("HEADERS")
    print("=" * 60)
    for k, v in parsed["headers"].items():
        if not k.endswith("_raw"):
            print(f"  {k:12s}: {v}")

    print("\n" + "=" * 60)
    print("BODY (nettoyé)")
    print("=" * 60)
    print(" ", parsed["body"])

    print("\n" + "=" * 60)
    print("URLs extraites")
    print("=" * 60)
    for url in parsed["urls"]:
        print(" ", url)

    print("\n" + "=" * 60)
    print("INPUT BERT")
    print("=" * 60)
    print(build_bert_input(parsed))

    print("\n" + "=" * 60)
    print(f"Multipart     : {parsed['is_multipart']}")
    print(f"Pièce jointe  : {parsed['has_attachment']}")
    print("=" * 60)


