#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jun  7 18:09:24 2026

@author: hounsousamuel
"""

import hashlib
import os


def checksum_path_for(path: str) -> str:
    """Calcule le chemin du fichier checksum associé à un fichier de modèle.

    Format : .sha_<nom_du_fichier_sans_extension>, dans le même dossier.

    Args:
        path (str): Chemin du fichier modèle (ex: .../model_2026-07-03T....pkl).

    Returns:
        str: Chemin du fichier checksum (ex: .../.sha_model_2026-07-03T...).
    """
    dirname = os.path.dirname(path)
    model_name = os.path.splitext(os.path.basename(path))[0]
    sha_name = f".sha_{model_name}"
    return os.path.join(dirname, sha_name)


def save(data: bytes, path: str):
    data = data if isinstance(data, bytes) else data.encode()
    checksum = hashlib.sha256(data).hexdigest()
    checksum_path = checksum_path_for(path)
    with open(checksum_path, "w") as f:
        f.write(checksum)

    with open(path, "wb") as f:
        f.write(data)

    return checksum


def load(path: str):
    try:
        checksum_path = checksum_path_for(path)
        with open(checksum_path) as f:
            expected = f.read().strip()

        with open(path, "rb") as f:
            data = f.read()

        checksum = hashlib.sha256(data).hexdigest()
        if expected != checksum:
            raise RuntimeError("Fichier invalide !")

        return data

    except RuntimeError:
        raise

    except Exception as e:
        raise RuntimeError(str(e))