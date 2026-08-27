#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr 23 09:02:41 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from urllib.parse import urljoin, urlparse, urldefrag, urlunparse

HEADERS =  {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'fr-FR,fr;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
}

def clean_url(url:str, preference:str = "https://") -> str:
    if url is None:
        return ""
    url = url.strip().strip("'\",;").strip()
    if not url.startswith(('http://', 'https://')):
        if url.startswith(':/'):
            url = preference + url
        else:
            url = preference + url
            
    return url

def normalize_link(base_url:str, url:str):
    """
    Méthode de normalisation des liens.

    Parameters
    ----------
    base_url : str
        Url de base.
    url : str
        Url a ajoutéz.

    Returns
    -------
    None | str
        None si échec et str si succès.

    """
    if not base_url or url is None:
        return None
    
    url = url.strip()
    base_url = base_url.strip()    
    if base_url.startswith("#"):
        return None
    
    if url.startswith("#"):
        return urldefrag(base_url)[0]

    if url.startswith("http"):
        return url
    
    if any(x.startswith(('javascript:', 'data:', 'mailto:', 'blob:', 'tel:')) for x in (url, base_url)):
        return None
    
    url_parse = urlparse(url)
    base_url_parse = urlparse(urldefrag(base_url)[0])
    
    if url_parse.scheme and url_parse.netloc:
        return url
    
    if url.startswith("//"):
        return base_url_parse.scheme + ':' + url
    
    if not base_url_parse.scheme and base_url_parse.netloc:
        return None
    
    
    final_url = urljoin(urlunparse(base_url_parse), urlunparse(url_parse))
    return urldefrag(final_url)[0]