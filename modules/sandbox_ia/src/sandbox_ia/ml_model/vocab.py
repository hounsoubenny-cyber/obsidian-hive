#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 29 23:06:45 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from sandbox_ia.configs.syscall_tracer_config import SYSCALL_FAMILIES

SYSCALL_VOCAB = {syscall: idx for idx, syscall in enumerate(SYSCALL_FAMILIES.keys())}
# + entrées spéciales
SYSCALL_VOCAB["fs_created"] = len(SYSCALL_VOCAB)
SYSCALL_VOCAB["fs_modified"] = len(SYSCALL_VOCAB)
SYSCALL_VOCAB["fs_deleted"] = len(SYSCALL_VOCAB)
SYSCALL_VOCAB["fs_moved"]  = len(SYSCALL_VOCAB)
SYSCALL_VOCAB["fs_opened"]  = len(SYSCALL_VOCAB)
SYSCALL_VOCAB["unknown"] = len(SYSCALL_VOCAB)  
SYSCALL_VOCAB["<UNK>"] = len(SYSCALL_VOCAB)  

SYSCALL_VOCAB_INVERSE = {v : k for k, v in SYSCALL_VOCAB.items()}

def encode(texte: str | list[str]) -> str | list[str] | None:
    if not texte:
        return None
    is_str = isinstance(texte, str)
    texte = [texte] if is_str else list(texte)
    encoded = [SYSCALL_VOCAB.get(x, SYSCALL_VOCAB["unknown"]) for x in texte]
    return encoded if not is_str else encoded[0]

def decode(encoded: int | list[int] ) -> str | list[str] | None:
    if not encoded and encoded != 0:
        return None
    is_int = isinstance(encoded, int)
    encoded = [encoded] if is_int else list(encoded)
    # print(encoded)
    decoded = [SYSCALL_VOCAB_INVERSE.get(x, "unknown") for x in encoded]
    return decoded if not is_int else decoded[0]

if __name__ == "__main__":
    print("\n" + "="*50)
    print("🧪 TEST vocab.py")
    print("="*50)

    # Taille du vocab
    print(f"\n📌 Taille vocab : {len(SYSCALL_VOCAB)}")
    assert "openat" in SYSCALL_VOCAB
    assert "execve" in SYSCALL_VOCAB
    assert "fs_created" in SYSCALL_VOCAB
    assert "unknown" in SYSCALL_VOCAB
    print("   ✅ entrées spéciales présentes")

    # encode str
    idx = encode("openat")
    assert isinstance(idx, int)
    print(f"   encode('openat') = {idx}")

    # encode liste
    idxs = encode(["execve", "connect", "openat"])
    assert isinstance(idxs, list) and len(idxs) == 3
    print(f"   encode(['execve','connect','openat']) = {idxs}")

    # encode inconnu → unknown
    idx_unk = encode("syscall_qui_nexiste_pas")
    assert idx_unk == SYSCALL_VOCAB["unknown"]
    print(f"   encode('inconnu') → unknown idx={idx_unk} ✅")

    # decode int
    name = decode(idx)
    assert name == "openat"
    print(f"   decode({idx}) = '{name}' ✅")

    # decode liste
    names = decode(idxs)
    assert names == ["execve", "connect", "openat"]
    print(f"   decode({idxs}) = {names} ✅")

    # decode inconnu → unknown
    name_unk = decode(99999)
    assert name_unk == "unknown"
    print(f"   decode(99999) = '{name_unk}' ✅")

    # encode/decode round-trip
    for syscall in ["ptrace", "mmap", "fs_created", "fs_deleted"]:
        assert decode(encode(syscall)) == syscall
    print("   ✅ round-trip encode→decode OK sur tous les syscalls")

    # None → None
    assert encode("") is None
    assert decode(0) is not None  # 0 est un index valide
    print("   ✅ cas limites OK")

    print("\n🎉 TOUS LES TESTS VOCAB PASSÉS")
    print("="*50)