"""
VulnLab - vérifie si un flag soumis est correct.
Usage : python3 check_flag.py "FLAG{...}"
"""
import sys, hashlib

# Les flags ne sont pas stockés en clair ici pour que tu ne puisses pas tricher
# juste en lisant ce fichier. Seul leur empreinte (hash) est comparée.
VALID_HASHES = {
    "level1": "f2313947c584bfb75ee8aa41192b0427b922cd9a37d45b81cacd0234b92c1922",
    "level2": "6f9a2ae57244f218f5c36d1597c5de3f59704e01d676d9e2099d127322deb43d",
    "level3": "fde48ab12494aec2c0f3ff306d619d292ce792216f05f244c71f8f70f0847922",
    "level4": "ef64e64e081d73cdd0244936675a3d3a768e4b56a10c0b443e7406afa00f2d78",
    "level5": "cad707c5c7de2b6126a59f1664897c55ace1618329dff13cdce9f86890f1493a",
}


def check(flag: str) -> bool:
    h = hashlib.sha256(flag.strip().encode()).hexdigest()
    return h in VALID_HASHES.values()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 check_flag.py \"FLAG{...}\"")
        sys.exit(1)
    flag = sys.argv[1]
    if check(flag):
        print("✅ Flag correct, bravo !")
    else:
        print("❌ Pas le bon flag, continue de chercher.")
