"""
VulnLab - lance tous les niveaux en même temps.
Usage : python3 start.py          -> tout lancer
        python3 start.py 1        -> lancer uniquement le niveau 1
Nécessite Python 3 + flask (pip install flask).
"""
import subprocess, sys, os, signal, time

BASE = os.path.dirname(os.path.abspath(__file__))

TARGETS = {
    "1": ("level1/app.py", "Level 1 - Web (port 5001)"),
    "2": ("level2/app.py", "Level 2 - Web (port 5002)"),
    "3": ("level3/app.py", "Level 3 - Web (port 5003)"),
    "4": ("level4/service.py", "Level 4 - Service réseau (port 4444)"),
    "5": ("level5/app.py", "Level 5 - Web + réseau + privesc (port 5005)"),
}


def main():
    which = sys.argv[1:] if len(sys.argv) > 1 else list(TARGETS.keys())
    procs = []
    for key in which:
        if key not in TARGETS:
            print(f"Niveau inconnu: {key}")
            continue
        script, label = TARGETS[key]
        print(f"-> Démarrage {label}")
        script_dir = os.path.join(BASE, os.path.dirname(script))
        script_name = os.path.basename(script)
        p = subprocess.Popen([sys.executable, script_name], cwd=script_dir)
        procs.append(p)
        time.sleep(0.3)

    print("\nTout est lancé. Ctrl+C pour tout arrêter.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nArrêt des services...")
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
