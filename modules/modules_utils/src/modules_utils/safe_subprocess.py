#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jul  8 09:30:59 2026

@author: hounsousamuel
"""

"""
Exécution restreinte de commandes shell pour l'agent Analyst (Alex).

Principe : ALLOWLIST stricte, jamais de blacklist. Une blacklist essaie de lister
tout ce qui est dangereux (impossible à faire exhaustivement) ; une allowlist
liste tout ce qui est permis (fini, contrôlable).

Défense en profondeur :
  1. Seuls des binaires explicitement autorisés peuvent être lancés (par nom ET
     par chemin résolu réel — pas de confiance sur le PATH).
  2. Pas de shell=True, jamais — évite l'injection via ; | & $() `` etc.
  3. Certains binaires autorisés ont des flags qui leur donnent un pouvoir
     d'exécution arbitraire (find -exec, tar --to-command, awk system(), etc.)
     — ces flags sont bloqués par binaire, même si le binaire est autorisé.
  4. Timeout obligatoire, pas de I/O interactif.
  5. Recommandation forte : faire tourner ça DANS le module Sandbox que t'as
     déjà (strace/FSMonitor/BehaviorScorer) plutôt qu'en direct sur l'hôte —
     l'allowlist protège contre les commandes voulues malveillantes, pas contre
     un binaire légitime qui a un comportement inattendu une fois lancé.
"""

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field


class CommandNotAllowedError(Exception):
    """Levée quand une commande ou un de ses flags n'est pas autorisé."""


@dataclass
class CommandPolicy:
    """Politique d'exécution pour un binaire donné."""
    # Flags qui donnent à ce binaire un pouvoir d'exécution/écriture arbitraire.
    # Si un de ces tokens apparaît dans les arguments, la commande est rejetée.
    forbidden_flags: set[str] = field(default_factory=set)
    # Si True, aucun argument commençant par '-' n'est autorisé au-delà de
    # ceux listés dans allowed_flags (allowlist de flags, pas juste de binaire).
    strict_flags: bool = False
    allowed_flags: set[str] = field(default_factory=set)
    # Si renseigné, le token JUSTE APRÈS le binaire doit être un de ceux-ci
    # (ex: "status" pour systemctl) — sinon rejeté. None = pas de sous-
    # commande requise (comportement actuel, inchangé pour grep/cat/tail...).
    subcommands: set[str] | None = None


# Allowlist des binaires + leur politique de flags.
# Ne contient QUE des outils de lecture/inspection — rien qui écrit, supprime,
# ou fait du réseau. Si Alex a besoin d'écrire, il a déjà create_file /
# replace_file_content / modify_file_content — pas besoin de subprocess pour ça.
ALLOWED_COMMANDS: dict[str, CommandPolicy] = {
    "grep":  CommandPolicy(),  # pas de flag connu dangereux
    "egrep": CommandPolicy(),
    "fgrep": CommandPolicy(),
    "cat":   CommandPolicy(),
    "head":  CommandPolicy(),
    "tail":  CommandPolicy(forbidden_flags={"-f", "--follow"}),  # -f bloque le process
    "wc":    CommandPolicy(),
    "diff":  CommandPolicy(),
    "sort":  CommandPolicy(),
    "uniq":  CommandPolicy(),
    "find":  CommandPolicy(forbidden_flags={
        "-exec", "-execdir", "-delete", "-ok", "-okdir", "-fprintf",
    }),
    "file":  CommandPolicy(),
    "stat":  CommandPolicy(),
    "du":    CommandPolicy(),
    "ls":    CommandPolicy(),
}

# Répertoires système où on accepte de résoudre un binaire — évite qu'un
# ".../malicious_dir/grep" planté dans un PATH pollué soit exécuté à la place
# du vrai /usr/bin/grep.
TRUSTED_BIN_DIRS = {"/usr/bin", "/bin", "/usr/local/bin"}


def _resolve_binary(name: str) -> str:
    """Résout un nom de commande vers son chemin réel et vérifie qu'il vient
    d'un répertoire système de confiance, pas d'un PATH détourné."""
    resolved = shutil.which(name)
    if resolved is None:
        raise CommandNotAllowedError(f"Binaire introuvable : {name!r}")

    real = os.path.realpath(resolved)
    real_dir = os.path.dirname(real)
    if real_dir not in TRUSTED_BIN_DIRS:
        raise CommandNotAllowedError(
            f"Binaire {name!r} résolu en dehors des répertoires de confiance "
            f"({real}) — rejeté."
        )
    return real


def _check_args(binary_name: str, args: list[str], policy: CommandPolicy) -> None:
    for arg in args:
        # Un flag combiné type -exec passé autrement (ex: --exec=xxx) doit
        # aussi être capté : on compare sur le préfixe avant '='.
        flag = arg.split("=", 1)[0]
        if flag in policy.forbidden_flags:
            raise CommandNotAllowedError(
                f"Flag interdit pour {binary_name!r} : {arg!r}"
            )
        if policy.strict_flags and flag.startswith("-") and flag not in policy.allowed_flags:
            raise CommandNotAllowedError(
                f"Flag non autorisé pour {binary_name!r} : {arg!r}"
            )


def safe_run(
    cmd: str, 
    cwd: str | None = None,
    timeout: int = 30,
    allowed_commands: dict[str, CommandPolicy] = ALLOWED_COMMANDS
) -> dict:
    """
    Exécute une commande de manière restreinte (allowlist + flags interdits).

    Args:
        cmd: Commande complète telle que générée par le LLM, ex: "grep -n TODO /path"
        cwd: Répertoire de travail (optionnel)
        timeout: Timeout en secondes (défaut 30, jamais illimité)

    Returns:
        Dict avec stdout / stderr / returncode / success

    Raises:
        CommandNotAllowedError: si le binaire ou un de ses flags n'est pas autorisé
    """
    try:
        argv = shlex.split(cmd)
    except ValueError as e:
        raise CommandNotAllowedError(f"Commande mal formée : {e}")

    if not argv:
        raise CommandNotAllowedError("Commande vide")

    binary_name = os.path.basename(argv[0])
    policy = allowed_commands.get(binary_name)
    if policy is None:
        raise CommandNotAllowedError(
            f"Commande {binary_name!r} non autorisée. "
            f"Autorisées : {sorted(allowed_commands)}"
        )
    
    remaining_args = argv[1:]

    if policy.subcommands is not None:
        if not remaining_args:
            raise CommandNotAllowedError(f"Sous-commande manquante pour {binary_name!r}")
        subcommand = remaining_args[0]
        if subcommand not in policy.subcommands:
            raise CommandNotAllowedError(
                f"Sous-commande {subcommand!r} non autorisée pour {binary_name!r}. "
                f"Autorisées : {sorted(policy.subcommands)}"
            )
        remaining_args = remaining_args[1:]  # le reste des args est vérifié normalement après


    resolved_path = _resolve_binary(binary_name)
    _check_args(binary_name, remaining_args, policy)

    try:
        result = subprocess.run(
            [resolved_path, *argv[1:]],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,          # non négociable
            env={"PATH": "/usr/bin:/bin"},  # PATH minimal, pas l'env hérité complet
        )
    except subprocess.TimeoutExpired:
        return {
            "stdout": "", "stderr": f"Timeout après {timeout}s",
            "returncode": -1, "success": False,
        }

    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
        "success": result.returncode == 0,
    }


if __name__ == "__main__":
    # Quelques essais rapides
    print(safe_run("grep -n def /etc/hostname"))
    try:
        safe_run("rm -rf /tmp/test")
    except CommandNotAllowedError as e:
        print("OK rejeté:", e)
    try:
        safe_run("find / -name '*.conf' -exec cat {} \\;")
    except CommandNotAllowedError as e:
        print("OK rejeté:", e)
    try:
        safe_run("/tmp/evil_grep -n x /etc/hostname")
    except CommandNotAllowedError as e:
        print("OK rejeté:", e)
    
    try:
        print(safe_run("grep -n  -r 'import' -C 2 --include='*.py' ."))
    except CommandNotAllowedError as e:
        print("OK rejeté:", e)