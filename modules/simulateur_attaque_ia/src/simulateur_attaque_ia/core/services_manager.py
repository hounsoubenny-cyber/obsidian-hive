#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
services_manager.py

@author: hounsousamuel

Capture et restauration de services (process host -> container), plus
déploiement de services factices prédéfinis (fake HTTP/SSH/FTP) pour des
scénarios de test reproductibles, indépendants de ce qui tourne réellement
sur le host.
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import shlex
import psutil
import json
from simulateur_attaque_ia.core.services_manager_config import is_gui_process
from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.core.fake_services_scripts import DEFAULT_SERVICE_REGISTRY
from simulateur_attaque_ia.simulateur_utils.logger import get_logger

logger = get_logger()

BASEDIR = os.path.dirname(os.path.abspath(__file__))
SAVEDIR = os.path.abspath(os.path.join(BASEDIR, "services"))
os.makedirs(SAVEDIR, exist_ok=True)

# Process d'infrastructure système à exclure par défaut de la capture —
# jamais des "services" applicatifs utiles à répliquer dans un container cible.
DEFAULT_EXCLUDED_NAMES: set[str] = {
    "systemd", "systemd-journald", "systemd-logind", "systemd-machined",
    "systemd-resolved", "systemd-udevd", "systemd-userdbd",
    "systemd-userwork:", "(sd-pam)",
    "dbus-broker", "dbus-broker-launch", "dbus-daemon",
    "containerd", "containerd-shim-runc-v2", "dockerd",
    "NetworkManager", "wpa_supplicant", "ModemManager",
    "polkitd", "irqbalance", "mcelog", "smartd", "thermald",
    "tuned", "tuned-ppd", "alsactl", "atd", "crond", "auditd",
    "gssproxy", "abrtd", "abrt-dump-journal-core", "abrt-dump-journal-oops",
    "abrt-dump-journal-xorg", "avahi-daemon", "pcscd", "cupsd",
    "gdm", "gdm-session-worker", "fusermount3", "ssh-agent",
    "sleep",
}


def _process_listen_ports(proc: "psutil.Process") -> list[int]:
    """
    Résout les ports en LISTEN d'un process via psutil, par-process
    (plutôt que via psutil.net_connections() global, qui retourne pid=None
    pour les connexions d'autres utilisateurs sans root).

    Fonctionne sans privilège root pour les process du même utilisateur.
    Reste soumis aux permissions noyau pour les process d'autres users —
    c'est une contrainte OS, pas quelque chose que la lib peut contourner.
    """
    try:
        get_conns = getattr(proc, "net_connections", None) or getattr(proc, "connections")
        conns = get_conns(kind="inet")
    except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
        return []
    return sorted({
        c.laddr.port for c in conns
        if getattr(c, "status", None) == psutil.CONN_LISTEN and c.laddr
    })


class ServiceManager:

    @staticmethod
    def capture_services(
        excluded_pids: list[int] = None,
        excludes_names: list[str] = None,
        excluded_ports: list[int] = None,
        only_listening: bool = False,
        use_default_excludes: bool = True,
        warn_if_not_root: bool = True,
    ) -> dict:
        """
        Capture les process du host, avec résolution des ports LISTEN
        associés (fix par-process, cf. _process_listen_ports).

        Args:
            excluded_pids: PIDs à ignorer explicitement.
            excludes_names: noms de process à ignorer, en plus des defaults.
            excluded_ports: ports à ignorer même s'ils sont trouvés.
            only_listening: si True, ne garde que les process avec >=1 port
                confirmé en LISTEN (filtre les vrais candidats "service réseau").
            use_default_excludes: applique DEFAULT_EXCLUDED_NAMES en plus
                de excludes_names (mettre False pour un scan brut complet).
            warn_if_not_root: log un avertissement si la capture tourne
                sans privilège root (résolution de ports potentiellement
                incomplète pour les process d'autres utilisateurs).
        """
        if warn_if_not_root and hasattr(os, "geteuid") and os.geteuid() != 0:
            logger.print(
                "⚠️ capture_services() exécuté sans privilège root — "
                "la résolution des ports pour les process d'autres utilisateurs "
                "(ex: services système lancés en root/apache) sera incomplète."
            )

        seen_pids: dict[int, dict] = {}
        excluded_pids = set(excluded_pids or [])
        excludes_names = set(excludes_names or [])
        if use_default_excludes:
            excludes_names |= DEFAULT_EXCLUDED_NAMES
        excluded_ports = set(excluded_ports or [])

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe', 'cwd', 'username']):
            try:
                info = proc.info
                if (not info['cmdline']
                    or info['pid'] in seen_pids
                    or info['pid'] in excluded_pids
                    or info['name'] in excludes_names):
                    continue
                try:
                    environ = proc.environ()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    environ = {}

                ports = [p for p in _process_listen_ports(proc) if p not in excluded_ports]

                if only_listening and not ports:
                    continue

                entry = {
                    "name": info['name'],
                    "cmdline": info['cmdline'],
                    "exe": info['exe'],
                    "cwd": info['cwd'],
                    "user": info['username'],
                    "environ": environ,
                    "ports": ports,
                }
                if not is_gui_process(entry):
                    seen_pids[info['pid']] = entry

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return seen_pids

    @staticmethod
    def restore_services(
        manager: DockerManager,
        services: list[dict] = None,
        default_services: dict[str, list[int]] = None,
        exec: bool = True,
    ) -> str | None:
        """
        Restaure des services dans un container.

        Args:
            services: liste d'entrées capturées via capture_services(),
                rejouées telles quelles (comportement historique inchangé).
            default_services: dict {"http": [80, 8080], "ssh": [22], "ftp": [21]}
                pour déployer des fake services prédéfinis via
                deploy_default_services(), indépendamment du scan système.
            exec: si False, construit les commandes sans les exécuter
                (dry-run / inspection).

        Returns:
            La commande bash construite pour les `services` capturés
            (None si `services` est vide/absent). Les commandes pour
            `default_services` sont exécutées/retournées séparément par
            deploy_default_services() — voir sa valeur de retour si besoin
            d'inspection détaillée.
        """
        final_cmd = None

        if isinstance(services, dict):
            services = list(services.values())

        if services:
            cmds = []
            for entry in services:
                env = entry["environ"]
                cmdline = shlex.join(entry["cmdline"])
                cwd = entry["cwd"]
                env_str = ' '.join(f'{k}={shlex.quote(str(v))}' for k, v in env.items())
                if cwd:
                    cmd = f'{env_str} cd {cwd} && {cmdline}'.strip()
                else:
                    cmd = f'{env_str} {cmdline}'.strip()

                if not cmd.endswith("&"):
                    cmd += " &"
                cmds.append(cmd)

            joined = " ".join(cmds).strip() if cmds else None
            if joined:
                final_cmd = f"bash -c {shlex.quote(joined)} "
                if exec:
                    manager.exec_command(final_cmd)

        if default_services:
            ServiceManager.deploy_default_services(manager, default_services, exec=exec)

        return final_cmd

    @staticmethod
    def deploy_default_services(
        manager: DockerManager,
        default_services: dict[str, list[int]],
        exec: bool = True,
    ) -> list[str]:
        """
        Déploie des fake services prédéfinis (http/ssh/ftp) dans un container,
        via les scripts de fake_services_scripts.DEFAULT_SERVICE_REGISTRY.

        Indépendant du scan système — utile pour des cibles de test
        reproductibles (mêmes ports, mêmes bannières, à chaque run).

        Args:
            default_services: ex. {"http": [80, 8080], "ssh": [22, 2222], "ftp": [21]}
                Si la liste de ports pour un service est vide/None, les ports
                par défaut du registre sont utilisés.
            exec: si False, construit les commandes sans les exécuter.

        Returns:
            Liste des commandes bash construites (une par port lancé),
            utile pour logging/inspection même en mode exec=False.

        Raises:
            ValueError: si un type de service demandé n'existe pas dans
                DEFAULT_SERVICE_REGISTRY.
        """
        cmds = []
        for kind, ports in default_services.items():
            tpl = DEFAULT_SERVICE_REGISTRY.get(kind)
            if tpl is None:
                raise ValueError(
                    f"Service par défaut inconnu : '{kind}'. "
                    f"Disponibles : {sorted(DEFAULT_SERVICE_REGISTRY)}"
                )

            script_path = f"/tmp/fake_{kind}.py"
            manager.exec_command(["mkdir", "-p", "/tmp"], show=False)
            heredoc = f"cat > {script_path} << 'SHIELDAI_EOF'\n{tpl['script']}\nSHIELDAI_EOF"
            if exec:
                manager.exec_command(["bash", "-c", heredoc], show=False)

            target_ports = ports or tpl["ports"]
            for port in target_ports:
                log_path = f"/tmp/fake_{kind}_{port}.log"
                # nohup : évite que le process soit tué si la session exec
                # se termine avant que le script ait fini de se détacher.
                cmd = f"nohup python3 {script_path} {port} >> {log_path} 2>&1 &"
                cmds.append(cmd)
                if exec:
                    manager.exec_command(["bash", "-c", cmd], show=False)
                    logger.print(f"  ✅ Fake {kind} déployé sur le port {port} (log: {log_path})")

        return cmds

    @staticmethod
    def run(
        manager: DockerManager,
        excluded_pids: list[int] = None,
        excludes_names: list[str] = None,
        excluded_ports: list[int] = None,
        default_services: dict[str, list[int]] = None,
        only_listening: bool = False,
        exec: bool = True,
    ) -> dict:
        """
        Pipeline complet : capture (optionnellement filtrée sur les process
        avec ports confirmés) + restauration, avec possibilité d'ajouter des
        fake services par défaut en plus/à la place du scan.
        """
        services = ServiceManager.capture_services(
            excluded_pids=excluded_pids,
            excluded_ports=excluded_ports,
            excludes_names=excludes_names,
            only_listening=only_listening,
        )
        cmd = None
        if services or default_services:
            cmd = ServiceManager.restore_services(
                manager,
                list(services.values()) if services else None,
                default_services=default_services,
                exec=exec,
            )

        return {
            "success": (cmd is not None and len(services) > 0) or bool(default_services),
            "services": services,
            "cmd": cmd,
        }

    @staticmethod
    def save(services: list[dict], name: str, path: str = None):
        if not path:
            path = os.path.join(SAVEDIR, name + ".json")
        with open(path, "w") as f:
            f.write(json.dumps(services, default=str))
        return path

    @staticmethod
    def load(name: str, path: str = None):
        if not path:
            path = os.path.join(SAVEDIR, name + ".json")
        return json.loads(open(path).read())


if __name__ == "__main__":
    sm = ServiceManager()
    result = sm.capture_services(only_listening=True)
    print(json.dumps(result, indent=2, default=str))