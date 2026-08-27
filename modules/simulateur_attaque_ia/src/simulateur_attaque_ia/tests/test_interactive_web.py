#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 14:01:06 2026

@author: hounsousamuel
"""

"""
test_interactive_web.py — Pilote interactif pour une simulation web.

Se connecte à l'API, démarre une simulation en mode 'interactive',
ouvre un WebSocket, et permet de piloter la sim via des commandes.

UI : Rich (magnifique) | Input : prompt_toolkit (auto-complétion)

Dépendances :
    pip install httpx websockets rich prompt-toolkit

Usage :
    python test_interactive_web.py \
        --base-url http://127.0.0.1:8000/api \
        --username admin \
        --password ChangeMe123 \
        --image mon_image:latest

    python test_interactive_web.py \
        --base-url http://127.0.0.1:8000/api \
        --username admin \
        --password ChangeMe123 \
        --session-id sim_abc123

CHANGEMENTS vs version précédente :
  - Suppression du double-prompt (listen_ws n'imprime plus ">>> " lui-même,
    input() gère déjà le sien) — évitait des lignes vides qui masquaient
    les vrais messages serveur.
  - handle_message() est maintenant appelée dans son propre try/except :
    une exception sur UN message (champ manquant, format inattendu) ne
    tue plus silencieusement toute la tâche listen_ws — elle affiche la
    trace et continue d'écouter les messages suivants.
  - Ajout du type "step_success" (envoyé par le serveur en plus de
    step_start/step_progress/step_result) avec un affichage dédié au lieu
    de tomber dans le fallback JSON brut tronqué.
"""
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_interactive_web.py — Pilote interactif pour une simulation web.

Se connecte à l'API, démarre une simulation en mode 'interactive',
ouvre un WebSocket, et permet de piloter la sim via des commandes.

UI : Rich (magnifique) | Input : prompt_toolkit (auto-complétion)

Dépendances :
    pip install httpx websockets rich prompt-toolkit

Usage :
    python test_interactive_web.py \
        --base-url http://127.0.0.1:8000/api \
        --username admin \
        --password ChangeMe123 \
        --image mon_image:latest

    python test_interactive_web.py \
        --base-url http://127.0.0.1:8000/api \
        --username admin \
        --password ChangeMe123 \
        --session-id sim_abc123
"""

import argparse
import asyncio
import json
import sys
import time
import traceback
from typing import Any, Dict, List, Optional

import httpx
import websockets

# ─── Rich ────────────────────────────────────────────────────────────────────
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

# ─── Prompt Toolkit ─────────────────────────────────────────────────────────
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter, FuzzyCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style

console = Console()

# ─── Style Prompt Toolkit ───────────────────────────────────────────────────
PT_STYLE = Style.from_dict({
    "prompt": "bold ansicyan",
    "prompt.arrow": "bold ansiyellow",
    "completion-menu.completion": "bg:#1a2d3a #c8dde8",
    "completion-menu.completion.current": "bg:#00d4ff #000000 bold",
    "auto-suggestion": "ansibrightblack italic",
})

_session = PromptSession(
    history=InMemoryHistory(),
    auto_suggest=AutoSuggestFromHistory(),
    style=PT_STYLE,
    mouse_support=False,
)

# ─── Constantes de couleurs et icônes pour les actions ─────────────────────
ACTION_COLORS = {
    "reconnaissance":       "bold cyan",
    "initial_access":       "bold yellow",
    "execution":            "bold green",
    "privilege_escalation": "bold magenta",
    "credential_access":    "bold red",
    "lateral_movement":     "bold blue",
    "exfiltration":         "bold white on red",
    "defense_evasion":      "bold white on black",
    "persistence":          "bold green",
    "report":               "bold cyan",
}

ACTION_ICONS = {
    "reconnaissance":       "🔍",
    "initial_access":       "🔑",
    "execution":            "⚡",
    "privilege_escalation": "🔺",
    "credential_access":    "🕵️",
    "lateral_movement":     "🕸️",
    "exfiltration":         "📤",
    "defense_evasion":      "🧹",
    "persistence":          "💾",
    "report":               "📊",
}


# ─────────────────────────────────────────────────────────────────────────────
# Types de messages WS
# ─────────────────────────────────────────────────────────────────────────────

class WSMessageType:
    CONNECTED = "connected"
    REPLAY_START = "replay_start"
    REPLAY_END = "replay_end"
    SIM_STATUS = "sim_status"
    SIM_READY = "sim_ready"
    STEP_START = "step_start"
    STEP_PROGRESS = "step_progress"
    STEP_SUCCESS = "step_success"
    STEP_RESULT = "step_result"
    STEP_END = "step_end"
    LLM_SUGGEST = "llm_suggest"
    LLM_REVIEW = "llm_review"
    SIM_STATE = "sim_state"
    SIM_FINISHED = "sim_finished"
    STEP_ERROR = "step_error"
    STEP_CANCELLED = "step_cancelled"
    STEP_RETRY = "step_retry"
    ERROR = "error"
    EXECUTE_ACTION = "execute_action"
    REQUEST_LLM_SUGGEST = "request_llm_suggest"
    REQUEST_LLM_REVIEW = "request_llm_review"
    GET_STATE = "get_state"
    FINISH = "finish"


# ─────────────────────────────────────────────────────────────────────────────
# Affichage Rich — amélioré
# ─────────────────────────────────────────────────────────────────────────────

def _banner():
    console.print()
    console.print(Panel.fit(
        Text("🛡  ShieldAI — Simulateur Interactif Web", justify="center", style="bold cyan"),
        border_style="cyan",
        padding=(1, 4),
    ))
    console.print()


def _section(title: str, style: str = "bold cyan"):
    console.print()
    console.print(f"[{style}]━━━ {title} ━━━[/{style}]")


def _ok(msg: str):   console.print(f"[bold green]✅ {msg}[/bold green]")
def _err(msg: str):  console.print(f"[bold red]❌ {msg}[/bold red]")
def _warn(msg: str): console.print(f"[bold yellow]⚠️  {msg}[/bold yellow]")
def _dim(msg: str):  console.print(f"[dim]{msg}[/dim]")


def _print_json(data: Any, title: str = "📄 Données", max_lines: int = 50) -> None:
    if data is None:
        console.print("[dim]Aucune donnée[/dim]")
        return
    json_str = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    lines = json_str.split("\n")
    if max_lines and len(lines) > max_lines:
        truncated = "\n".join(lines[:max_lines])
        json_str = truncated + f"\n[dim]... {len(lines) - max_lines} lignes tronquées[/dim]"
    syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title=title, border_style="blue"))


def _summarize_params(params: Dict) -> str:
    """Résumé intelligent des params au lieu d'une troncature brutale."""
    if not params:
        return "aucun paramètre"
    parts = []
    for k, v in params.items():
        if isinstance(v, list):
            if len(v) <= 5:
                parts.append(f"{k}: {v}")
            else:
                parts.append(f"{k}: [{len(v)} éléments]")
        elif isinstance(v, dict):
            parts.append(f"{k}: {{{len(v)} clés}}")
        elif isinstance(v, bool):
            parts.append(f"{k}: {'✓' if v else '✗'}")
        elif isinstance(v, (int, float)):
            parts.append(f"{k}: {v}")
        elif isinstance(v, str) and len(v) > 40:
            parts.append(f"{k}: \"{v[:40]}...\"")
        else:
            parts.append(f"{k}: {v}")
    return " | ".join(parts)


def _print_step_start(step: str, params: Dict) -> None:
    icon = ACTION_ICONS.get(step, "▶️")
    style = ACTION_COLORS.get(step, "bold cyan")
    console.print()
    console.print(Panel(
        f"[{style}]{icon} {step}[/{style}]\n"
        f"[dim]{_summarize_params(params)}[/dim]",
        title="Step Start",
        border_style="cyan",
        padding=(1, 2),
    ))


def _print_step_progress(step: str, message: str):
    icon = ACTION_ICONS.get(step, "⏳")
    console.print(f"[yellow]⏳ {icon} {step}[/yellow] — [dim]{message}[/dim]")


def _print_step_success(step: str, message: str, actions_available: List[str]):
    icon = ACTION_ICONS.get(step, "✅")
    _ok(f"{icon} {step} : {message or 'terminé'}")
    if actions_available:
        _print_actions_available(actions_available)


def _print_actions_available(actions: List[str]):
    if not actions:
        return
    colored_actions = []
    for action in actions:
        icon = ACTION_ICONS.get(action, "•")
        style = ACTION_COLORS.get(action, "white")
        colored_actions.append(f"[{style}]{icon} {action}[/{style}]")
    console.print(f"[dim]Actions disponibles :[/dim] " + "  ".join(colored_actions))


def _print_blocked_actions(details: Dict) -> None:
    """Affiche les actions non disponibles avec leur raison."""
    if not details:
        return
    blocked = {k: v for k, v in details.items() if not v.get("available")}
    if not blocked:
        return
    console.print()
    console.print("[dim]── Actions non disponibles ──[/dim]")
    for action, info in blocked.items():
        icon = ACTION_ICONS.get(action, "•")
        console.print(f"  [dim]{icon} {action}[/dim] → [yellow]{info.get('reason', '?')}[/yellow]")


def _print_step_result(step: str, result: Dict, actions_available: List[str]):
    data = result.get("result", result)

    table = Table(
        title=f"Résultat : {ACTION_ICONS.get(step, '✅')} {step}",
        box=box.ROUNDED, border_style="green", show_lines=False, padding=(0, 1),
    )
    table.add_column("Clé", style="bold cyan", min_width=22)
    table.add_column("Valeur", style="white", max_width=70)

    # ── Gestion spécifique par étape ──
    if step == "reconnaissance":
        open_ports = data.get("open_ports", [])
        port_function = data.get("port_function", {})
        table.add_row("Ports ouverts", str(len(open_ports)) + (f" → {open_ports}" if open_ports else ""))
        for func, ports in port_function.items():
            table.add_row(f"  {func.upper()}", str(ports) if ports else "[dim]aucun[/dim]")
        table.add_row("Continue", "✅" if data.get("continue") else "❌")

    elif step == "initial_access":
        credentials = data.get("credentials", {})
        for service in ["ssh", "ftp", "http"]:
            svc_creds = credentials.get(service, {})
            if svc_creds:
                found = 0
                for port, res in svc_creds.items():
                    found += len(res.get("results", {}).get("founds", []))
                table.add_row(f"  {service.upper()}", f"{found} trouvé(s)" if found else "[dim]aucun[/dim]")
            else:
                table.add_row(f"  {service.upper()}", "[dim]non testé[/dim]")
        table.add_row("Continue", "✅" if data.get("continue") else "❌")

    elif step == "execution":
        selected = data.get("selected_cred", {})
        ssh_creds = data.get("ssh_creds", [])
        table.add_row("Cred utilisé", f"{selected.get('username', '?')}@{selected.get('port', '?')}")
        table.add_row("Creds dispo", str(len(ssh_creds)))
        table.add_row("Continue", "✅" if data.get("continue") else "❌")

    elif step == "privilege_escalation":
        sudo = "✅" if data.get("sudo_result", {}).get("results", {}).get("success_number", 0) > 0 else "❌"
        suid = "✅" if data.get("suid_result", {}).get("results", {}).get("success_number", 0) > 0 else "❌"
        table.add_row("Sudo", sudo)
        table.add_row("SUID", suid)
        table.add_row("Privesc", "✅ ROOT" if data.get("privesc_success") else "❌")
        table.add_row("Continue", "✅" if data.get("continue") else "❌")

    elif step == "credential_access":
        keys = len(data.get("usable_keys", []))
        hosts = len(data.get("known_hosts", []))
        hashes = data.get("dump_result", {}).get("results", {}).get("hashes_count", 0)
        hist = data.get("read_result", {}).get("results", {}).get("credentials_count", 0)
        table.add_row("Hashes", str(hashes) if hashes else "[dim]0[/dim]")
        table.add_row("Bash history", str(hist) if hist else "[dim]0[/dim]")
        table.add_row("Clés SSH volées", str(keys) if keys else "[dim]0[/dim]")
        table.add_row("Hosts connus", str(hosts) if hosts else "[dim]0[/dim]")
        table.add_row("Continue", "✅" if data.get("continue") else "❌")

    elif step == "lateral_movement":
        sessions = data.get("sessions", {})
        comp = data.get("lateral_result", {}).get("results", {}).get("compromised_count", len(sessions))
        table.add_row("Hosts compromis", str(comp) if comp else "[dim]0[/dim]")
        if sessions:
            for host, info in list(sessions.items())[:3]:
                if isinstance(info, list):
                    info = info[0] if info else {}
                table.add_row(f"  {host}", f"{info.get('username','?')} ({info.get('auth_method','?')})")
        table.add_row("Continue", "✅" if data.get("continue") else "❌")

    elif step == "exfiltration":
        exfil = data.get("exfil_result", {})
        sent = exfil.get("results", {}).get("sent_count", 0)
        failed = exfil.get("results", {}).get("failed_count", 0)
        table.add_row("Envoyés", str(sent))
        table.add_row("Échecs", str(failed))
        table.add_row("Continue", "✅" if data.get("continue") else "❌")

    elif step == "defense_evasion":
        clean = data.get("clean_result", {}).get("results", {}).get("success_number", 0)
        stomp = data.get("stomp_results", 0)
        table.add_row("Logs nettoyés", str(clean))
        table.add_row("Timestomp", str(stomp))
        table.add_row("Continue", "✅" if data.get("continue") else "❌")

    elif step == "persistence":
        installed = data.get("installed", [])
        table.add_row("Backdoors", ", ".join(installed) if installed else "[dim]aucune[/dim]")
        table.add_row("Continue", "✅" if data.get("continue") else "❌")

    elif step == "report":
        # Rapport final : affichage dédié
        table.add_row("IP cible", data.get("ip", "—"))
        table.add_row("Étapes faites", ", ".join(data.get("done_steps", [])))
        table.add_row("Logs", f"{len(data.get('logs', []))} entrées")
        table.add_row("Début", str(data.get("started_at", ""))[:19])
        table.add_row("Fin", str(data.get("ended_at", ""))[:19])
        console.print(table)
        console.print()
        _print_json(data, "📊 Rapport complet", max_lines=80)
        if actions_available:
            _print_actions_available(actions_available)
        return  # on évite le double affichage générique

    else:
        # Affichage générique
        for k, v in list(data.items())[:5]:
            table.add_row(k, str(v)[:100])

    console.print(table)
    if actions_available:
        _print_actions_available(actions_available)


def _print_sim_state(state: Dict) -> None:
    _section("📊 État de la simulation")
    table = Table(box=box.ROUNDED, border_style="cyan", show_lines=False, padding=(0, 1))
    table.add_column("Catégorie", style="bold cyan", min_width=24)
    table.add_column("Détail", style="white", max_width=80)

    table.add_row("🎯 IP cible", state.get("ip", "—"))
    table.add_row("📅 Démarré", str(state.get("started_at", "—"))[:19])
    table.add_row("✅ Étapes faites", f"{state.get('steps_count', 0)} : {', '.join(state.get('done_steps', []))}")

    # Reconnaissance
    ports = state.get("open_ports", [])
    port_func = state.get("port_function", {})
    if ports:
        table.add_row("🔍 Reconnaissance", f"{state.get('open_ports_count', len(ports))} ports ouverts : {ports}")
        for func, p in port_func.items():
            if p:
                table.add_row(f"  └ {func.upper()}", str(p))
    else:
        table.add_row("🔍 Reconnaissance", "[dim]Non effectuée[/dim]")

    # Initial Access
    ssh_creds = state.get("ssh_creds_found", {})
    total_ssh = state.get("total_ssh_creds", 0)
    if total_ssh:
        creds_summary = ", ".join(f"port {p}: {c} cred(s)" for p, c in ssh_creds.items())
        table.add_row("🔑 Credentials SSH", f"{total_ssh} → {creds_summary}")
    else:
        table.add_row("🔑 Credentials SSH", "[dim]Aucun[/dim]")
    ftp_c = state.get("ftp_creds_count", 0)
    http_c = state.get("http_paths_count", 0)
    if ftp_c or http_c:
        table.add_row("  └ Autres", f"FTP: {ftp_c}, HTTP: {http_c}")

    # Execution
    sel = state.get("selected_cred")
    if sel:
        table.add_row("⚡ Execution", f"{sel.get('username', '?')}@{sel.get('port', '?')} | "
                      f"{state.get('commands_executed', 0)} cmd(s) | "
                      f"RevShell: {'✅' if state.get('reverse_shell_success') else '❌' if state.get('reverse_shell_done') else '—'}")
    else:
        table.add_row("⚡ Execution", "[dim]Non effectuée[/dim]")

    # PrivEsc
    if state.get("privesc_done"):
        sudo = "✅" if state.get("sudo_success") else "❌"
        suid = "✅" if state.get("suid_success") else "❌"
        root = "✅ ROOT OBTENU" if state.get("privesc_success") else "❌ Échec"
        table.add_row("🔺 PrivEsc", f"Sudo: {sudo} | SUID: {suid} → {root}")
    else:
        table.add_row("🔺 PrivEsc", "[dim]Non effectuée[/dim]")

    # Credential Access
    if state.get("credential_access_done"):
        hashes = state.get("hashes_extracted", 0)
        bash = state.get("bash_history_creds", 0)
        keys = state.get("ssh_keys_stolen", 0)
        hosts = state.get("known_hosts_count", 0)
        table.add_row("🕵️ Credential Access", f"Hashes: {hashes} | Bash: {bash} | Clés SSH: {keys} | Hosts connus: {hosts}")
    else:
        table.add_row("🕵️ Credential Access", "[dim]Non effectuée[/dim]")

    # Lateral Movement
    if state.get("lateral_movement_done"):
        comp = state.get("hosts_compromised", 0)
        summary = state.get("compromised_hosts_summary", {})
        detail = ", ".join(f"{h} ({u})" for h, u in list(summary.items())[:3])
        if len(summary) > 3: detail += f" +{len(summary)-3} autres"
        table.add_row("🕸️ Lateral Movement", f"{comp} host(s) : {detail}" if comp else "[dim]Aucun host compromis[/dim]")
    else:
        table.add_row("🕸️ Lateral Movement", "[dim]Non effectué[/dim]")

    # Exfiltration
    if state.get("exfiltration_done"):
        sent = state.get("payloads_sent", 0)
        failed = state.get("payloads_failed", 0)
        table.add_row("📤 Exfiltration", f"{sent} envoyé(s), {failed} échec(s)")
    else:
        table.add_row("📤 Exfiltration", "[dim]Non effectuée[/dim]")

    # Defense Evasion
    if state.get("defense_evasion_done"):
        logs = "✅" if state.get("logs_cleaned") else "❌"
        stomp = "✅" if state.get("timestomp_done") else "—"
        table.add_row("🧹 Defense Evasion", f"Logs: {logs} | Timestomp: {stomp}")
    else:
        table.add_row("🧹 Defense Evasion", "[dim]Non effectuée[/dim]")

    # Persistence
    if state.get("persistence_done"):
        bd = state.get("backdoors_installed", 0)
        ssh_key = "✅" if state.get("ssh_key_installed") else "—"
        cron = "✅" if state.get("cron_installed") else "—"
        table.add_row("💾 Persistence", f"{bd} backdoor(s) : SSH Key: {ssh_key} | Cron: {cron}")
    else:
        table.add_row("💾 Persistence", "[dim]Non effectuée[/dim]")

    console.print(table)

    available = state.get("available_actions", [])
    if available:
        console.print()
        _print_actions_available(available)


def _print_sim_finished(report: Dict) -> None:
    """Affiche l'écran de fin de simulation avec le rapport complet."""
    _section("🏁 Simulation terminée", "bold green")

    table = Table(box=box.ROUNDED, border_style="green", show_lines=False)
    table.add_column("Clé", style="bold cyan", min_width=20)
    table.add_column("Valeur", style="white")
    table.add_row("🎯 IP cible", report.get("ip", "—"))
    table.add_row("✅ Étapes réalisées", ", ".join(report.get("done_steps", [])))
    table.add_row("📝 Logs", f"{len(report.get('logs', []))} entrées")
    table.add_row("📅 Début", str(report.get("started_at", ""))[:19])
    table.add_row("📅 Fin", str(report.get("ended_at", ""))[:19])
    console.print(table)

    console.print()
    _print_json(report, "📊 Rapport complet", max_lines=80)


def _print_llm_suggest(suggestion: str) -> None:
    if not suggestion or suggestion == "Assistant indisponible":
        console.print("[dim]🤖 Aucune suggestion disponible[/dim]")
        return
    console.print(Panel(Text(f"💡 {suggestion}", style="bold green"), title="🤖 Suggestion IA", border_style="green"))


def _print_llm_review(action: str, review: str) -> None:
    console.print(Panel(Text(review, style="white"), title=f"🤖 Avis sur '{action}'", border_style="cyan"))


def _print_error(error: str, error_type: str = None, trace: str = None) -> None:
    error_type_str = f" ({error_type})" if error_type else ""
    console.print(Panel(Text(f"❌ {error}", style="bold red"), title=f"Erreur{error_type_str}", border_style="red"))
    if trace:
        console.print(f"[dim]{trace[:500]}[/dim]")


def _print_help() -> None:
    help_table = Table(title="📚 Commandes disponibles", box=box.ROUNDED, border_style="cyan")
    help_table.add_column("Commande", style="bold cyan", min_width=25)
    help_table.add_column("Description", style="white")
    help_table.add_column("Exemple", style="dim")
    help_table.add_row("list / state", "Afficher l'état complet", "state")
    help_table.add_row("suggest", "Demander une suggestion IA", "suggest")
    help_table.add_row("review <action>", "Demander un avis IA", "review execution")
    help_table.add_row("run <action> [params]", "Exécuter une action", "run reconnaissance port_range: [22,80]")
    help_table.add_row("finish", "Terminer la simulation", "finish")
    help_table.add_row("quit", "Fermer la connexion", "quit")
    help_table.add_row("help / ?", "Cette aide", "help")
    help_table.add_row("clear", "Effacer l'écran", "clear")
    console.print(help_table)

    console.print("\n[bold cyan]Actions disponibles (à utiliser avec 'run') :[/bold cyan]")
    for action in ["reconnaissance", "initial_access", "execution", "privilege_escalation",
                   "credential_access", "lateral_movement", "exfiltration", "defense_evasion",
                   "persistence", "report"]:
        icon = ACTION_ICONS.get(action, "•")
        style = ACTION_COLORS.get(action, "white")
        console.print(f"  [{style}]{icon} {action}[/{style}]")


# ─────────────────────────────────────────────────────────────────────────────
# Traitement des commandes
# ─────────────────────────────────────────────────────────────────────────────

def _parse_json_params(raw: str) -> Dict:
    raw = raw.strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            console.print(f"[red]❌ JSON invalide : {e}[/red]")
            return {}
    try:
        if ":" in raw:
            parts = []
            for part in raw.split(","):
                if ":" in part:
                    k, v = part.split(":", 1)
                    k = k.strip().strip('"\'')
                    v = v.strip()
                    if v.startswith("[") and v.endswith("]"):
                        parts.append(f'"{k}": {v}')
                    elif v.isdigit():
                        parts.append(f'"{k}": {int(v)}')
                    elif v.lower() in ("true", "false"):
                        parts.append(f'"{k}": {v.lower()}')
                    elif v.lower() == "null":
                        parts.append(f'"{k}": null')
                    else:
                        parts.append(f'"{k}": "{v}"')
            json_str = "{" + ", ".join(parts) + "}"
            return json.loads(json_str)
    except Exception:
        pass
    return {}


def parse_command(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    if line in ("help", "?"):
        _print_help()
        return None
    if line == "clear":
        console.clear()
        _banner()
        return None
    if line in ("list", "state"):
        return {"type": WSMessageType.GET_STATE}
    if line == "suggest":
        return {"type": WSMessageType.REQUEST_LLM_SUGGEST}
    if line.startswith("review "):
        action = line[len("review "):].strip()
        if not action:
            console.print("[red]❌ Spécifiez une action à évaluer[/red]")
            return None
        return {"type": WSMessageType.REQUEST_LLM_REVIEW, "action": action}
    if line.startswith("run "):
        rest = line[len("run "):].strip()
        if not rest:
            console.print("[red]❌ Spécifiez une action à exécuter[/red]")
            return None
        first_brace = rest.find("{")
        if first_brace == -1:
            action = rest
            params = {}
        else:
            action = rest[:first_brace].strip()
            raw_params = rest[first_brace:].strip()
            params = _parse_json_params(raw_params)
        if not action:
            console.print("[red]❌ Spécifiez une action à exécuter[/red]")
            return None
        return {"type": WSMessageType.EXECUTE_ACTION, "action": action, "params": params}
    if line == "finish":
        return {"type": WSMessageType.FINISH}
    console.print(f"[red]❌ Commande inconnue : '{line}'[/red]")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Handlers de messages WS
# ─────────────────────────────────────────────────────────────────────────────

def handle_message(msg: Dict) -> bool:
    msg_type = msg.get("type", "?")

    if msg_type == WSMessageType.CONNECTED:
        _ok(f"Connecté — mode={msg.get('mode')}, status={msg.get('status')}")
        _dim(f"Session: {msg.get('session_id')}")
        _dim(f"Étapes déjà faites: {msg.get('actions_done', [])}")

    elif msg_type == WSMessageType.REPLAY_START:
        _dim(f"🔄 Replay de {msg.get('count', 0)} message(s)...")

    elif msg_type == WSMessageType.REPLAY_END:
        _dim("✅ Replay terminé")

    elif msg_type == WSMessageType.SIM_READY:
        _ok(f"Simulation prête — IP: {msg.get('ip', '?')}")
        state = msg.get("state_summary", {})
        if state:
            _print_sim_state(state)
        else:
            actions = msg.get("actions_available", [])
            _print_actions_available(actions)

    elif msg_type == WSMessageType.STEP_START:
        _print_step_start(msg.get("step", "?"), msg.get("params", {}))

    elif msg_type == WSMessageType.STEP_PROGRESS:
        _print_step_progress(msg.get("step", "?"), msg.get("message", ""))

    elif msg_type == WSMessageType.STEP_SUCCESS:
        _print_step_success(msg.get("step", "?"), msg.get("message", ""), msg.get("actions_available", []))

    elif msg_type == WSMessageType.STEP_RESULT:
        _print_step_result(msg.get("step", "?"), msg.get("result", {}), msg.get("actions_available", []))
        details = msg.get("actions_details")
        if details:
            _print_blocked_actions(details)

    elif msg_type == WSMessageType.STEP_END:
        _dim(f"🏁 {msg.get('step', '?')} terminé")

    elif msg_type == WSMessageType.STEP_ERROR:
        _print_error(msg.get("error", "Erreur inconnue"), msg.get("error_type"), msg.get("trace", ""))

    elif msg_type == WSMessageType.STEP_CANCELLED:
        _warn(f"⏹️ {msg.get('step', '?')} annulé")

    elif msg_type == WSMessageType.LLM_SUGGEST:
        _print_llm_suggest(msg.get("suggestion", ""))

    elif msg_type == WSMessageType.LLM_REVIEW:
        _print_llm_review(msg.get("action", "?"), msg.get("review", ""))

    elif msg_type == WSMessageType.SIM_STATE:
        _print_sim_state(msg.get("state", {}))
        details = msg.get("state", {}).get("available_actions_with_details")
        if details:
            _print_blocked_actions(details)

    elif msg_type == WSMessageType.SIM_FINISHED:
        _print_sim_finished(msg.get("report", {}))
        return True

    elif msg_type == WSMessageType.ERROR:
        _print_error(msg.get("message", "Erreur inconnue"))
        return True

    elif msg_type == WSMessageType.SIM_STATUS:
        status = msg.get("status", "?")
        status_colors = {
            "starting": "yellow", "running": "green", "waiting": "cyan",
            "completed": "green", "stopped": "yellow", "failed": "red",
        }
        color = status_colors.get(status, "white")
        _dim(f"[{color}]📊 Status : {status}[/{color}] — {msg.get('message', '')}")

    else:
        _dim(f"📨 [{msg_type}] {json.dumps(msg, ensure_ascii=False, default=str)[:200]}")

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Async IO
# ─────────────────────────────────────────────────────────────────────────────

async def read_stdin_line() -> str:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, input, ">>> ")


async def listen_ws(ws) -> bool:
    try:
        async for raw in ws:
            # console.print(f"[dim]Raw: {raw[:700]}...[/dim]")
            try:
                msg = await asyncio.to_thread(json.loads, raw)
            except json.JSONDecodeError as e:
                console.print(f"[red]❌ Erreur JSON: {e}[/red]")
                continue
            try:
                if (await asyncio.to_thread(handle_message, msg)):
                    return True
            except Exception:
                console.print("[red]❌ Erreur dans handle_message :[/red]")
                console.print(f"[dim]{traceback.format_exc()}[/dim]")
    except websockets.exceptions.ConnectionClosed:
        console.print("\n[red]❌ Connexion WS fermée[/red]")
        return True
    except Exception:
        console.print("[red]❌ Erreur fatale dans listen_ws :[/red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return True
    return False


async def login(client: httpx.AsyncClient, username: str, password: str) -> str:
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("🔐 Connexion...", total=None)
        r = await client.post("/auth/login", json={"username": username, "password": password})
        progress.remove_task(task)
    r.raise_for_status()
    data = r.json()
    if not data.get("success") or not data.get("token"):
        raise RuntimeError(f"Login échoué : {data}")
    _ok("Connexion réussie")
    return data["token"]


async def start_interactive_sim(client: httpx.AsyncClient, headers: Dict, image: str, use_llm: bool = False) -> str:
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("🚀 Démarrage simulation...", total=None)
        r = await client.post("/sim/start", headers=headers, json={
            "image": image, "mode": "interactive", "use_llm": use_llm,
            "authorize_network": False, "network_caps": False,
            "only_listening": True,
            "default_services": {"http": [8080, 8000, 9000], "ssh": [22, 25], "ftp": [21, 33]}
        })
        progress.remove_task(task)
    r.raise_for_status()
    data = r.json()
    session_id = data.get("session_id")
    if not session_id:
        raise RuntimeError(f"Pas de session_id : {data}")
    _ok(f"Simulation démarrée — {session_id}")
    return session_id


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000/api")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--image", required=True, help="Image Docker à utiliser")
    parser.add_argument("--session-id", default=None, help="Reconnecte à une sim existante")
    parser.add_argument("--use-llm", action="store_true", help="Active le LLM")
    args = parser.parse_args()

    ws_base_url = args.base_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws"
    _banner()

    async with httpx.AsyncClient(base_url=args.base_url, timeout=60.0) as client:
        try:
            token = await login(client, args.username, args.password)
            headers = {"Authorization": f"Bearer {token}"}

            if args.session_id:
                session_id = args.session_id
                _dim(f"Reconnexion à : {session_id}")
            else:
                session_id = await start_interactive_sim(client, headers, args.image, args.use_llm)

            url = f"{ws_base_url}/{session_id}?token={token}"
            _dim(f"Connexion WS : {url}")

            _print_help()

            async with websockets.connect(url, max_size=None) as ws:
                listener = asyncio.create_task(listen_ws(ws))

                try:
                    while True:
                        line = await read_stdin_line()
                        if line.strip() == "quit":
                            break
                        msg = parse_command(line)
                        if msg is None:
                            continue
                        try:
                            await ws.send(json.dumps(msg))
                        except websockets.exceptions.ConnectionClosed:
                            console.print("[red]❌ Connexion WS fermée[/red]")
                            break
                        if msg.get("type") == WSMessageType.FINISH:
                            _dim("⏳ Attente de la fin de la simulation...")
                            await asyncio.sleep(3)
                            break
                except (KeyboardInterrupt, EOFError):
                    console.print("\n[yellow]⏹️ Interruption[/yellow]")
                finally:
                    listener.cancel()
                    try:
                        await listener
                    except asyncio.CancelledError:
                        pass

            _dim("Connexion fermée")

        except httpx.HTTPStatusError as e:
            _err(f"Erreur HTTP {e.response.status_code}")
            console.print(f"[dim]{e.response.text[:500]}[/dim]")
            return 1
        except Exception as e:
            _err(f"Erreur : {e}")
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))