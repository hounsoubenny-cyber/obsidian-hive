#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jun 18 16:52:04 2026

@author: hounsousamuel
"""



# ============================================================================
# AFFICHAGE AMÉLIORÉ AVEC FALLBACK (Rich -> Colorama -> Print)
# ============================================================================

_RICH_AVAILABLE = False
_COLORAMA_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    # from rich.tree import Tree
    # from rich import print as rprint
    _RICH_AVAILABLE = True
    _console = Console()
except ImportError:
    Table = None
    pass

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    _COLORAMA_AVAILABLE = True
except ImportError:
    # Classes factices si colorama n'est pas installé
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
        BLACK = ''
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = ''
        RESET_ALL = ''
        DIM = ''


class Display:
    """
    Classe utilitaire pour l'affichage amélioré avec fallback automatique.

    Cette classe détecte automatiquement les bibliothèques disponibles
    (Rich > Colorama > print simple) et utilise la meilleure option.

    Attributes:
        _colorize: Méthode statique pour coloriser le texte
        print_header: Affiche un en-tête formaté
        print_success: Affiche un message de succès (vert)
        print_error: Affiche un message d'erreur (rouge)
        print_warning: Affiche un avertissement (jaune)
        print_info: Affiche une information (bleu)
        print_debug: Affiche un message de débogage (magenta)
        print_result_table: Affiche les résultats d'analyse dans un tableau

    Example:
        >>> Display.print_header("Analyse en cours")
        >>> Display.print_success("URL sûre")
        >>> Display.print_error("Erreur de connexion")
    """

    @staticmethod
    def _colorize(text: str, color: str = "white", bold: bool = False) -> str:
        """
        Colorise un texte si colorama est disponible.

        Args:
            text (str): Texte à coloriser
            color (str): Couleur ('red', 'green', 'yellow', 'blue', etc.)
            bold (bool): Si True, texte en gras

        Returns:
            str: Texte colorisé ou texte brut
        """
        if _COLORAMA_AVAILABLE:
            color_map = {
                "red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
                "blue": Fore.BLUE, "magenta": Fore.MAGENTA, "cyan": Fore.CYAN,
                "white": Fore.WHITE, "black": Fore.BLACK
            }
            prefix = Style.BRIGHT if bold else ""
            return f"{prefix}{color_map.get(color, Fore.WHITE)}{text}{Style.RESET_ALL}"
        return text

    @staticmethod
    def print_header(text: str) -> None:
        """
        Affiche un en-tête formaté.

        Args:
            text (str): Texte de l'en-tête
        """
        if _RICH_AVAILABLE:
            _console.print(Panel(text, style="bold cyan", width=70))
        else:
            print("=" * 70)
            print(Display._colorize(f"  {text}", "cyan", bold=True))
            print("=" * 70)

    @staticmethod
    def print_success(text: str) -> None:
        """
        Affiche un message de succès (vert).

        Args:
            text (str): Message à afficher
        """
        if _RICH_AVAILABLE:
            _console.print(f"✅ [green]{text}[/green]")
        else:
            print(Display._colorize(f"✅ {text}", "green"))

    @staticmethod
    def print_error(text: str) -> None:
        """
        Affiche un message d'erreur (rouge).

        Args:
            text (str): Message d'erreur
        """
        if _RICH_AVAILABLE:
            _console.print(f"❌ [red]{text}[/red]")
        else:
            print(Display._colorize(f"❌ {text}", "red"))

    @staticmethod
    def print_warning(text: str) -> None:
        """
        Affiche un avertissement (jaune).

        Args:
            text (str): Avertissement
        """
        if _RICH_AVAILABLE:
            _console.print(f"⚠️  [yellow]{text}[/yellow]")
        else:
            print(Display._colorize(f"⚠️ {text}", "yellow"))

    @staticmethod
    def print_info(text: str) -> None:
        """
        Affiche une information (bleu).

        Args:
            text (str): Information
        """
        if _RICH_AVAILABLE:
            _console.print(f"ℹ️  [blue]{text}[/blue]")
        else:
            print(Display._colorize(f"ℹ️ {text}", "blue"))

    @staticmethod
    def print_debug(text: str) -> None:
        """
        Affiche un message de débogage (magenta).

        Args:
            text (str): Message de debug
        """
        if _RICH_AVAILABLE:
            _console.print(f"🔍 [magenta]{text}[/magenta]")
        else:
            print(Display._colorize(f"🔍 {text}", "magenta"))

    @staticmethod
    def print_result_table(result: dict) -> None:
        """
        Affiche les résultats d'analyse dans un tableau formaté.

        Args:
            result (dict): Dictionnaire contenant les résultats de predict_url
        """
        decision = result.get('final_decision', 'unknown')
        decision_color = "green" if decision == "safe" else "red" if decision == "phishing" else "yellow"

        if _RICH_AVAILABLE:
            table = Table(title="📊 Résultat de l'analyse", style="cyan")
            table.add_column("Critère", style="bold cyan")
            table.add_column("Valeur", style="white")

            table.add_row("URL", result.get('url', 'N/A')[:80])
            table.add_row("Décision", f"[{decision_color}]{decision.upper()}[/{decision_color}]")
            table.add_row("Confiance", f"{result.get('confidence', 0) * 100:.1f}%")
            table.add_row("Source", result.get('source', 'N/A'))
            table.add_row("Temps", f"{result.get('elapsed', 0):.2f}s")
            table.add_row("Date", result.get('date', 'N/A'))

            _console.print(table)

            # Affichage du breakdown si présent
            breakdown = result.get('breakdown', {})
            if breakdown:
                breakdown_table = Table(title="🔍 Détails de l'analyse", style="yellow")
                breakdown_table.add_column("Métrique", style="bold yellow")
                breakdown_table.add_column("Valeur", style="white")

                for key, value in breakdown.items():
                    if value is not None:
                        key_display = key.replace('_', ' ').title()
                        if isinstance(value, float):
                            value_display = f"{value:.3f}"
                        else:
                            value_display = str(value)
                        breakdown_table.add_row(key_display, value_display)

                _console.print(breakdown_table)

            if result.get('advice'):
                _console.print(Panel(result['advice'], style="italic yellow", title="💡 Conseil"))
        else:
            print("\n" + "=" * 60)
            print(Display._colorize("📊 RÉSULTAT DE L'ANALYSE", "cyan", bold=True))
            print("=" * 60)
            print(f"  URL      : {result.get('url', 'N/A')[:80]}")
            print(f"  Décision : {Display._colorize(decision.upper(), decision_color, bold=True)}")
            print(f"  Confiance: {result.get('confidence', 0) * 100:.1f}%")
            print(f"  Source   : {result.get('source', 'N/A')}")
            print(f"  Temps    : {result.get('elapsed', 0):.2f}s")
            print(f"  Date     : {result.get('date', 'N/A')}")

            breakdown = result.get('breakdown', {})
            if breakdown:
                print("\n" + "-" * 40)
                print(Display._colorize("🔍 DÉTAILS", "yellow", bold=True))
                print("-" * 40)
                for key, value in breakdown.items():
                    if value is not None:
                        key_display = key.replace('_', ' ').title()
                        if isinstance(value, float):
                            value_display = f"{value:.3f}"
                        else:
                            value_display = str(value)
                        print(f"  {key_display}: {value_display}")

            if result.get('advice'):
                print("\n" + "-" * 40)
                print(Display._colorize(f"💡 Conseil: {result['advice']}", "yellow"))
            print("=" * 60)
    
    @staticmethod
    def print_result_table_mail(result: dict) -> None:
        """
        Affiche les résultats d'analyse d'email dans un tableau formaté.
        
        Args:
            result (dict): Dictionnaire contenant les résultats de predict_email
        """
        decision = result.get('final_decision', 'unknown')
        decision_color = "green" if decision == "safe" else "red" if decision == "phishing" else "yellow"
        
        if _RICH_AVAILABLE:
            table = Table(title="📧 Résultat de l'analyse email", style="cyan")
            table.add_column("Critère", style="bold cyan")
            table.add_column("Valeur", style="white")
            
            table.add_row("Expéditeur", result.get('sender', 'N/A')[:60])
            table.add_row("Sujet", result.get('subject', 'N/A')[:60])
            table.add_row("Décision", f"[{decision_color}]{decision.upper()}[/{decision_color}]")
            table.add_row("Confiance", f"{result.get('confidence', 0) * 100:.1f}%")
            table.add_row("Source", result.get('source', 'N/A'))
            table.add_row("URLs", f"{result.get('nb_urls_total', 0)} total, {result.get('nb_urls_phishing', 0)} phishing")
            table.add_row("SPF/DKIM", f"{result.get('spf', 'N/A')} / {result.get('dkim', 'N/A')}")
            table.add_row("Temps", f"{result.get('elapsed', 0):.2f}s")
            table.add_row("Date", result.get('date', 'N/A'))
            
            _console.print(table)
            
            if result.get('advice'):
                _console.print(Panel(result['advice'], style="italic yellow", title="💡 Conseil"))
        else:
            print("\n" + "=" * 60)
            print(Display._colorize("📧 RÉSULTAT DE L'ANALYSE EMAIL", "cyan", bold=True))
            print("=" * 60)
            print(f"  Expéditeur : {result.get('sender', 'N/A')[:60]}")
            print(f"  Sujet      : {result.get('subject', 'N/A')[:60]}")
            print(f"  Décision   : {Display._colorize(decision.upper(), decision_color, bold=True)}")
            print(f"  Confiance  : {result.get('confidence', 0) * 100:.1f}%")
            print(f"  Source     : {result.get('source', 'N/A')}")
            print(f"  URLs       : {result.get('nb_urls_total', 0)} total, {result.get('nb_urls_phishing', 0)} phishing")
            print(f"  SPF/DKIM   : {result.get('spf', 'N/A')} / {result.get('dkim', 'N/A')}")
            print(f"  Temps      : {result.get('elapsed', 0):.2f}s")
            print(f"  Date       : {result.get('date', 'N/A')}")
            
            if result.get('advice'):
                print(f"\n  💡 Conseil : {result['advice']}")
            
            print("=" * 60)

