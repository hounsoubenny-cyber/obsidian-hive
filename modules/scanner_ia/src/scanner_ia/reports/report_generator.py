#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShieldAI — ReportGenerator
Sauvegarde les rapports en JSON / HTML / PDF.
Author : Samuel — ShieldAI
"""

import os
import json
import asyncio
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja2.utils import markupsafe

# from weasyprint import HTML as WH
_dir             = os.path.dirname(os.path.abspath(__file__))
storage_default  = os.path.join(_dir, 'generated')
os.makedirs(storage_default, exist_ok=True)

# ── Filtre tojson pour Chart.js inline ────────────────────────────────────────
def _tojson_filter(value, indent=None):
    """Sérialise value en JSON sûr pour injecter dans <script>."""
    result = json.dumps(value, ensure_ascii=False, indent=indent, default=str)
    result = result.replace('</script>', r'<\/script>')   # sécurité XSS
    return markupsafe.Markup(result)


_THEME_MAP = {
    "dark":  "template_dark.html",
    "light": "template_light.html",
    # Thème unique multi-boutons — utilisé par défaut
    "multi": "template_multi_theme.html",
    "cyber": "template_multi_theme.html",
    "punk":  "template_multi_theme.html",
    "void":  "template_multi_theme.html",
}
_DEFAULT_TEMPLATE = "template_multi_theme.html"
BASEDIR = os.path.dirname(__file__)

class ReportGenerator:
    def __init__(self, storage_dir: str = storage_default, theme: str = "multi"):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

        self.theme         = (theme or "multi").lower()
        template_file      = _THEME_MAP.get(self.theme, _DEFAULT_TEMPLATE)
        template_dir       = os.path.join(BASEDIR, 'templates')

        if not os.path.exists(os.path.join(template_dir, template_file)):
            template_file = _DEFAULT_TEMPLATE
            if not os.path.exists(os.path.join(template_dir, template_file)):
                raise FileNotFoundError(
                    f"Template introuvable : {template_file} dans {template_dir}"
                )

        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"])
        )
        self.env.filters['tojson'] = _tojson_filter   # ← enregistre le filtre
        self.template_file  = template_file

    def save_json(self, data: dict, filename: str = None) -> str:
        json_dir = os.path.join(self.storage_dir, 'JSON')
        os.makedirs(json_dir, exist_ok=True)

        if filename is None:
            filename = f'report_{datetime.now().strftime("%d-%m-%Y_%H-%M-%S")}'
        if not filename.endswith('.json'):
            filename += '.json'

        file_path = os.path.join(json_dir, filename)
        # Filtrer les valeurs non-sérialisables (callables, objets complexes) car il ne sont pas sérialisable
        safe_data = {k: v for k, v in data.items() if not callable(v)}
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(safe_data, f, indent=4, default=str, ensure_ascii=False)
        return file_path

    def save_html(self, data: dict, filename: str = None) -> str:
        html_dir = os.path.join(self.storage_dir, 'HTML')
        os.makedirs(html_dir, exist_ok=True)

        if filename is None:
            filename = f'report_{datetime.now().strftime("%d-%m-%Y_%H-%M-%S")}'
        if not filename.endswith('.html'):
            filename += '.html'

        file_path  = os.path.join(html_dir, filename)
        template   = self.env.get_template(self.template_file)
        html_content = template.render(**data)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return file_path
    
    # async def save_pdf_playwright(self, pdf_filename: str, html_filename: str):
    #     """Génère HTML puis convertit en PDF avec Playwright."""
        
    #     async with async_playwright() as a_playwright:
    #         ...
            
    # def save_pdf(self, data: dict, filename: str = None):
    #     """Génère HTML puis convertit en PDF avec WeasyPrint."""
    #     pdf_dir = os.path.join(self.storage_dir, 'PDF')
    #     os.makedirs(pdf_dir, exist_ok=True)
        
    #     html_path = self.save_html(data, filename)
    #     pdf_path  = html_path.replace('HTML', 'PDF').replace('.html', '.pdf')
    #     asyncio.run(self.save_pdf_play(pdf_path, html_path))
    #     # WH(html_path).write_pdf(pdf_path)
    #     return pdf_path, html_path
    
    async def save_pdf_playwright(self, pdf_path: str, html_path: str):
        """Convertit HTML → PDF avec Playwright + Firefox (support CSS moderne complet)."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            print("⚠️  Playwright non installé. pip install playwright && playwright install chromium")
            return False
    
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page(viewport={'width': 1280, 'height': 720})
    
                # Charger le fichier HTML
                await page.goto(f'file://{os.path.abspath(html_path)}', wait_until='networkidle', timeout=1000000)
    
                await page.wait_for_selector('body', state='attached', timeout=1000000)

                await page.evaluate('document.fonts ? document.fonts.ready : Promise.resolve()')
    
                # Générer le PDF
                await page.pdf(
                    path=pdf_path,
                    format='A4',
                    print_background=True,
                    margin={'top': '10mm', 'bottom': '10mm', 'left': '10mm', 'right': '10mm'}
                )
    
                await browser.close()
    
                if os.path.exists(pdf_path):
                    size_kb = os.path.getsize(pdf_path) / 1024
                    print(f"✅ PDF généré : {pdf_path} ({size_kb:.0f} KB)")
                    return True
                return False
    
        except Exception as e:
            print(f"⚠️  Erreur PDF Playwright : {e}")
            return False
    
    
    def save_pdf(self, data: dict, filename: str = None):
        """Génère HTML puis convertit en PDF avec Playwright + Firefox."""
        pdf_dir = os.path.join(self.storage_dir, 'PDF')
        os.makedirs(pdf_dir, exist_ok=True)
    
        html_path = self.save_html(data, filename)
        pdf_path  = html_path.replace('HTML', 'PDF').replace('.html', '.pdf')
        success = False
        try:
            success = asyncio.run(self.save_pdf_playwright(pdf_path, html_path))
        except Exception:
            loop = asyncio.new_event_loop()
            try:
                success = loop.run_until_complete(self.save_pdf_playwright(pdf_path, html_path))
            finally:
                loop.close()
            
    
        if not success:
            print(f"⚠️  PDF non généré. Rapport HTML disponible : {html_path}")
            return None, html_path
    
        return pdf_path, html_path

    # ── Tout en même temps ─────────────────────────────────────────────────────
    def save_all(self, data: dict, filename: str = None):
        json_path   = self.save_json(data, filename)
        # html_path = self.save_html(data, filename)
        pdf_path, html_path  = self.save_pdf(data, filename)
        return json_path, pdf_path, html_path


# ── Test rapide ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from report_builder import ReportBuilder

    # Données factices pour tester le rendu
    class _Fake:
        def __init__(self, **kw):
            for k, v in kw.items(): setattr(self, k, v)

    from base_class.analyser_helper_base_class import AnalyzerHelperResult
    from base_class.fuzzer_base_class          import FuzzerResult
    from base_class.passive_analyzer_base_class import PassiveAnalyzerResult
    from base_class.code_analyse_base_class     import CodeAnalyzerResult

    ah = AnalyzerHelperResult()
    fr = FuzzerResult()
    fr.stats = {"mock": True, "total_tests": 842, "total_vulns": 3,
                "vuln_count": {"XSS": 2, "SQLi": 1}, "vuln_by_url": {},
                "vulns_url": [], "vuln_rate": 0.035, "success_rate": 0.82}
    fr.elapsed = 0.2

    builder = ReportBuilder()
    data    = builder.build(
        url                    = "https://example.com",
        scan_id                = "test-001",
        date                   = datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
        timings                = {"crawler": 12.3, "passive": 1.2, "code": 0.8, "fuzzer": 0.2, "features": 2.1},
        analyzer_helper_result = ah,
        passive_result         = PassiveAnalyzerResult(),
        code_result            = CodeAnalyzerResult(),
        fuzzer_result          = fr,
        ml_predictions         = {"XSS": 0.92, "SQLi": 0.85, "SSRF": 0.41, "CMDi": 0.12},
        theme                  = "multi",
    )

    gen = ReportGenerator(theme="multi")
    html_path = gen.save_html(data, "test_report")
    gen.save_all(data, "test_report2")
    print(f"✅ HTML généré : {html_path}")
