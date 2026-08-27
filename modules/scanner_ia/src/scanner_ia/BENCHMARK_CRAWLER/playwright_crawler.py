#!/usr/bin/env python3
"""
Crawler Playwright — exécute le JS, découvre les routes SPA.
"""

import asyncio
from urllib.parse import urlparse, urljoin
from playwright.async_api import async_playwright


class PlaywrightCrawler:
    def __init__(self, base_url: str, max_pages: int = 50):
        self.base_url   = base_url.rstrip("/")
        self.max_pages  = max_pages
        self.visited    = set()
        self.found_urls = set()
        self.found_forms= []
        self.found_apis = []

    def _same_domain(self, url: str) -> bool:
        base = urlparse(self.base_url)
        target = urlparse(url)
        return base.netloc == target.netloc

    async def _crawl_page(self, page, url: str):
        if url in self.visited or len(self.visited) >= self.max_pages:
            return
        self.visited.add(url)

        try:
            # Intercepter les requêtes XHR/fetch
            api_calls = []
            page.on("request", lambda req: api_calls.append(req.url)
                    if req.resource_type in ("fetch", "xhr") else None)

            await page.goto(url, wait_until="networkidle", timeout=10000)
            await page.wait_for_timeout(1000)  # attendre le JS

            # Collecter tous les liens <a href>
            links = await page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.href)"
            )
            for link in links:
                normalized = link.split("?")[0].split("#")[0].rstrip("/")
                if self._same_domain(normalized) and normalized not in self.visited:
                    self.found_urls.add(normalized)

            # Collecter les formulaires
            forms = await page.eval_on_selector_all(
                "form",
                """forms => forms.map(f => ({
                    action: f.action,
                    method: f.method || 'GET',
                    inputs: Array.from(f.querySelectorAll('input,select,textarea'))
                              .map(i => ({name: i.name, type: i.type}))
                }))"""
            )
            for form in forms:
                if form not in self.found_forms:
                    self.found_forms.append(form)

            # Collecter les API calls
            for api in api_calls:
                if api not in self.found_apis:
                    self.found_apis.append(api)

            # Cliquer sur les liens JS (onclick) pour découvrir routes cachées
            await page.eval_on_selector_all(
                "[onclick], [data-route], [data-href]",
                "els => els.map(e => e.getAttribute('onclick') || e.getAttribute('data-route') || '')"
            )

        except Exception:
            pass

    async def crawl(self) -> dict:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page    = await browser.new_page()

            # Queue de crawl
            queue = [self.base_url]
            self.found_urls.add(self.base_url)

            while queue and len(self.visited) < self.max_pages:
                url = queue.pop(0)
                await self._crawl_page(page, url)

                # Ajouter les nouvelles URLs découvertes
                for new_url in self.found_urls - self.visited:
                    if new_url not in queue:
                        queue.append(new_url)

            await browser.close()

        return {
            "visited":    sorted(self.visited),
            "found_urls": sorted(self.found_urls),
            "forms":      self.found_forms,
            "api_calls":  self.found_apis,
        }


if __name__ == "__main__":
    async def main():
        crawler = PlaywrightCrawler("http://localhost:5000")
        result  = await crawler.crawl()
        print(f"\n🎭 Playwright — {len(result['visited'])} pages visitées")
        for url in sorted(result["visited"]):
            print(f"  ✓ {url}")
        print(f"\n🔗 URLs découvertes : {len(result['found_urls'])}")
        for url in sorted(result["found_urls"]):
            print(f"  → {url}")
        print(f"\n📋 Formulaires : {len(result['forms'])}")
        for f in result["forms"]:
            print(f"  → {f['method'].upper()} {f['action']}")
            for inp in f["inputs"]:
                print(f"      [{inp['type']}] {inp['name']}")
        print(f"\n🌐 API calls détectés : {len(result['api_calls'])}")
        for api in result["api_calls"]:
            print(f"  → {api}")
    asyncio.run(main())
