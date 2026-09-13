(function () {
    const resultsCache = new Map(); // url -> résultat, valable pour la durée de vie de CETTE page
    const pendingChecks = new Set(); // évite de renvoyer 2 requêtes pour le même lien survolé 2 fois vite

    let settings = { checkOnLoad: true, checkOnHover: true };

    function sendMessage(message) {
        return new Promise((resolve, reject) => {
            chrome.runtime.sendMessage(message, (response) => {
                if (chrome.runtime.lastError) {
                    reject(chrome.runtime.lastError);
                    return;
                }
                resolve(response);
            });
        });
    }

    function isRisky(result) {
        if (!result || result.error) return false; // une erreur réseau ne veut pas dire "dangereux"
        const passive = result.passive_pred || {};
        const riskLevel = (passive.risk_level || '').toLowerCase();
        return riskLevel.includes('danger') || riskLevel.includes('suspect') || riskLevel.includes('⚠') || riskLevel.includes('❌');
    }

    function addBadge(anchor) {
        if (anchor.dataset.ohPhishBadge) return; // déjà marqué, on ne double pas
        anchor.dataset.ohPhishBadge = '1';
        const badge = document.createElement('span');
        badge.textContent = ' ⚠️';
        badge.title = 'Lien potentiellement dangereux (Obsidian Hive Anti-Phishing)';
        badge.style.cursor = 'help';
        anchor.appendChild(badge);
    }

    function collectVisibleLinks(limit = 200) {
        const anchors = Array.from(document.querySelectorAll('a[href]'));
        const seen = new Set();
        const list = [];
        for (const a of anchors) {
            const href = a.href;
            if (!href || !href.startsWith('http')) continue; // ignore mailto:, javascript:, ancres...
            if (seen.has(href)) continue;
            seen.add(href);
            list.push({ anchor: a, url: href });
            if (list.length >= limit) break; // sécurité anti-surcharge (page à des milliers de liens)
        }
        return list;
    }

    async function runLoadScan() {
        const links = collectVisibleLinks();
        if (links.length === 0) return;

        const urls = links.map((l) => l.url);
        let response;
        try {
            response = await sendMessage({ type: 'CHECK_URLS', urls });
        } catch (e) {
            return; // token absent/invalide ou API injoignable : on abandonne silencieusement
        }
        if (!response || !response.results) return;

        let suspiciousCount = 0;
        for (const { anchor, url } of links) {
            const result = response.results[url];
            resultsCache.set(url, result);
            if (isRisky(result)) {
                suspiciousCount += 1;
                addBadge(anchor);
            }
        }
        sendMessage({ type: 'REPORT_TAB_STATS', stats: { total: links.length, suspicious: suspiciousCount } }).catch(() => {});
    }

    function buildTooltip(result) {
        const passive = (result && result.passive_pred) || {};
        return `Obsidian Hive Anti-Phishing\n${passive.risk_level || 'Analyse indisponible'}`;
    }

    async function handleHover(anchor) {
        const url = anchor.href;
        if (!url || !url.startsWith('http')) return;

        if (resultsCache.has(url)) {
            anchor.title = buildTooltip(resultsCache.get(url));
            return;
        }
        if (pendingChecks.has(url)) return;
        pendingChecks.add(url);

        try {
            const response = await sendMessage({ type: 'CHECK_URL', url });
            const result = response && response.result;
            resultsCache.set(url, result);
            anchor.title = buildTooltip(result);
            if (isRisky(result)) addBadge(anchor);
        } catch (e) {
            // silencieux : pas de tooltip si l'API est injoignable
        } finally {
            pendingChecks.delete(url);
        }
    }

    function attachHoverListener() {
        document.addEventListener(
            'mouseover',
            (event) => {
                if (!settings.checkOnHover) return;
                const anchor = event.target.closest && event.target.closest('a[href]');
                if (anchor) handleHover(anchor);
            },
            { passive: true }
        );
    }

    async function init() {
        try {
            const stored = await sendMessage({ type: 'GET_SETTINGS' });
            if (stored && stored.settings) settings = stored.settings;
        } catch (e) {
            // on garde les valeurs par défaut définies plus haut
        }

        if (settings.checkOnLoad) runLoadScan();
        attachHoverListener();
    }

    init();
})();
