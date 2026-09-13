const API_BASE_URL = 'http://localhost:8000'; // ⚠️ à remplacer par le domaine de prod avant publication
const CHECK_URL_ENDPOINT = `${API_BASE_URL}/api/anti_phishing_extension/check_url`;
const CHECK_URLS_BATCH_ENDPOINT = `${API_BASE_URL}/api/anti_phishing_extension/check_urls_batch`;

const DEFAULT_SETTINGS = { checkOnLoad: true, checkOnHover: true };

// Stats par onglet (nombre de liens analysés / suspects) — en mémoire seulement,
// remises à zéro à chaque navigation ou fermeture d'onglet.
const tabStats = new Map();

async function getToken() {
    const { extensionToken } = await chrome.storage.local.get('extensionToken');
    return extensionToken || null;
}

async function getSettings() {
    const { settings } = await chrome.storage.local.get('settings');
    return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

async function apiFetch(url, body) {
    const token = await getToken();
    if (!token) {
        throw new Error("Aucun token configuré — ouvre les options de l'extension.");
    }

    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
    });

    if (response.status === 401) {
        throw new Error('Token invalide ou révoqué — régénère-le depuis le dashboard.');
    }
    if (!response.ok) {
        throw new Error(`Erreur API (${response.status})`);
    }
    return response.json();
}

async function checkUrl(url) {
    return apiFetch(CHECK_URL_ENDPOINT, {
        url,
        explain: false,
        check_blacklist: true,
        check_right_click: false,
    });
}

async function checkUrlsBatch(urls) {
    return apiFetch(CHECK_URLS_BATCH_ENDPOINT, {
        urls,
        explains: urls.map(() => false),
                    check_blacklists: urls.map(() => true),
                    check_right_clicks: urls.map(() => false),
    });
}

function updateBadgeForTab(tabId, stats) {
    if (!stats || stats.suspicious === 0) {
        chrome.action.setBadgeText({ tabId, text: '' });
        return;
    }
    chrome.action.setBadgeText({ tabId, text: String(stats.suspicious) });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#dc2626' });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    (async () => {
        try {
            switch (message.type) {
                case 'GET_SETTINGS': {
                    sendResponse({ settings: await getSettings() });
                    break;
                }
                case 'CHECK_URL': {
                    const result = await checkUrl(message.url);
                    sendResponse({ result });
                    break;
                }
                case 'CHECK_URLS': {
                    const data = await checkUrlsBatch(message.urls);
                    sendResponse({ results: data.results || data });
                    break;
                }
                case 'REPORT_TAB_STATS': {
                    const tabId = sender.tab && sender.tab.id;
                    if (tabId !== undefined) {
                        tabStats.set(tabId, message.stats);
                        updateBadgeForTab(tabId, message.stats);
                    }
                    sendResponse({ ok: true });
                    break;
                }
                case 'GET_TAB_STATS': {
                    sendResponse({ stats: tabStats.get(message.tabId) || null });
                    break;
                }
                default:
                    sendResponse({ error: 'Type de message inconnu' });
            }
        } catch (e) {
            sendResponse({ error: e.message || String(e) });
        }
    })();
    return true; // obligatoire : indique à Chrome qu'une réponse ASYNCHRONE va arriver
});

chrome.tabs.onRemoved.addListener((tabId) => {
    tabStats.delete(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading') {
        tabStats.delete(tabId); // nouvelle page → on oublie les anciennes stats
        chrome.action.setBadgeText({ tabId, text: '' });
    }
});
