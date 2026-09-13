async function init() {
    const statusEl = document.getElementById('status');

    const { extensionToken } = await chrome.storage.local.get('extensionToken');
    if (!extensionToken) {
        statusEl.textContent = "Aucun token configuré. Ouvre les options pour en coller un.";
        statusEl.className = 'status off';
        return;
    }

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) {
        statusEl.textContent = "Impossible de lire l'onglet actif.";
        return;
    }

    chrome.runtime.sendMessage({ type: 'GET_TAB_STATS', tabId: tab.id }, (response) => {
        const stats = response && response.stats;
        if (!stats) {
            statusEl.textContent = "Aucune analyse sur cette page pour l'instant.";
            statusEl.className = 'status ok';
            return;
        }
        if (stats.suspicious > 0) {
            statusEl.textContent = `⚠️ ${stats.suspicious} lien(s) suspect(s) sur ${stats.total} analysé(s).`;
            statusEl.className = 'status warn';
        } else {
            statusEl.textContent = `✅ ${stats.total} lien(s) analysé(s), rien de suspect.`;
            statusEl.className = 'status ok';
        }
    });
}

document.getElementById('openOptions').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
});

init();
