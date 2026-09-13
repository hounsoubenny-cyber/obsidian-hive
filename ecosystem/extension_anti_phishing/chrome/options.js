async function load() {
    const { extensionToken, settings } = await chrome.storage.local.get(['extensionToken', 'settings']);
    document.getElementById('token').value = extensionToken || '';
    const s = { checkOnLoad: true, checkOnHover: true, ...(settings || {}) };
    document.getElementById('checkOnLoad').checked = s.checkOnLoad;
    document.getElementById('checkOnHover').checked = s.checkOnHover;
}

async function save() {
    const token = document.getElementById('token').value.trim();
    const settings = {
        checkOnLoad: document.getElementById('checkOnLoad').checked,
        checkOnHover: document.getElementById('checkOnHover').checked,
    };
    await chrome.storage.local.set({ extensionToken: token, settings });

    const status = document.getElementById('saveStatus');
    status.textContent = 'Enregistré ✅';
    setTimeout(() => { status.textContent = ''; }, 2000);
}

document.getElementById('save').addEventListener('click', save);
load();
