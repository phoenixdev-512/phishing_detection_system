// Firefox MV2 background script
// Uses browser.* APIs (chrome.* also available via polyfill in Firefox)

const BACKEND_URL = 'http://localhost:8000';
const SKIP_SCHEMES = [
    'about:', 'moz-extension://', 'chrome://', 'data:', 'file://'
];

async function scanTab(tabId, url) {
    if (!url || SKIP_SCHEMES.some(s => url.startsWith(s))) return;

    try {
        await browser.storage.local.set({
            [`tab_${tabId}`]: { status: 'scanning', url }
        });
        browser.browserAction.setBadgeText({ text: '...', tabId });

        const response = await fetch(`${BACKEND_URL}/api/v1/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const result = await response.json();

        await browser.storage.local.set({ [`tab_${tabId}`]: result });

        const badge = result.status === 'safe' ? 'OK'
                    : result.status === 'suspicious' ? '?!'
                    : '!!';
        browser.browserAction.setBadgeText({ text: badge, tabId });

        if (result.status === 'malicious') {
            browser.tabs.sendMessage(tabId, {
                type: 'SHOW_WARNING', data: result
            }).catch(() => {});
        }
    } catch (err) {
        await browser.storage.local.set({
            [`tab_${tabId}`]: {
                status: 'unavailable',
                risk_score: 0,
                reasons: ['Backend unreachable.'],
                url
            }
        });
        browser.browserAction.setBadgeText({ text: '—', tabId });
    }
}

browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        scanTab(tabId, tab.url);
    }
});

browser.tabs.onActivated.addListener(({ tabId }) => {
    browser.tabs.get(tabId).then(tab => {
        if (tab.url) scanTab(tabId, tab.url);
    });
});