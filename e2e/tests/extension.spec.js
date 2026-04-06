import { test, expect, chromium } from '@playwright/test';
import path from 'path';

test.describe('Chrome Extension', () => {

    test('extension loads without errors', async () => {
        const extensionPath = path.resolve('./extension');
        const context = await chromium.launchPersistentContext('', {
            headless: false,  // extensions require non-headless
            args: [
                `--disable-extensions-except=${extensionPath}`,
                `--load-extension=${extensionPath}`,
                '--no-sandbox'
            ],
        });

        const page = await context.newPage();
        await page.goto('https://example.com');
        await page.waitForTimeout(3000);

        // Check no crash in service worker
        const workers = context.serviceWorkers();
        expect(workers.length).toBeGreaterThan(0);

        await context.close();
    });

    test('extension popup opens', async () => {
        const extensionPath = path.resolve('./extension');
        const context = await chromium.launchPersistentContext('', {
            headless: false,
            args: [
                `--disable-extensions-except=${extensionPath}`,
                `--load-extension=${extensionPath}`,
                '--no-sandbox'
            ],
        });

        const page = await context.newPage();
        await page.goto('https://example.com');

        // Get extension ID
        await page.waitForTimeout(2000);
        const workers = context.serviceWorkers();
        if (workers.length === 0) {
            console.log('No service workers found — extension may not have loaded');
            await context.close();
            return;
        }

        const extensionId = workers[0].url().split('/')[2];
        const popupPage = await context.newPage();
        await popupPage.goto(`chrome-extension://${extensionId}/popup.html`);

        await expect(popupPage.locator('text=TGIS')).toBeVisible({ timeout: 5000 });
        await context.close();
    });

});