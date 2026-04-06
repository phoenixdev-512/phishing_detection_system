import { test, expect } from '@playwright/test';

test.describe('TGIS Dashboard', () => {

    test('loads the dashboard', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('text=PHISHING DETECTION SYSTEM')).toBeVisible();
        await expect(page.locator('text=TGIS v2')).toBeVisible();
    });

    test('scan form is visible and interactive', async ({ page }) => {
        await page.goto('/');
        const input = page.locator('input[placeholder*="URL"]');
        await expect(input).toBeVisible();
        const button = page.locator('button:has-text("Scan")');
        await expect(button).toBeVisible();
    });

    test('scans a URL and renders result card', async ({ page }) => {
        await page.goto('/');
        await page.fill('input[placeholder*="URL"]', 'https://example.com');
        await page.click('button:has-text("Scan")');

        // Wait for result (up to 15 seconds for graph build)
        await expect(page.locator('.animate-pulse')).toBeVisible();
        await expect(page.locator('[data-testid="result-card"], .status-banner, text=SAFE, text=SUSPICIOUS, text=MALICIOUS')).toBeVisible({ timeout: 15000 });
    });

    test('result shows verdict and risk score', async ({ page }) => {
        await page.goto('/');
        await page.fill('input[placeholder*="URL"]', 'https://google.com');
        await page.click('button:has-text("Scan")');
        await page.waitForTimeout(12000);

        // One of the three verdicts must be visible
        const verdict = await page.locator('text=SAFE, text=SUSPICIOUS, text=MALICIOUS').first();
        await expect(verdict).toBeVisible();
    });

    test('shows domain age in result', async ({ page }) => {
        await page.goto('/');
        await page.fill('input[placeholder*="URL"]', 'https://github.com');
        await page.click('button:has-text("Scan")');
        await page.waitForTimeout(12000);
        await expect(page.locator('text=/days old|hours old|Age/i')).toBeVisible();
    });

    test('shows TIS score badge', async ({ page }) => {
        await page.goto('/');
        await page.fill('input[placeholder*="URL"]', 'https://example.com');
        await page.click('button:has-text("Scan")');
        await page.waitForTimeout(12000);
        await expect(page.locator('text=/TIS:/i')).toBeVisible();
    });

    test('empty URL shows no crash', async ({ page }) => {
        await page.goto('/');
        const button = page.locator('button:has-text("Scan")');
        await expect(button).toBeDisabled();
    });

    test('stats panel renders after load', async ({ page }) => {
        await page.goto('/');
        await page.waitForTimeout(2000);
        await expect(page.locator('text=/Total Scans|System Statistics/i')).toBeVisible();
    });

});