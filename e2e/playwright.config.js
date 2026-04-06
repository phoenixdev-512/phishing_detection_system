import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
    testDir: './e2e/tests',
    timeout: 30000,
    retries: 1,
    use: {
        baseURL: 'http://localhost:8000',
        screenshot: 'only-on-failure',
        video: 'off',
    },
    projects: [
        { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
        { name: 'firefox',  use: { ...devices['Desktop Firefox'] } },
    ],
    webServer: {
        command: 'echo "Start backend manually with: uvicorn app.main:app --port 8000"',
        url: 'http://localhost:8000/api/v1/health',
        reuseExistingServer: true,
    },
});