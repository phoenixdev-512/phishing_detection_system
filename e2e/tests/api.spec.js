import { test, expect, request } from '@playwright/test';

test.describe('TGIS API', () => {

    test('health endpoint returns ok', async ({ request }) => {
        const res = await request.get('/api/v1/health');
        expect(res.status()).toBe(200);
        const body = await res.json();
        expect(body.status).toBe('ok');
    });

    test('scan endpoint returns full schema', async ({ request }) => {
        const res = await request.post('/api/v1/scan', {
            data: { url: 'https://example.com' }
        });
        expect(res.status()).toBe(200);
        const body = await res.json();
        expect(body).toHaveProperty('status');
        expect(body).toHaveProperty('risk_score');
        expect(body).toHaveProperty('tgis_score');
        expect(body).toHaveProperty('tis_score');
        expect(body).toHaveProperty('scp_score');
        expect(body).toHaveProperty('domain_age_days');
        expect(body).toHaveProperty('graph_json');
        expect(body).toHaveProperty('siblings');
        expect(body).toHaveProperty('graph_summary');
    });

    test('invalid URL returns 422', async ({ request }) => {
        const res = await request.post('/api/v1/scan', {
            data: { url: 'not-a-url' }
        });
        expect([422, 400]).toContain(res.status());
    });

    test('history endpoint returns array', async ({ request }) => {
        const res = await request.get('/api/v1/history?limit=5');
        expect(res.status()).toBe(200);
        const body = await res.json();
        expect(Array.isArray(body)).toBeTruthy();
    });

    test('stats endpoint returns counters', async ({ request }) => {
        const res = await request.get('/api/v1/stats');
        expect(res.status()).toBe(200);
        const body = await res.json();
        expect(body).toHaveProperty('total_scans');
    });

    test('scan risk_score is int 0-100', async ({ request }) => {
        const res = await request.post('/api/v1/scan', {
            data: { url: 'https://google.com' }
        });
        const body = await res.json();
        expect(typeof body.risk_score).toBe('number');
        expect(body.risk_score).toBeGreaterThanOrEqual(0);
        expect(body.risk_score).toBeLessThanOrEqual(100);
    });

});