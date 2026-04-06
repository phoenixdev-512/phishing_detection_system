import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

const client = axios.create({
    baseURL: BASE_URL,
    timeout: 30000,   // 30 seconds — graph build can take up to 200ms
                      // but WHOIS can spike; give headroom
    headers: {
        'Content-Type': 'application/json',
    },
});

client.interceptors.response.use(
    response => response,
    error => {
        if (error.code === 'ECONNREFUSED' || !error.response) {
            return Promise.reject(
                new Error('Backend unreachable. Is the server running?')
            );
        }
        if (error.response?.status === 429) {
            return Promise.reject(
                new Error('Rate limit exceeded. Wait a moment and try again.')
            );
        }
        if (error.response?.status === 422) {
            return Promise.reject(
                new Error('Invalid URL format. Please enter a complete URL.')
            );
        }
        return Promise.reject(error);
    }
);

export const scanUrl = async (url) => {
    const response = await client.post('/api/v1/scan', { url });
    return response.data;
};

export const getHistory = async (limit = 20) => {
    const response = await client.get(`/api/v1/history?limit=${limit}`);
    return response.data;
};

export const getStats = async () => {
    const response = await client.get('/api/v1/stats');
    return response.data;
};

export const checkHealth = async () => {
    const response = await client.get('/api/v1/health');
    return response.data;
};

export default client;