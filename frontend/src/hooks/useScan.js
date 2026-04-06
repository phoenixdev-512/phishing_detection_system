import { useState, useCallback } from 'react';
import { scanUrl as clientScanUrl } from '../api/client';

export const useScan = () => {
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const scan = useCallback(async (url) => {
        if (!url || !url.trim()) {
            setError('Please enter a URL to scan.');
            return;
        }
        setLoading(true);
        setError(null);
        setResult(null);
        try {
            const data = await clientScanUrl(url.trim());
            setResult(data);
        } catch (err) {
            setError(err.message || 'Scan failed. Check the backend connection.');
        } finally {
            setLoading(false);
        }
    }, []);

    return { result, loading, error, scan };
};
