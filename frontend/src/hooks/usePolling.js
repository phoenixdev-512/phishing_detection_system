import { useState, useEffect, useRef } from 'react';

export const usePolling = (fetchFn, intervalMs = 10000) => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const intervalRef = useRef(null);

    const fetchData = async () => {
        try {
            const result = await fetchFn();
            setData(result);
            setError(null);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
        intervalRef.current = setInterval(fetchData, intervalMs);
        return () => clearInterval(intervalRef.current);
    }, []);

    return { data, loading, error };
};