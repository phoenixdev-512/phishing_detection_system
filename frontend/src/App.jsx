import React, { useState, useEffect } from 'react';
import { useScan } from './hooks/useScan';
import { usePolling } from './hooks/usePolling';
import { getHistory, getStats, checkHealth } from './api/client';

import ScanForm from './components/ScanForm';
import TGISResultCard from './components/TGISResultCard';
import StatsPanel from './components/StatsPanel';
import ScanHistory from './components/ScanHistory';

export default function App() {
  const { result, loading, error, scan } = useScan();
  const { data: stats } = usePolling(getStats, 10000);
  const { data: history } = usePolling(getHistory, 10000);
  const [backendOnline, setBackendOnline] = useState(null);

  useEffect(() => {
    checkHealth()
      .then(() => setBackendOnline(true))
      .catch(() => setBackendOnline(false));
  }, []);

  return (
    <div className="min-h-screen bg-tgis-bg text-tgis-text font-mono">
      {/* TOP NAV */}
      <nav className="border-b border-tgis-border bg-tgis-panel px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-2xl">??</span>
            <div>
              <h1 className="text-lg font-black text-tgis-text tracking-tight">
                PHISHING DETECTION SYSTEM
              </h1>
              <p className="text-xs text-tgis-muted">
                TGIS v2 · Temporal Graph Isolation Scoring
              </p>
            </div>
          </div>
          {/* Backend status indicator */}
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${
                backendOnline === null ? 'bg-gray-500 animate-pulse'
              : backendOnline        ? 'bg-green-500'
              :                        'bg-red-500'
            }`} />
            <span className="text-xs text-tgis-muted">
              {backendOnline === null ? 'Connecting...'
             : backendOnline        ? 'Backend Online'
             :                        'Backend Offline'}
            </span>
          </div>
        </div>
      </nav>

      {/* MAIN CONTENT */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        {/* SCAN FORM — always visible at top */}
        <div className="mb-8">
          <ScanForm onScan={scan} loading={loading} />
        </div>

        {/* RESULT SECTION */}
        <div className="mb-8">
          <TGISResultCard result={result} loading={loading} error={error} />
        </div>

        {/* BOTTOM STATS AND HISTORY */}
        {(stats || history) && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
              <h2 className="text-sm font-semibold text-tgis-muted mb-3 uppercase tracking-wider">
                System Statistics
              </h2>
              <StatsPanel stats={stats} />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-tgis-muted mb-3 uppercase tracking-wider">
                Recent Scans
              </h2>
              <ScanHistory history={history} />
            </div>
          </div>
        )}
      </main>

      {/* FOOTER */}
      <footer className="border-t border-tgis-border mt-16 py-6 text-center">
        <p className="text-xs text-tgis-muted">
          TGIS · Temporal Graph Isolation Scoring Engine ·
          Infrastructure-based phishing detection
        </p>
      </footer>
    </div>
  );
}
