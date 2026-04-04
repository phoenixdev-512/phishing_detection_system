import React from 'react';
import ScanForm from './components/ScanForm';
import ScoreBadges from './components/ScoreBadges';
import EgoGraphViewer from './components/EgoGraphViewer';
import EGDCurveChart from './components/EGDCurveChart';
import { useScan } from './hooks/useScan';

export default function App() {
  const { scanUrl, loading, result, error } = useScan();

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#030712', color: '#f9fafb', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      <header style={{ padding: '24px 32px', borderBottom: '1px solid #1f2937', backgroundColor: '#111827' }}>
        <h1 style={{ margin: 0, fontSize: '28px', background: '-webkit-linear-gradient(45deg, #38bdf8, #818cf8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          TGIS Phishing Detection Platform
        </h1>
        <p style={{ margin: '8px 0 0 0', color: '#9ca3af', fontSize: '14px' }}>Temporal Graph Isolation Scoring Architecture v2.0</p>
      </header>

      <main style={{ maxWidth: '1400px', margin: '0 auto', padding: '32px' }}>
        <ScanForm onScan={scanUrl} loading={loading} />

        {error && (
          <div style={{ padding: '16px', backgroundColor: '#7f1d1d', color: '#fca5a5', borderRadius: '8px', marginBottom: '24px', border: '1px solid #991b1b' }}>
            <strong>Pipeline Error:</strong> {error}
          </div>
        )}

        {result && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', animation: 'fadeIn 0.5s ease-out' }}>
            <div style={{ padding: '24px', backgroundColor: '#111827', borderRadius: '12px', border: `2px solid ${result.status === 'safe' ? '#059669' : result.status === 'malicious' ? '#dc2626' : '#d97706'}`, boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)' }}>
               <h2 style={{ margin: '0 0 12px 0', fontSize: '28px', color: result.status === 'safe' ? '#10b981' : result.status === 'malicious' ? '#ef4444' : '#f59e0b' }}>
                 {result.recommendation}
               </h2>
               <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
                 <p style={{ margin: 0, color: '#d1d5db', fontSize: '18px' }}>Compound Risk Score: <strong style={{ color: '#fff', fontSize: '24px' }}>{result.risk_score}</strong> <span style={{ fontSize: '14px', color: '#6b7280' }}>/ 100</span></p>
                 {result.scp_activated && result.siblings && result.siblings.filter(s => s.is_known_malicious).length > 0 && (
                     <div style={{ backgroundColor: '#7f1d1d', color: '#fca5a5', padding: '6px 12px', borderRadius: '16px', fontSize: '14px', fontWeight: 'bold' }}>
                       ⚠️ Sibling Contamination: {result.siblings.filter(s => s.is_known_malicious).length} known malicious neighbors
                     </div>
                 )}
               </div>
            </div>

            <ScoreBadges 
              tisScore={result.tis_score} 
              scpScore={result.scp_score} 
              scpActivated={result.scp_activated} 
              residualScore={result.residual_heuristic} 
              domainAgeDays={result.domain_age_days} 
            />

            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: '24px' }}>
               <div style={{ display: 'flex', flexDirection: 'column' }}>
                 <h3 style={{ color: '#e5e7eb', marginBottom: '12px', fontSize: '18px' }}>Ego-Graph Topology</h3>
                 <EgoGraphViewer graphData={result.graph_json} />
               </div>
               <div style={{ display: 'flex', flexDirection: 'column' }}>
                 <h3 style={{ color: '#e5e7eb', marginBottom: '12px', fontSize: '18px', opacity: 0 }}>EGD Curve</h3>
                 <EGDCurveChart observedEdges={result.graph_summary?.edge_counts} domainAgeDays={result.domain_age_days} />
               </div>
            </div>
            
            {/* Latency Footer */}
            {result.details?.pipeline_timing && (
              <div style={{ marginTop: '16px', fontSize: '12px', color: '#6b7280', display: 'flex', gap: '16px', justifyContent: 'center' }}>
                {Object.entries(result.details.pipeline_timing).map(([key, ms]) => (
                  <span key={key}>{key.replace('stage_', '').replace('_ms', '')}: {ms}ms</span>
                ))}
              </div>
            )}
          </div>
        )}
      </main>
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        body { margin: 0; background-color: #030712; }
      `}} />
    </div>
  );
}
