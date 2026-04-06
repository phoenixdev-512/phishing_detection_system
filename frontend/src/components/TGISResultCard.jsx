import React, { useState } from 'react';
import ScoreBadges from './ScoreBadges';
import EgoGraphViewer from './EgoGraphViewer';
import EGDCurveChart from './EGDCurveChart';
import SiblingTable from './SiblingTable';

export default function TGISResultCard({ result, loading, error }) {
  const [reasonsOpen, setReasonsOpen] = useState(true);
  const [statsOpen, setStatsOpen] = useState(false);
  const [feedbackSent, setFeedbackSent] = useState(false);
  const [feedbackError, setFeedbackError] = useState(null);

  const submitFeedback = async (correctedStatus) => {
    try {
      // Create a local axios or native fetch instance if 'client' isn't explicitly defined
      const res = await fetch('/api/v1/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: result.url,
          original_status: result.status,
          corrected_status: correctedStatus,
          analyst_note: ''
        })
      });
      if (!res.ok) throw new Error('Feedback failed');
      setFeedbackSent(true);
      setFeedbackError(null);
    } catch (err) {
      setFeedbackError('Failed to submit feedback.');
    }
  };

  if (loading) {
    return (
      <div className="animate-pulse bg-tgis-panel rounded-xl p-8 border border-tgis-border">
        <div className="h-6 bg-gray-700 rounded w-1/4 mb-4 mx-auto"></div>
        <div className="h-4 bg-gray-700 rounded w-1/2 mb-4 mx-auto"></div>
        <div className="h-4 bg-gray-700 rounded w-3/4 mx-auto"></div>
        <p className="text-center text-tgis-muted mt-8">Analyzing domain infrastructure...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-tgis-panel border-2 border-[#F44336] rounded-xl p-8 text-center">
        <div className="text-5xl mb-4">⚠</div>
        <h2 className="text-2xl font-bold text-white mb-2">Scan Failed</h2>
        <p className="text-tgis-muted mb-4">{error}</p>
        <p className="text-sm text-gray-500">Check that your backend is running at localhost:8000</p>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="text-tgis-muted text-center py-16">
        <div className="text-5xl mb-4">🔍</div>
        <h2 className="text-xl font-semibold text-white mb-2">Enter a URL above to begin infrastructure analysis</h2>
        <p className="max-w-md mx-auto">The TGIS engine will build an ego-graph and compute isolation scores in under 300ms</p>
      </div>
    );
  }

  const statusColor = result.status === 'safe' ? '#4CAF50' : result.status === 'suspicious' ? '#FF9800' : '#F44336';
  const statusLabel = result.status.toUpperCase();
  
  const domain = (() => {
    try {
      return new URL(result.url).hostname;
    } catch {
      return result.url;
    }
  })();

  const ageText = result.domain_age_days !== null
    ? result.domain_age_days < 1
      ? `${Math.round(result.domain_age_days * 24)}h old`
      : `${result.domain_age_days.toFixed(1)} days old`
    : 'Age unknown';

  const tgisScore = result.tgis_score || 0;
  const tisScore = result.tis_score || 0;
  const scpScore = result.scp_score || 0;

  return (
    <div className="flex flex-col w-full max-w-5xl mx-auto animation-fadeIn">
      {/* A. VERDICT BANNER */}
      <div 
        className="rounded-xl p-6 mb-4 border-2" 
        style={{ borderColor: statusColor, backgroundColor: `${statusColor}1A` }}
      >
        <div className="flex justify-between items-center mb-4">
          <div>
            <h2 className="text-4xl font-black" style={{ color: statusColor }}>{statusLabel}</h2>
            <p className="text-tgis-muted mt-1 text-lg">{domain}</p>
          </div>
          <div className="text-right">
            <div className="flex items-baseline justify-end gap-1">
              <span className="text-5xl font-black" style={{ color: statusColor }}>{result.risk_score}</span>
              <span className="text-tgis-muted text-xl">/100</span>
            </div>
            <p className="text-tgis-muted text-sm font-bold tracking-wider mt-1">RISK SCORE</p>
          </div>
        </div>
        
        <div className="w-full h-px mb-4 opacity-30" style={{ backgroundColor: statusColor }}></div>
        
        <div className="flex gap-3">
          <div className="rounded-full px-3 py-1 text-white font-mono text-sm" style={{ backgroundColor: `${statusColor}CC` }}>
            TGIS: {tgisScore.toFixed(3)}
          </div>
          <div className="rounded-full px-3 py-1 text-white font-mono text-sm" style={{ backgroundColor: `${statusColor}CC` }}>
            TIS: {tisScore.toFixed(3)}
          </div>
          <div className="rounded-full px-3 py-1 text-white font-mono text-sm" style={{ backgroundColor: `${statusColor}CC` }}>
            SCP: {scpScore.toFixed(3)}
          </div>
        </div>
      </div>

      {/* B. METADATA ROW */}
      <div className="flex flex-wrap gap-4 mb-4">
        <div className="bg-tgis-panel border border-tgis-border rounded-full px-3 py-1 text-xs text-tgis-muted flex items-center gap-1">
          <span>🕐</span> Domain age: {ageText}
        </div>
        <div className={`border border-tgis-border rounded-full px-3 py-1 text-xs flex items-center gap-1 ${result.scp_activated ? 'bg-amber-900/20 text-amber-500' : 'bg-tgis-panel text-tgis-muted'}`}>
          <span>🔗</span> SCP: {result.scp_activated ? 'Active' : 'Inactive'}
        </div>
        <div className="bg-tgis-panel border border-tgis-border rounded-full px-3 py-1 text-xs text-tgis-muted flex items-center gap-1">
          <span>⚡</span> Pipeline: {result.details?.pipeline_timing?.total_ms ?? '—'}ms
        </div>
        <div className="bg-tgis-panel border border-tgis-border rounded-full px-3 py-1 text-xs text-tgis-muted flex items-center gap-1">
          <span>🛡</span> Source: {result.verdict_source}
        </div>
      </div>

      {/* C. SCORE BADGES */}
      <div className="mb-4">
        <ScoreBadges 
          tisScore={result.tis_score}
          scpScore={result.scp_score}
          scpActivated={result.scp_activated}
          residualScore={result.residual_heuristic}
          domainAgeDays={result.domain_age_days}
        />
      </div>

      {/* D. REASONS LIST */}
      <div className="bg-tgis-panel border border-tgis-border rounded-lg p-4 mb-4">
        <div 
          className="flex justify-between items-center cursor-pointer select-none"
          onClick={() => setReasonsOpen(!reasonsOpen)}
        >
          <h3 className="text-white font-semibold flex items-center gap-2">
            Detection Reasons
          </h3>
          <span className="text-tgis-muted transition-transform duration-200" style={{ transform: reasonsOpen ? 'rotate(180deg)' : 'rotate(0)' }}>▼</span>
        </div>
        
        {reasonsOpen && (
          <div className="mt-4">
            {!result.reasons || result.reasons.length === 0 ? (
              <p className="text-tgis-muted text-sm italic">No specific indicators flagged.</p>
            ) : (
              <ul className="space-y-2">
                {result.reasons.map((reason, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-tgis-text text-sm">
                    <span className="mt-1" style={{ color: statusColor }}>•</span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>

      {/* E. RECOMMENDATION BOX */}
      <div 
        className="rounded-lg p-4 mb-4 flex gap-3 items-start"
        style={{ borderLeft: `4px solid ${statusColor}`, backgroundColor: `${statusColor}0D` }}
      >
        <div className="text-xl mt-0.5">
          {result.status === 'safe' ? '✅' : result.status === 'suspicious' ? '⚠️' : '🚫'}
        </div>
        <p className="text-sm italic text-gray-300 leading-relaxed">
          {result.recommendation}
        </p>
      </div>

      {result.status && (
        <div className="bg-tgis-panel border border-tgis-border rounded-lg p-4 mb-4">
          <p className="text-xs text-tgis-muted uppercase tracking-wider mb-3">
            📝 Analyst Feedback — Was this verdict correct?
          </p>
          {feedbackSent ? (
            <p className="text-green-500 text-sm">✓ Feedback submitted. Thank you.</p>
          ) : (
            <div className="flex gap-2 flex-wrap">
              {['safe', 'suspicious', 'malicious'].map(status => (
                <button
                  key={status}
                  onClick={() => submitFeedback(status)}
                  className={`px-4 py-2 text-xs font-bold uppercase rounded-lg
                    border transition-colors ${
                    result.status === status
                      ? 'opacity-40 cursor-default'
                      : 'hover:opacity-80 cursor-pointer'
                  }`}
                  style={{
                    borderColor: status === 'safe'       ? '#4CAF50'
                               : status === 'suspicious' ? '#FF9800' : '#F44336',
                    color:       status === 'safe'       ? '#4CAF50'
                               : status === 'suspicious' ? '#FF9800' : '#F44336',
                  }}
                  disabled={result.status === status}
                >
                  {status === result.status ? `✓ Marked as ${status}` : `Flag as ${status}`}
                </button>
              ))}
            </div>
          )}
          {feedbackError && (
            <p className="text-red-500 text-xs mt-2">{feedbackError}</p>
          )}
        </div>
      )}

      {/* F. EGO GRAPH */}
      {result.graph_json && (
        <div className="bg-tgis-panel border border-tgis-border rounded-lg p-2 mb-4">
          <h3 className="text-tgis-muted text-sm font-semibold px-2 pt-2 mb-2">Infrastructure Ego-Graph</h3>
          <EgoGraphViewer graphJson={result.graph_json} />
        </div>
      )}

      {/* G. EGD CURVE */}
      {result.graph_summary && (
        <div className="bg-tgis-panel border border-tgis-border rounded-lg p-4 mb-4">
          <h3 className="text-tgis-muted text-sm font-semibold mb-4">Expected vs Observed Edge Density</h3>
          <div className="h-64">
            <EGDCurveChart 
              graphSummary={result.graph_summary}
              domainAgeDays={result.domain_age_days} 
            />
          </div>
        </div>
      )}

      {/* H. SIBLING TABLE */}
      {result.siblings && (
        <div className="bg-tgis-panel border border-tgis-border rounded-lg p-4 mb-4">
          <h3 className="text-tgis-muted text-sm font-semibold mb-4">Sibling Contamination Analysis</h3>
          <SiblingTable 
            siblings={result.siblings}
            scpActivated={result.scp_activated} 
          />
        </div>
      )}

      {/* I. RAW GRAPH STATS */}
      {result.graph_summary && (
        <div className="bg-tgis-panel border border-tgis-border rounded-lg p-4 mb-4">
          <div 
            className="flex justify-between items-center cursor-pointer select-none"
            onClick={() => setStatsOpen(!statsOpen)}
          >
            <h3 className="text-white font-semibold text-sm">Graph Statistics</h3>
            <span className="text-tgis-muted transition-transform duration-200" style={{ transform: statsOpen ? 'rotate(180deg)' : 'rotate(0)' }}>▼</span>
          </div>
          
          {statsOpen && (
            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-tgis-text">
              <div className="bg-gray-800/30 p-3 rounded">
                <p><strong className="text-white">Total Nodes:</strong> {result.graph_summary.total_nodes}</p>
              </div>
              <div className="bg-gray-800/30 p-3 rounded">
                <p><strong className="text-white">Total Edges:</strong> {result.graph_summary.total_edges}</p>
              </div>
              
              <div className="col-span-1 md:col-span-2 mt-2">
                <h4 className="text-xs text-tgis-muted font-bold uppercase mb-2">Edge Type Breakdown</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {Object.entries(result.graph_summary.edge_counts || {}).map(([type, count]) => {
                    const expected = result.graph_summary.expected_edges?.[type] || 0;
                    return (
                      <div key={type} className="flex justify-between items-center border-b border-gray-800 py-1">
                        <span className="capitalize">{type}</span>
                        <span className="font-mono text-xs">
                          <span className="text-white">{count}</span> / <span className="text-tgis-muted">{expected.toFixed(1)}</span>
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}