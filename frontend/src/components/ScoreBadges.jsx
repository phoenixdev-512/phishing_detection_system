import React from 'react';

export default function ScoreBadges({ tisScore, scpScore, scpActivated, residualScore, domainAgeDays }) {
  const getColor = (score) => {
    if (score >= 0.6) return '#ef4444';
    if (score >= 0.3) return '#eab308';
    return '#22c55e';
  };

  const Gauge = ({ label, score, subtext }) => (
    <div style={{ flex: 1, padding: '16px', backgroundColor: '#111827', borderRadius: '12px', border: '1px solid #374151', color: 'white', marginRight: '16px' }}>
      <h4 style={{ margin: '0 0 12px 0', fontSize: '14px', color: '#9ca3af' }}>{label}</h4>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
        <div style={{ width: '100%', backgroundColor: '#374151', height: '8px', borderRadius: '4px', overflow: 'hidden' }}>
           <div data-testid="gauge-fill" style={{ width: `${Math.min(score * 100, 100)}%`, backgroundColor: getColor(score), height: '100%', transition: 'width 0.8s ease-in-out' }} />
        </div>
        <span style={{ marginLeft: '12px', fontWeight: 'bold', whiteSpace: 'nowrap' }}>{score.toFixed(2)} / 1.00</span>
      </div>
      <p style={{ margin: 0, fontSize: '12px', color: '#6b7280' }}>{subtext}</p>
    </div>
  );

  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '24px' }}>
      <Gauge 
        label="Temporal Isolation (TIS)" 
        score={tisScore || 0} 
        subtext={`Domain age: ${domainAgeDays != null ? domainAgeDays.toFixed(1) + ' days' : 'Unknown'}`} 
      />
      <Gauge 
        label="Sibling Contamination (SCP)" 
        score={scpScore || 0} 
        subtext={`SCP activated: ${scpActivated ? 'Yes' : 'No'}`} 
      />
      <Gauge 
        label="Residual Heuristic (R)" 
        score={residualScore || 0} 
        subtext="Legacy heuristics" 
      />
    </div>
  );
}
