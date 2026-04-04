import React from 'react';

export default function SiblingTable({ siblings }) {
  if (!siblings || siblings.length === 0) {
    return null; // hide if none
  }

  const maliciousCount = siblings.filter(s => s.is_known_malicious).length;

  return (
    <div style={{ backgroundColor: '#111827', borderRadius: '12px', border: '1px solid #374151', padding: '16px', marginTop: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <h3 style={{ margin: 0, color: '#fff', fontSize: '16px' }}>Shared Infrastructure Analysis</h3>
        <span data-testid="malicious-badge" style={{ backgroundColor: maliciousCount > 0 ? '#ef4444' : '#374151', color: '#fff', padding: '4px 8px', borderRadius: '16px', fontSize: '12px', fontWeight: 'bold' }}>
          Malicious Count: {maliciousCount}
        </span>
      </div>
      <table style={{ width: '100%', borderCollapse: 'collapse', color: '#d1d5db', fontSize: '14px' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #374151', textAlign: 'left' }}>
            <th style={{ padding: '8px' }}>Sibling Domain</th>
            <th style={{ padding: '8px' }}>Contamination Weight</th>
            <th style={{ padding: '8px' }}>Status</th>
          </tr>
        </thead>
        <tbody>
          {siblings.map((sib, idx) => (
            <tr key={idx} style={{ borderBottom: '1px solid #1f2937' }}>
              <td style={{ padding: '8px' }}>{sib.domain}</td>
              <td style={{ padding: '8px' }}>{sib.weight.toFixed(2)}</td>
              <td style={{ padding: '8px' }}>
                <span style={{ color: sib.is_known_malicious ? '#ef4444' : '#9ca3af' }}>
                  {sib.is_known_malicious ? 'MALICIOUS' : 'UNKNOWN'}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
