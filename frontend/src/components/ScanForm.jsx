import React, { useState } from 'react';

export default function ScanForm({ onScan, loading }) {
  const [url, setUrl] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url) onScan(url);
  };

  return (
    <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '16px', marginBottom: '32px' }}>
      <input
        type="url"
        required
        placeholder="Enter URL to analyze (e.g. https://example.com/login)"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        style={{ flex: 1, padding: '16px', borderRadius: '8px', border: '1px solid #374151', backgroundColor: '#1f2937', color: 'white', fontSize: '16px', outline: 'none' }}
        disabled={loading}
      />
      <button 
        type="submit" 
        disabled={loading || !url}
        style={{ padding: '0 32px', borderRadius: '8px', backgroundColor: '#3b82f6', color: 'white', border: 'none', fontSize: '16px', fontWeight: 'bold', cursor: loading ? 'not-allowed' : 'pointer', opacity: loading ? 0.7 : 1, transition: 'background-color 0.2s' }}
      >
        {loading ? 'Analyzing Graph...' : 'Analyze Domain'}
      </button>
    </form>
  );
}
