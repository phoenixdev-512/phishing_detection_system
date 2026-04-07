import React from 'react';

export default function StatsPanel({ stats }) {
  if (!stats) {
    return <div className="text-tgis-muted py-4 text-sm">Loading statistics...</div>;
  }

  return (
    <div className="bg-tgis-panel border border-tgis-border rounded p-4">
      <div className="grid grid-cols-2 gap-4">
        {Object.entries(stats).map(([key, value]) => (
          <div key={key} className="flex flex-col">
            <span className="text-xs text-tgis-muted uppercase tracking-wider">
              {key.replace(/_/g, ' ')}
            </span>
            <span className="text-lg font-bold text-tgis-text mt-1">
              {typeof value === 'number' && !Number.isInteger(value) 
                ? value.toFixed(2) 
                : typeof value === 'object' 
                  ? JSON.stringify(value)
                  : value}
            </span>
          </div>
        ))}
        {Object.keys(stats).length === 0 && (
          <div className="text-tgis-muted text-sm col-span-2">No stats available</div>
        )}
      </div>
    </div>
  );
}
