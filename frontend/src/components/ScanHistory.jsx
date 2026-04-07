import React from 'react';

export default function ScanHistory({ history }) {
  if (!history || !Array.isArray(history) || history.length === 0) {
    return <div className="text-tgis-muted py-4 text-sm">No recent scans available.</div>;
  }

  return (
    <div className="bg-tgis-panel border border-tgis-border rounded overflow-hidden">
      <ul className="divide-y divide-tgis-border">
        {history.map((scan, index) => {
          const score = scan.score || scan.final_score || scan.tgis_score || 0;
          let scoreColor = 'text-green-400 bg-green-500/20';
          if (score >= 70) scoreColor = 'text-red-400 bg-red-500/20';
          else if (score >= 40) scoreColor = 'text-yellow-400 bg-yellow-500/20';

          return (
            <li key={scan.id || index} className="p-3 hover:bg-black/10 transition-colors">
              <div className="flex justify-between items-center mb-2 gap-4">
                <span 
                  className="text-sm font-medium text-tgis-text truncate flex-1" 
                  title={scan.url}
                >
                  {scan.url || 'Unknown URL'}
                </span>
                <span className={`text-xs px-2 py-1 rounded-full font-bold uppercase tracking-wider ${scoreColor}`}>
                  {score.toFixed(1)} / 100
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-tgis-muted font-mono">
                  {scan.timestamp ? new Date(scan.timestamp).toLocaleString() : 'Unknown Data'}
                </span>
                <span className="text-xs text-tgis-muted uppercase">
                  {scan.status || 'Complete'}
                </span>
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
