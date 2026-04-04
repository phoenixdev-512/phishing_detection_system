import React, { useRef, useEffect, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

const NODE_COLORS = {
  candidate: '#4FC3F7',
  ip: '#FF9800',
  ca: '#9C27B0',
  nameserver: '#00BCD4',
  asn: '#4CAF50',
  san_sibling: '#FFEB3B',
  known_malicious: '#F44336'
};

const EDGE_COLORS = {
  infrastructure: '#FF9800',
  certificate: '#9C27B0',
  ownership: '#00BCD4',
  routing: '#4CAF50',
  certificate_sibling: '#FFEB3B'
};

export default function EgoGraphViewer({ graphData }) {
  const containerRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 800, height: 420 });

  useEffect(() => {
    if (containerRef.current) {
      setDimensions({
        width: containerRef.current.getBoundingClientRect().width,
        height: 420
      });
    }
  }, [containerRef.current]);

  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    return (
      <div style={{ height: '420px', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: '#111827', borderRadius: '12px', border: '1px solid #374151', color: '#9ca3af' }}>
        Graph data unavailable — check backend connectivity.
      </div>
    );
  }

  // Pre-process for links since react-force-graph expects simple source/target
  const formattedData = {
    nodes: graphData.nodes.map(n => ({ ...n })),
    links: graphData.links.map(l => ({ ...l, source: l.source, target: l.target }))
  };

  return (
    <div ref={containerRef} style={{ position: 'relative', height: '420px', backgroundColor: '#111827', borderRadius: '12px', border: '1px solid #374151', overflow: 'hidden' }}>
      <ForceGraph2D
        width={dimensions.width}
        height={dimensions.height}
        graphData={formattedData}
        nodeColor={n => NODE_COLORS[n.type] || '#fff'}
        nodeVal={n => n.type === 'candidate' ? 64 : 16}
        nodeLabel={n => n.domain_creation_date ? `${n.id} (${n.type})\nCreated: ${n.domain_creation_date}` : `${n.id} (${n.type})`}
        linkColor={l => EDGE_COLORS[l.edge_type] || '#555'}
        linkWidth={1.5}
        linkDirectionalArrowLength={3.5}
        linkDirectionalArrowRelPos={1}
      />
      
      {/* Legend */}
      <div style={{ position: 'absolute', bottom: '16px', left: '16px', backgroundColor: 'rgba(17, 24, 39, 0.8)', padding: '12px', borderRadius: '8px', border: '1px solid #374151', fontSize: '12px', color: '#fff' }}>
        <h4 style={{ margin: '0 0 8px 0', fontSize: '13px' }}>Node Types</h4>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <div key={type} style={{ display: 'flex', alignItems: 'center' }}>
              <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: color, marginRight: '6px' }} />
              {type}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
