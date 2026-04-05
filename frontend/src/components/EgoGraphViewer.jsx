import React, { useState, useEffect, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { transformGraphData } from '../utils/graphTransform';

export default function EgoGraphViewer({ graphJson }) {
  const containerRef = useRef(null);
  const [width, setWidth] = useState(800);
  const [hoveredNode, setHoveredNode] = useState(null);

  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      if (entries[0]) {
        setWidth(entries[0].contentRect.width);
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  const graphData = transformGraphData(graphJson);

  const nodeColor = (node) => {
    switch (node.type) {
      case 'candidate': return '#4FC3F7';
      case 'ip': return '#FF9800';
      case 'ca': return '#9C27B0';
      case 'nameserver':
      case 'registrar': return '#00BCD4';
      case 'asn': return '#4CAF50';
      case 'san_sibling': return '#FFEB3B';
      case 'known_malicious': return '#F44336';
      default: return '#8B949E';
    }
  };

  const nodeVal = (node) => {
    if (node.type === 'candidate') return 12;
    if (node.type === 'known_malicious') return 8;
    return 4;
  };

  const linkColor = (link) => {
    switch (link.edge_type) {
      case 'infrastructure': return '#FF9800';
      case 'certificate': return '#9C27B0';
      case 'certificate_sibling': return '#FFEB3B';
      case 'ownership': return '#00BCD4';
      case 'routing': return '#4CAF50';
      default: return '#8B949E';
    }
  };

  if (!graphData.nodes || graphData.nodes.length === 0) {
    return (
      <div className="relative rounded-lg overflow-hidden border border-tgis-border bg-tgis-panel h-[420px] flex items-center justify-center text-tgis-text">
        Graph data unavailable — check backend connectivity.
      </div>
    );
  }

  return (
    <div ref={containerRef} className="relative rounded-lg overflow-hidden border border-tgis-border bg-tgis-panel h-[420px]">
      <ForceGraph2D
        width={width}
        height={420}
        graphData={graphData}
        nodeColor={nodeColor}
        nodeVal={nodeVal}
        linkColor={linkColor}
        linkDirectionalArrowLength={4}
        linkDirectionalArrowRelPos={1}
        backgroundColor="#0D1117"
        onNodeHover={setHoveredNode}
      />

      {hoveredNode && (
        <div className="absolute top-2 left-2 bg-tgis-bg border border-tgis-border p-2 rounded shadow-md text-sm pointer-events-none z-10 text-tgis-text">
          <p><strong>ID:</strong> {hoveredNode.id}</p>
          <p><strong>Type:</strong> {hoveredNode.type}</p>
          {hoveredNode.threat_score !== undefined && (
            <p className="text-tgis-suspicious">Threat score: {hoveredNode.threat_score.toFixed(2)}</p>
          )}
        </div>
      )}

      <div className="absolute bottom-2 left-2 bg-tgis-bg border border-tgis-border p-2 rounded shadow-md text-xs pointer-events-none z-10 grid grid-cols-2 gap-2">
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-[#4FC3F7]" /> <span className="text-tgis-text">candidate</span></div>
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-[#FF9800]" /> <span className="text-tgis-text">ip</span></div>
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-[#9C27B0]" /> <span className="text-tgis-text">ca</span></div>
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-[#00BCD4]" /> <span className="text-tgis-text">nameserver / registrar</span></div>
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-[#4CAF50]" /> <span className="text-tgis-text">asn</span></div>
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-[#FFEB3B]" /> <span className="text-tgis-text">san_sibling</span></div>
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-[#F44336]" /> <span className="text-tgis-text">known_malicious</span></div>
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-[#8B949E]" /> <span className="text-tgis-text">default</span></div>
      </div>
    </div>
  );
}
