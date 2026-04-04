import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Scatter, ComposedChart, ReferenceLine } from 'recharts';

const EDGE_COLORS = {
  infrastructure: '#FF9800',
  certificate: '#9C27B0',
  ownership: '#00BCD4',
  routing: '#4CAF50'
};

const EGD_PARAMS = {
    infrastructure: {alpha: 18.0, beta: 0.045, gamma: 0.5},
    certificate:    {alpha: 6.0,  beta: 0.08,  gamma: 0.0},
    ownership:      {alpha: 4.0,  beta: 0.12,  gamma: 1.0},
    routing:        {alpha: 3.0,  beta: 0.06,  gamma: 0.2},
};

export default function EGDCurveChart({ observedEdges, domainAgeDays }) {
  const age = Math.min(domainAgeDays || 1.0, 90); // default to 1 if missing for display, clamp max
  
  // Generate curve data points
  const data = [];
  for (let x = 0; x <= 90; x += 5) {
    const point = { day: x };
    for (const [type, params] of Object.entries(EGD_PARAMS)) {
      point[type] = params.alpha * (1 - Math.exp(-params.beta * x)) + params.gamma;
    }
    data.push(point);
  }

  // Scatter points for actual observed
  const observedData = [
    { day: age, infrastructure_obs: observedEdges?.infrastructure || 0 },
    { day: age, certificate_obs: observedEdges?.certificate || 0 },
    { day: age, ownership_obs: observedEdges?.ownership || 0 },
    { day: age, routing_obs: observedEdges?.routing || 0 }
  ];

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div style={{ backgroundColor: 'rgba(31, 41, 55, 0.95)', padding: '12px', border: '1px solid #374151', borderRadius: '4px', color: '#fff', fontSize: '12px' }}>
          <p style={{ margin: '0 0 8px 0', fontWeight: 'bold' }}>Day {label}</p>
          {payload.map((entry, index) => {
            // Only process the curve payloads to pair effectively
            if (entry.dataKey.includes('_obs')) return null;
            
            const exp = entry.value;
            const obsKey = `${entry.dataKey}_obs`;
            const obsPayload = payload.find(p => p.dataKey === obsKey);
            
            if (obsPayload) {
              const obs = obsPayload.value || 0;
              const iso = exp > 0 ? Math.max(0, exp - obs) / exp : 0;
              return (
                <div key={index} style={{ color: entry.color, marginBottom: '4px' }}>
                   <strong>{entry.dataKey}:</strong> Expected: {exp.toFixed(1)}, Observed: {obs}, Isolation: {(iso * 100).toFixed(0)}%
                </div>
              );
            }
            
            return (
              <div key={index} style={{ color: entry.color, marginBottom: '4px' }}>
                 <strong>{entry.dataKey}:</strong> Expected: {exp.toFixed(1)}
              </div>
            );
          })}
        </div>
      );
    }
    return null;
  };

  return (
    <div style={{ height: '420px', backgroundColor: '#111827', borderRadius: '12px', border: '1px solid #374151', padding: '16px' }}>
      <h3 style={{ color: '#fff', marginTop: 0, marginBottom: '20px', fontSize: '16px' }}>Expected Graph Density (EGD) Baselining</h3>
      <ResponsiveContainer width="100%" height="85%">
        <ComposedChart data={data} margin={{ top: 5, right: 30, left: 10, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis dataKey="day" stroke="#9ca3af" label={{ value: 'Domain Age (Days)', position: 'insideBottom', fill: '#9ca3af', offset: -5 }} />
          <YAxis stroke="#9ca3af" label={{ value: 'Edge Count', angle: -90, position: 'insideLeft', fill: '#9ca3af' }} />
          <Tooltip content={<CustomTooltip />} />
          <Legend wrapperStyle={{ color: '#9ca3af' }} />
          
          <ReferenceLine x={age} stroke="#ef4444" strokeDasharray="3 3" label={{ position: 'top', value: 'Actual Age', fill: '#ef4444', fontSize: '12px' }} />

          {/* Curves */}
          <Line type="monotone" dataKey="infrastructure" stroke={EDGE_COLORS.infrastructure} dot={false} strokeWidth={2} name="Exp. Infrastructure" />
          <Line type="monotone" dataKey="certificate" stroke={EDGE_COLORS.certificate} dot={false} strokeWidth={2} name="Exp. Certificate" />
          <Line type="monotone" dataKey="ownership" stroke={EDGE_COLORS.ownership} dot={false} strokeWidth={2} name="Exp. Ownership" />
          <Line type="monotone" dataKey="routing" stroke={EDGE_COLORS.routing} dot={false} strokeWidth={2} name="Exp. Routing" />

          {/* Scatter points */}
          <Scatter data={observedData} dataKey="infrastructure_obs" fill={EDGE_COLORS.infrastructure} name="Obs. Infrastructure" />
          <Scatter data={observedData} dataKey="certificate_obs" fill={EDGE_COLORS.certificate} name="Obs. Certificate" />
          <Scatter data={observedData} dataKey="ownership_obs" fill={EDGE_COLORS.ownership} name="Obs. Ownership" />
          <Scatter data={observedData} dataKey="routing_obs" fill={EDGE_COLORS.routing} name="Obs. Routing" />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}
