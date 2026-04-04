import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import ScoreBadges from '../components/ScoreBadges.jsx';

describe('ScoreBadges', () => {
  it('renders correct color class for score below 0.30 (SAFE, Green)', () => {
    render(<ScoreBadges tisScore={0.20} />);
    const gauges = screen.getAllByTestId('gauge-fill');
    // rgba to hex mapping in jsdom can vary, so testing inclusion safely
    expect(gauges[0].style.backgroundColor).toMatch(/(#22c55e|rgb\(34,\s*197,\s*94\))/i);
  });

  it('renders correct color class for score between 0.30-0.59 (SUSPICIOUS, Amber)', () => {
    render(<ScoreBadges scpScore={0.45} />);
    const gauges = screen.getAllByTestId('gauge-fill');
    expect(gauges[1].style.backgroundColor).toMatch(/(#eab308|rgb\(234,\s*179,\s*8\))/i);
  });

  it('renders correct color class for score above 0.60 (MALICIOUS, Red)', () => {
    render(<ScoreBadges residualScore={0.75} />);
    const gauges = screen.getAllByTestId('gauge-fill');
    expect(gauges[2].style.backgroundColor).toMatch(/(#ef4444|rgb\(239,\s*68,\s*68\))/i);
  });
});
