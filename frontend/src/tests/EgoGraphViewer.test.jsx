import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import EgoGraphViewer from '../components/EgoGraphViewer.jsx';

describe('EgoGraphViewer', () => {
  it('renders placeholder text when graph_json is null or empty', () => {
    render(<EgoGraphViewer graphData={null} />);
    expect(screen.getByText(/Graph data unavailable — check backend connectivity/)).toBeDefined();
  });
});
