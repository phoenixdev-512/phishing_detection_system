import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import SiblingTable from '../components/SiblingTable.jsx';

describe('SiblingTable', () => {
  it('shows correct malicious count badge dynamically', () => {
    const mockSiblings = [
      { domain: 'phish1.com', weight: 0.8, is_known_malicious: true },
      { domain: 'safe1.net', weight: 0.2, is_known_malicious: false },
      { domain: 'phish2.org', weight: 0.9, is_known_malicious: true }
    ];

    render(<SiblingTable siblings={mockSiblings} />);
    const badge = screen.getByTestId('malicious-badge');
    expect(badge.textContent).toContain('Malicious Count: 2');
    expect(badge.style.backgroundColor).toBe('rgb(239, 68, 68)'); // red for > 0
  });
});
