import React from 'react';
import type { SeverityLevel } from '../types';

interface SeverityBadgeProps {
  severity: SeverityLevel | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const normSev = (severity || 'LOW').toUpperCase() as SeverityLevel;

  return (
    <span
      className={`sev-badge sev-badge-${normSev}`}
      style={{
        fontSize: size === 'sm' ? '0.7rem' : '0.75rem',
        padding: size === 'sm' ? '0.15rem 0.4rem' : '0.25rem 0.55rem',
      }}
    >
      <span>{normSev}</span>
    </span>
  );
};
