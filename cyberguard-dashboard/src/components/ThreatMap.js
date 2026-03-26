import React, { useMemo } from 'react';
import s from '../styles/Dashboard.module.css';

const ThreatMap = ({ blockedIps }) => {
  // Simple projection: Map lat/lon to 800x400 SVG space
  // Lon: -180 to 180 -> 0 to 800
  // Lat: 90 to -90 -> 0 to 400
  const project = (lat, lon) => {
    const x = ((lon + 180) * 800) / 360;
    const y = ((90 - lat) * 400) / 180;
    return { x, y };
  };

  const threatMarkers = useMemo(() => {
    return blockedIps
      .filter(b => b.latitude !== null && b.longitude !== null)
      .map((b, i) => {
        const { x, y } = project(b.latitude, b.longitude);
        return (
          <g key={i} className={s.mapMarker}>
            <circle cx={x} cy={y} r="3" fill="var(--accent-red)" />
            <circle cx={x} cy={y} r="8" fill="var(--accent-red)" opacity="0.2">
              <animate attributeName="r" from="3" to="12" dur="2s" repeatCount="indefinite" />
              <animate attributeName="opacity" from="0.4" to="0" dur="2s" repeatCount="indefinite" />
            </circle>
            <title>{`${b.ip} - ${b.city}, ${b.country}`}</title>
          </g>
        );
      });
  }, [blockedIps]);

  return (
    <div className={s.mapCard}>
      <div className={s.tableHeader}>
        <span className={s.tableTitle}>Global Threat Origin Map</span>
      </div>
      <div className={s.mapWrap}>
        <svg viewBox="0 0 800 400" className={s.worldMap}>
          {/* Simplified World Outlines - Dots/Grid style */}
          <rect width="800" height="400" fill="transparent" />
          
          {/* Background Grid */}
          <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
            <path d="M 20 0 L 0 0 0 20" fill="none" stroke="rgba(59, 130, 246, 0.05)" strokeWidth="0.5"/>
          </pattern>
          <rect width="800" height="400" fill="url(#grid)" />

          {/* Abstract Continents (Slightly simplified for performance/cleanliness) */}
          <g fill="rgba(255, 255, 255, 0.03)" stroke="rgba(59, 130, 246, 0.1)" strokeWidth="0.5">
             {/* North America */}
             <path d="M 100,80 L 150,80 L 220,150 L 180,220 L 100,180 Z" />
             {/* South America */}
             <path d="M 180,230 L 240,230 L 220,350 L 180,350 Z" />
             {/* Europe/Asia */}
             <path d="M 380,80 L 600,80 L 750,150 L 700,250 L 450,250 L 400,150 Z" />
             {/* Africa */}
             <path d="M 380,180 L 450,180 L 480,320 L 420,320 Z" />
             {/* Australia */}
             <path d="M 650,280 L 720,280 L 700,350 L 630,350 Z" />
          </g>

          {/* Threat Markers */}
          {threatMarkers}
        </svg>
      </div>
    </div>
  );
};

export default ThreatMap;
