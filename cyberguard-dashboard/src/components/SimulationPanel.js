import React, { useState } from 'react';
import axios from 'axios';
import s from '../styles/SimulationPanel.module.css';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

export default function SimulationPanel({ onSuccess, onError }) {
  const [attackType, setAttackType] = useState('DDoS');
  const [targetIp, setTargetIp] = useState('192.168.1.100');
  const [isLoading, setIsLoading] = useState(false);

  const handleSimulate = async () => {
    setIsLoading(true);
    try {
      const token = localStorage.getItem('cg_token');
      await axios.post(
        `${API_URL}/simulate-threat`,
        { attack_type: attackType, target_ip: targetIp },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (onSuccess) {
        onSuccess(`Synthetic ${attackType} targeted at ${targetIp} injected.`);
      }
    } catch (err) {
      if (onError) {
        onError(err.response?.data?.error || 'Simulation failed.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className={s.panelCard}>
      <h3 className={s.panelTitle}>
        <span style={{ color: '#ef4444' }}>⚠</span> Threat Simulation Engine
      </h3>
      <p className={s.panelDesc}>
        Inject synthetic malicious traffic into the live analysis queue. 
        Watch the AI models detect, score, and automatically block the attack vector in real-time.
      </p>
      
      <div className={s.controlsGrid}>
        <div className={s.inputGroup}>
          <label className={s.label}>Attack Vector</label>
          <select 
            className={s.select}
            value={attackType}
            onChange={(e) => setAttackType(e.target.value)}
            disabled={isLoading}
          >
            <option value="DDoS">DDoS (SYN Flood)</option>
            <option value="SQL_Injection">SQL Injection</option>
            <option value="Port_Scan">Port Scan (Xmas / Null)</option>
            <option value="Malware_C2">Malware C2 Beacon</option>
          </select>
        </div>

        <div className={s.inputGroup}>
          <label className={s.label}>Target IP</label>
          <input 
            type="text" 
            className={s.input}
            value={targetIp}
            onChange={(e) => setTargetIp(e.target.value)}
            placeholder="e.g. 192.168.1.100"
            disabled={isLoading}
          />
        </div>

        <button 
          className={s.launchBtn} 
          onClick={handleSimulate}
          disabled={isLoading || !targetIp.trim()}
        >
          {isLoading ? (
            <>
              <div className={s.loadingSpinner} />
              Injecting...
            </>
          ) : (
            'Launch Attack'
          )}
        </button>
      </div>
    </div>
  );
}
