import { useState, useEffect } from 'react';
import axios from 'axios';
import s from '@/styles/Login.module.css';

const API = process.env.NEXT_PUBLIC_API_URL || 'https://cyberguard-backend-qqb4.onrender.com';

export default function LoginScreen({ onLogin }) {
  const [isRegisterMode, setIsRegisterMode] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Check if system has no users yet (force register mode)
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const { data } = await axios.get(`${API}/auth/status`);
        if (!data.has_users) {
          setIsRegisterMode(true);
        }
      } catch (err) {
        console.error("Auth status check failed:", err);
      }
    };
    checkStatus();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isRegisterMode) {
        // Register the first user
        await axios.post(`${API}/auth/register`, { username, password });
        // Auto-login after register
        const { data } = await axios.post(`${API}/auth/login`, { username, password });
        onLogin(data.token, data.username);
      } else {
        // Standard login
        const { data } = await axios.post(`${API}/auth/login`, { username, password });
        onLogin(data.token, data.username);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Authentication failed. Server unreachable.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={s.container}>
      {/* Cyberpunk Grid Background */}
      <div className={s.gridBg}></div>
      <div className={s.scanline}></div>

      <div className={s.loginCard}>
        <div className={s.glowingBorder}></div>
        
        <div className={s.header}>
          <div className={s.logo}>
            <span className={s.logoIcon}>🛡️</span>
            <span className={s.logoText}>CYBERGUARD<span className={s.accent}>_AI</span></span>
          </div>
          <p className={s.subtitle}>
            {isRegisterMode ? 'INITIALIZE SYSTEM ADMIN' : 'AUTHORIZED ACCESS REQUIRED'}
          </p>
        </div>

        {error && <div className={s.errorMessage}>{error}</div>}

        <form onSubmit={handleSubmit} className={s.form}>
          <div className={s.inputGroup}>
            <label className={s.label}>USERNAME_</label>
            <input
              type="text"
              className={s.input}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="operator_01"
              required
              autoFocus
            />
          </div>

          <div className={s.inputGroup}>
            <label className={s.label}>PASSWORD_</label>
            <input
              type="password"
              className={s.input}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />
          </div>

          <button type="submit" className={s.submitBtn} disabled={loading}>
            {loading ? 'AUTHENTICATING...' : (isRegisterMode ? 'INITIALIZE SYSTEM' : 'ACCESS TERMINAL')}
          </button>
        </form>
        
        <div className={s.footer}>
          Secure connection established on port 5000.
        </div>
      </div>
    </div>
  );
}
