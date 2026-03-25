import { useEffect, useState, useCallback, useRef } from 'react';
import axios from 'axios';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, PieChart, Pie, Cell,
} from 'recharts';
import s from '@/styles/Dashboard.module.css';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:5000';

const LEVEL_COLORS = {
  CRITICAL: '#ff4757',
  HIGH: '#ff8c42',
  MEDIUM: '#ffc312',
  NORMAL: '#2ed573',
};

const PIE_COLORS = ['#ff4757', '#ff8c42', '#ffc312', '#2ed573'];

// ── Custom Tooltip ──────────────────────────────────────
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: '#111631', border: '1px solid #1c2245', borderRadius: 8,
      padding: '8px 12px', fontSize: 12,
    }}>
      <p style={{ color: '#8b92b0', marginBottom: 4 }}>{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color, fontWeight: 600 }}>
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
}

// ── Main Dashboard ──────────────────────────────────────
export default function Dashboard() {
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [filter, setFilter] = useState('ALL');
  const [alert, setAlert] = useState('');
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [isPaused, setIsPaused] = useState(false);
  const pollRef = useRef(null);

  const fetchData = useCallback(async () => {
    try {
      const [threatRes, statsRes] = await Promise.all([
        axios.get(`${API}/threats`, { params: { limit: 80 }, timeout: 5000 }),
        axios.get(`${API}/stats`, { timeout: 5000 }),
      ]);

      setThreats(threatRes.data);
      setStats(statsRes.data);
      setConnected(true);
      setLoading(false);

      // Build timeline data from stats
      if (statsRes.data.timeline && statsRes.data.timeline.length > 0) {
        setTimeline(statsRes.data.timeline.map(t => ({
          time: t.minute,
          total: t.count,
          critical: t.critical || 0,
          high: t.high || 0,
        })));
      } else {
        // Fallback: accumulate from polls
        setTimeline(prev => {
          const now = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
          const critCount = threatRes.data.filter(t => t.threat_level === 'CRITICAL').length;
          const highCount = threatRes.data.filter(t => t.threat_level === 'HIGH').length;
          const next = [...prev, { time: now, critical: critCount, high: highCount, total: threatRes.data.length }];
          return next.slice(-25);
        });
      }
    } catch (err) {
      setConnected(false);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isPaused) {
      if (pollRef.current) clearInterval(pollRef.current);
      return;
    }
    fetchData();
    pollRef.current = setInterval(fetchData, 4000);
    return () => clearInterval(pollRef.current);
  }, [fetchData, isPaused]);

  const blockIP = async (ip) => {
    try {
      await axios.post(`${API}/block`, { ip });
      setAlert(`Blocked IP: ${ip}`);
      setTimeout(() => setAlert(''), 4000);
      fetchData();
    } catch { /* ignore */ }
  };

  const resetData = async () => {
    try {
      await axios.post(`${API}/reset`);
      setThreats([]);
      setTimeline([]);
      setFilter('ALL');
      setAlert('All threat logs and counters have been reset');
      setTimeout(() => setAlert(''), 4000);
      // Let the natural poll refresh data on the next cycle or manually refresh
      fetchData();
    } catch { /* ignore */ }
  };

  // ── Derived Data ────────────────────────────────────
  const filtered = filter === 'ALL'
    ? threats
    : threats.filter(t => t.threat_level === filter);

  const pieData = stats ? [
    { name: 'Critical', value: stats.critical_threats || 0 },
    { name: 'High', value: stats.high_threats || 0 },
    { name: 'Medium', value: stats.medium_threats || 0 },
    { name: 'Normal', value: stats.normal_packets || 0 },
  ].filter(d => d.value > 0) : [];

  const topAttackers = stats?.top_attackers?.slice(0, 6) || [];
  const maxAttackerCount = topAttackers.length > 0
    ? Math.max(...topAttackers.map(a => a.count)) : 1;

  // ── Render ──────────────────────────────────────────
  return (
    <div className={s.wrapper}>
      {/* Header */}
      <header className={s.header}>
        <div className={s.brand}>
          <div className={s.logo}>🛡️</div>
          <div className={s.brandText}>
            <h1>CyberGuard - AI</h1>
            <p>Real-Time Network Threat Intelligence</p>
          </div>
        </div>
        <div className={s.headerRight}>
          <div style={{ display: 'flex', gap: '8px', marginRight: '8px' }}>
            <button 
              className={s.filterBtn} 
              onClick={() => setIsPaused(!isPaused)} 
              style={{ borderColor: isPaused ? '#ffc312' : '#2ed573', color: isPaused ? '#ffc312' : '#2ed573', height: '28px', display: 'flex', alignItems: 'center' }}
            >
              {isPaused ? '▶ Resume' : '⏸ Pause'}
            </button>
            <button 
              className={s.filterBtn} 
              onClick={resetData} 
              style={{ borderColor: '#ff4757', color: '#ff4757', height: '28px', display: 'flex', alignItems: 'center' }}
            >
              ↻ Reset Data
            </button>
          </div>
          <span className={s.monitorBadge}>
            {stats?.monitor?.type === 'simulated' ? '◉ Simulation' : '◉ Live Capture'}
          </span>
          <div className={s.statusIndicator}>
            <span className={`${s.statusDot} ${connected ? s.online : s.offline}`} />
            {connected ? 'Backend Online' : 'Disconnected'}
          </div>
        </div>
      </header>

      {/* Alert Banner */}
      {alert && (
        <div className={s.alertBanner}>
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 3a1 1 0 011 1v4a1 1 0 01-2 0V5a1 1 0 011-1zm0 8a1 1 0 100-2 1 1 0 000 2z"/>
          </svg>
          {alert}
        </div>
      )}

      {/* Stats Cards */}
      {loading ? (
        <div className={s.statsGrid}>
          {[...Array(5)].map((_, i) => (
            <div key={i} className={`${s.skeleton} ${s.skeletonCard}`} />
          ))}
        </div>
      ) : stats && (
        <div className={s.statsGrid}>
          <div className={`${s.statCard} ${s.total}`}>
            <div className={s.statLabel}>Total Analyzed</div>
            <div className={s.statValue}>
              {(stats.total_packets_analyzed || 0).toLocaleString()}
            </div>
          </div>
          <div className={`${s.statCard} ${s.critical}`}>
            <div className={s.statLabel}>Critical</div>
            <div className={s.statValue}>{stats.critical_threats || 0}</div>
          </div>
          <div className={`${s.statCard} ${s.high}`}>
            <div className={s.statLabel}>High</div>
            <div className={s.statValue}>{stats.high_threats || 0}</div>
          </div>
          <div className={`${s.statCard} ${s.medium}`}>
            <div className={s.statLabel}>Medium</div>
            <div className={s.statValue}>{stats.medium_threats || 0}</div>
          </div>
          <div className={`${s.statCard} ${s.blocked}`}>
            <div className={s.statLabel}>Blocked IPs</div>
            <div className={s.statValue}>{stats.blocked_ips_count || 0}</div>
          </div>
        </div>
      )}

      {/* Charts */}
      <div className={s.chartsGrid}>
        {/* Timeline Chart */}
        <div className={s.chartCard}>
          <div className={s.chartHeader}>
            <span className={s.chartTitle}>Threat Activity Timeline</span>
            <span className={s.chartBadge}>● Live</span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="gradCrit" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ff4757" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#ff4757" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ff8c42" stopOpacity={0.2} />
                  <stop offset="100%" stopColor="#ff8c42" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1c2245" />
              <XAxis dataKey="time" stroke="#555c78" tick={{ fontSize: 10 }} />
              <YAxis stroke="#555c78" tick={{ fontSize: 10 }} />
              <Tooltip content={<ChartTooltip />} />
              <Area type="monotone" dataKey="critical" stroke="#ff4757" strokeWidth={2}
                fill="url(#gradCrit)" name="Critical" />
              <Area type="monotone" dataKey="high" stroke="#ff8c42" strokeWidth={1.5}
                fill="url(#gradHigh)" name="High" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Right: Pie + Top Attackers */}
        <div className={s.chartCard}>
          <div className={s.chartHeader}>
            <span className={s.chartTitle}>Threat Distribution</span>
          </div>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={120}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={30} outerRadius={50}
                  dataKey="value" paddingAngle={3} strokeWidth={0}>
                  {pieData.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{
                  background: '#111631', border: '1px solid #1c2245',
                  borderRadius: 8, fontSize: 12
                }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className={s.emptyState}>No data yet</div>
          )}

          {/* Top Attackers */}
          {topAttackers.length > 0 && (
            <>
              <div className={s.chartTitle} style={{ marginTop: 12, marginBottom: 8 }}>
                Top Attackers
              </div>
              <ul className={s.attackersList}>
                {topAttackers.map((a, i) => (
                  <li key={i} className={s.attackerItem}>
                    <span className={s.attackerIp}>{a.src_ip}</span>
                    <div className={s.attackerBar}>
                      <div className={s.attackerBarFill}
                        style={{ width: `${(a.count / maxAttackerCount) * 100}%` }} />
                    </div>
                    <span className={s.attackerCount}>{a.count}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </div>

      {/* Threat Table */}
      <div className={s.tableCard}>
        <div className={s.tableHeader}>
          <span className={s.tableTitle}>
            Live Threat Log
            {filtered.length > 0 && (
              <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: 8 }}>
                ({filtered.length})
              </span>
            )}
          </span>
          <div className={s.filters}>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'NORMAL'].map(level => (
              <button
                key={level}
                className={`${s.filterBtn} ${filter === level ? s.active : ''}`}
                onClick={() => setFilter(level)}
              >
                {level === 'ALL' ? 'All' : level.charAt(0) + level.slice(1).toLowerCase()}
              </button>
            ))}
          </div>
        </div>

        <div className={s.tableWrap}>
          {filtered.length === 0 ? (
            <div className={s.emptyState}>
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <p>{loading ? 'Loading threat data...' : 'No threats found for this filter'}</p>
            </div>
          ) : (
            <table className={s.table}>
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Port</th>
                  <th>Threat Level</th>
                  <th>Score</th>
                  <th>Time</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 50).map((t, i) => (
                  <tr key={i}>
                    <td className={s.mono}>{t.src_ip}</td>
                    <td className={s.mono}>{t.dst_ip}</td>
                    <td>{t.protocol || 'TCP'}</td>
                    <td>{t.dst_port || '—'}</td>
                    <td>
                      <span className={`${s.badge} ${s[t.threat_level?.toLowerCase()]}`}>
                        {t.threat_level}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600, color: LEVEL_COLORS[t.threat_level] || '#8b92b0' }}>
                      {t.threat_score}%
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                      {t.timestamp ? new Date(t.timestamp).toLocaleTimeString() : '—'}
                    </td>
                    <td>
                      {t.threat_level !== 'NORMAL' && (
                        <button className={s.blockBtn} onClick={() => blockIP(t.src_ip)}>
                          Block
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Footer */}
      <footer className={s.footer}>
        <span>CyberGuard - AI Network Threat Intelligence Platform</span>
        <span className={s.footerVersion}>v1.0.0</span>
      </footer>
    </div>
  );
}
