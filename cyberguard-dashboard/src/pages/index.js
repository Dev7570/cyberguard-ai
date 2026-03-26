import { useEffect, useState, useCallback, useRef } from 'react';
import axios from 'axios';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, PieChart, Pie, Cell,
} from 'recharts';
import s from '@/styles/Dashboard.module.css';
import ThreatMap from '../components/ThreatMap';
import LoginScreen from '../components/LoginScreen';
import SimulationPanel from '../components/SimulationPanel';

const API = 'https://cyberguard-backend-qqb4.onrender.com';

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
  const [token, setToken] = useState(null);
  const [user, setUser] = useState(null);

  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState(null);
  const [blockedIps, setBlockedIps] = useState([]);
  const [blockedCountries, setBlockedCountries] = useState([]);
  const [newCountryCode, setNewCountryCode] = useState('');
  const [newCountryName, setNewCountryName] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [analyticsData, setAnalyticsData] = useState(null);
  const [isTestLoading, setIsTestLoading] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [timeline, setTimeline] = useState([]);
  const [filter, setFilter] = useState('ALL');
  const [alert, setAlert] = useState('');
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [isPaused, setIsPaused] = useState(false);
  const pollRef = useRef(null);

  const getAuthHeaders = useCallback(() => ({
    headers: { Authorization: `Bearer ${token}` }
  }), [token]);

  const showAlert = useCallback((message) => {
    setAlert(message);
    setTimeout(() => setAlert(''), 4000);
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const authHeader = getAuthHeaders();
      
      const [healthRes, statsRes, threatsRes, blockedIpsRes, blockedCountriesRes, settingsRes, analyticsRes] = await Promise.all([
        axios.get(`${API}/health`),
        axios.get(`${API}/stats`, authHeader),
        axios.get(`${API}/threats?limit=${filter === 'ALL' ? 100 : 50}${filter !== 'ALL' ? `&level=${filter}` : ''}`),
        axios.get(`${API}/blocked`, authHeader).catch(() => ({ data: [] })),
        axios.get(`${API}/countries/blocked`, authHeader).catch(() => ({ data: [] })),
        axios.get(`${API}/settings`, authHeader).catch(() => ({ data: {} })),
        axios.get(`${API}/threats/summary`).catch(() => ({ data: null }))
      ]);

      setConnected(healthRes.status === 200);
      setStats(statsRes.data);
      setThreats(threatsRes.data);
      setBlockedIps(blockedIpsRes.data || []);
      setBlockedCountries(blockedCountriesRes.data);
      setWebhookUrl(settingsRes.data.webhook_url || '');
      setAnalyticsData(analyticsRes.data);

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
          const critCount = threatsRes.data.filter(t => t.threat_level === 'CRITICAL').length;
          const highCount = threatsRes.data.filter(t => t.threat_level === 'HIGH').length;
          const next = [...prev, { time: now, critical: critCount, high: highCount, total: threatsRes.data.length }];
          return next.slice(-25);
        });
      }
    } catch (err) {
      console.error("Failed to fetch data:", err);
      setConnected(false);
    } finally {
      setLoading(false);
    }
  }, [filter, getAuthHeaders]);

  useEffect(() => {
    // Check local storage for auth token
    const storedToken = localStorage.getItem('cyberguard_token');
    const storedUser = localStorage.getItem('cyberguard_user');
    if (storedToken && storedUser) {
      setToken(storedToken);
      setUser(storedUser);
    } else {
      setLoading(false); // Stop loading if no token
    }
  }, []);

  useEffect(() => {
    if (!token) return;
    
    fetchData();
    const analyticsInterval = setInterval(fetchData, 30000); // Use fetchData for analytics too
    return () => clearInterval(analyticsInterval);
  }, [token, fetchData]);

  useEffect(() => {
    if (!token) return; // Only poll if authenticated
    if (isPaused) {
      if (pollRef.current) clearInterval(pollRef.current);
      return;
    }
    fetchData();
    pollRef.current = setInterval(fetchData, 4000);
    return () => clearInterval(pollRef.current);
  }, [fetchData, isPaused, token]);

  // ── Handlers ──────────────────────────────────────────
  const handleLogin = (jwt, username) => {
    localStorage.setItem('cyberguard_token', jwt);
    localStorage.setItem('cyberguard_user', username);
    setToken(jwt);
    setUser(username);
    setLoading(true); // Restart loading for dashboard
  };

  const handleLogout = () => {
    localStorage.removeItem('cyberguard_token');
    localStorage.removeItem('cyberguard_user');
    setToken(null);
    setUser(null);
    setLoading(false); // Ensure loading is false after logout
  };

  const handleBlock = async (ip) => {
    try {
      await axios.post(`${API}/block`, { ip, reason: 'Manual block from dashboard' }, getAuthHeaders());
      showAlert(`Blocked IP: ${ip}`);
      fetchData();
    } catch (err) { showAlert(err.response?.data?.error || 'Failed to block IP'); }
  };

  const handleUnblock = async (ip) => {
    try {
      await axios.post(`${API}/unblock`, { ip }, getAuthHeaders());
      showAlert(`Unblocked IP: ${ip}`);
      fetchData();
    } catch (err) { showAlert('Failed to unblock IP'); }
  };

  const toggleMonitorMode = async () => {
    try {
      const currentMode = stats?.monitor?.type === 'simulated';
      await axios.post(`${API}/settings`, { simulation_mode: !currentMode }, getAuthHeaders());
      showAlert(`Switching to ${!currentMode ? 'Simulation' : 'Live Capture'} mode...`);
      fetchData();
    } catch (err) { showAlert('Failed to toggle monitor mode.'); }
  };

  const handleUpdateSettings = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API}/settings`, { webhook_url: webhookUrl }, getAuthHeaders());
      showAlert('Settings saved successfully!');
    } catch (err) {
      showAlert('Failed to save settings.');
    }
  };

  const handleTestWebhook = async () => {
    if (!webhookUrl) return showAlert('Please enter a webhook URL first');
    setIsTestLoading(true);
    try {
      await axios.post(`${API}/test-webhook`, {}, getAuthHeaders());
      showAlert('Test webhook sent! Check your channel.');
    } catch (err) {
      showAlert('Failed to send test webhook. Check the URL and server logs.');
    } finally {
      setIsTestLoading(false);
    }
  };

  const handleBlockCountry = async () => {
    if (!newCountryCode) return;
    try {
      await axios.post(`${API}/countries/block`, {
        country_code: newCountryCode.toUpperCase(),
        country_name: newCountryName || newCountryCode.toUpperCase()
      }, getAuthHeaders());
      showAlert(`Country blocked: ${newCountryName || newCountryCode}`);
      setNewCountryCode('');
      setNewCountryName('');
      fetchData();
    } catch (err) { showAlert(err.response?.data?.error || 'Failed to block country'); }
  };

  const handleUnblockCountry = async (code) => {
    try {
      await axios.post(`${API}/countries/unblock`, { country_code: code }, getAuthHeaders());
      showAlert(`Country unblocked: ${code}`);
      fetchData();
    } catch (err) { showAlert('Failed to unblock country'); }
  };

  const resetData = async () => {
    try {
      await axios.post(`${API}/reset`, {}, getAuthHeaders());
      setThreats([]);
      setBlockedIps([]);
      setTimeline([]);
      setFilter('ALL');
      showAlert('All threat logs and counters have been reset');
      fetchData();
    } catch (err) { showAlert('Failed to reset data.'); }
  };

  const handleExport = () => {
    window.location.href = `${API}/threats/export?hours=24`;
  };

  if (!token) {
    if (loading) return <div className={s.loading}>Initializing Authentication...</div>;
    return <LoginScreen onLogin={handleLogin} />;
  }

  if (loading) return <div className={s.loading}>Initializing Global Node...</div>;

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
          <div className={`${s.monitorToggle} ${stats?.monitor?.type === 'simulated' ? '' : s.liveActive}`} onClick={toggleMonitorMode} title="Click to switch monitor mode">
            {stats?.monitor?.type === 'simulated' ? '◉ Simulation' : '◉ Live Capture'}
          </div>
          <div className={`${s.statusBadge} ${connected ? s.connected : s.disconnected}`}>
            {connected ? '● LIVE' : '○ OFFLINE'}
          </div>
          <div className={s.userBadge}>
            <span role="img" aria-label="user">👤</span> {user}
          </div>
          <button className={s.iconBtn} onClick={() => setIsSettingsOpen(true)} title="Settings">
            ⚙️
          </button>
          <button className={s.logoutBtn} onClick={handleLogout} title="Logout">
            ⏻
          </button>
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

      <ThreatMap blockedIps={blockedIps} />

      {/* Analytics Section */}
      <div className={s.tableCard}>
        <div className={s.tableHeader}>
          <span className={s.tableTitle}>📊 24h Threat Analytics</span>
          <a 
            href={`${API}/threats/export?hours=24`} 
            className={s.exportBtn}
            download
          >
            ⬇ Export CSV
          </a>
        </div>
        <div className={s.analyticsContent}>
          {/* Summary Badges */}
          <div className={s.analyticsBadges}>
            <div className={s.analyticsBadge}>
              <span className={s.badgeValue}>{analyticsData?.total_24h || 0}</span>
              <span className={s.badgeLabel}>Total Packets</span>
            </div>
            <div className={`${s.analyticsBadge} ${s.criticalBadge}`}>
              <span className={s.badgeValue}>{analyticsData?.by_level?.CRITICAL || 0}</span>
              <span className={s.badgeLabel}>Critical</span>
            </div>
            <div className={`${s.analyticsBadge} ${s.highBadge}`}>
              <span className={s.badgeValue}>{analyticsData?.by_level?.HIGH || 0}</span>
              <span className={s.badgeLabel}>High</span>
            </div>
            <div className={`${s.analyticsBadge} ${s.mediumBadge}`}>
              <span className={s.badgeValue}>{analyticsData?.by_level?.MEDIUM || 0}</span>
              <span className={s.badgeLabel}>Medium</span>
            </div>
            <div className={`${s.analyticsBadge} ${s.normalBadge}`}>
              <span className={s.badgeValue}>{analyticsData?.by_level?.NORMAL || 0}</span>
              <span className={s.badgeLabel}>Normal</span>
            </div>
          </div>

          {/* Hourly Trend + Top Attacks */}
          <div className={s.analyticsGrid}>
            <div className={s.analyticsChart}>
              <div className={s.chartTitle}>Hourly Threat Volume</div>
              {analyticsData?.hourly_trend?.length > 0 ? (
                <ResponsiveContainer width="100%" height={160}>
                  <AreaChart data={analyticsData.hourly_trend}>
                    <defs>
                      <linearGradient id="colorAnalytics" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1c2245" />
                    <XAxis dataKey="hour" tick={{ fill: '#8b92b0', fontSize: 10 }} />
                    <YAxis tick={{ fill: '#8b92b0', fontSize: 10 }} />
                    <Tooltip content={<ChartTooltip />} />
                    <Area type="monotone" dataKey="total" stroke="#3b82f6" fillOpacity={1} fill="url(#colorAnalytics)" name="Total" />
                    <Area type="monotone" dataKey="critical" stroke="#ff4757" fillOpacity={0} name="Critical" />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className={s.emptyState}>Collecting data...</div>
              )}
            </div>
            <div className={s.topAttacks}>
              <div className={s.chartTitle}>Top Attack Types</div>
              {analyticsData?.top_attacks?.length > 0 ? (
                <ul className={s.attackersList}>
                  {analyticsData.top_attacks.map((a, i) => (
                    <li key={i} className={s.attackerItem}>
                      <span className={s.attackerIp}>{a.attack_type}</span>
                      <span className={s.attackerCount}>{a.count}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className={s.emptyState}>No attacks detected</div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Security Rules - Country Blocking */}
      <div className={s.tableCard}>
        <div className={s.tableHeader}>
          <span className={s.tableTitle}>🌍 Security Rules — Country Blocking</span>
        </div>
        <div className={s.rulesContent}>
          <div className={s.addRuleRow}>
            <input
              type="text"
              className={s.settingsInput}
              placeholder="Country Code (e.g. CN)"
              value={newCountryCode}
              onChange={(e) => setNewCountryCode(e.target.value)}
              maxLength={2}
              style={{ maxWidth: 160 }}
            />
            <input
              type="text"
              className={s.settingsInput}
              placeholder="Country Name (e.g. China)"
              value={newCountryName}
              onChange={(e) => setNewCountryName(e.target.value)}
              style={{ flex: 1 }}
            />
            <button className={s.blockCountryBtn} onClick={handleBlockCountry} disabled={!newCountryCode}>
              Block Country
            </button>
          </div>
          {blockedCountries.length > 0 ? (
            <div className={s.countryBadges}>
              {blockedCountries.map((c) => (
                <div key={c.country_code} className={s.countryBadge}>
                  <span className={s.countryFlag}>{c.country_code}</span>
                  <span className={s.countryName}>{c.country_name}</span>
                  <button className={s.removeCountryBtn} onClick={() => handleUnblockCountry(c.country_code)}>&times;</button>
                </div>
              ))}
            </div>
          ) : (
            <p className={s.helpText} style={{ textAlign: 'center', padding: 16 }}>No country rules active. Add a country code above to auto-block all traffic from that region.</p>
          )}
        </div>
      </div>

      <SimulationPanel onSuccess={showAlert} onError={showAlert} />

      {/* Threat Table */}
      <div className={s.tableCard}>
        <div className={s.tableHeader}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <span className={s.tableTitle}>
              Live Threat Log
              {filtered.length > 0 && (
                <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: 8 }}>
                  ({filtered.length})
                </span>
              )}
            </span>
            <button 
              className={s.filterBtn} 
              style={{ padding: '6px 16px', background: 'var(--surface-bg)' }}
              onClick={() => {
                const token = localStorage.getItem('cyberguard_token');
                window.open(`${API}/threats/report/pdf?token=${token}`, '_blank');
              }}
            >
              <span role="img" aria-label="document">📄</span> Export PDF
            </button>
          </div>
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
                        <button className={s.blockBtn} onClick={() => handleBlock(t.src_ip)}>
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

      {/* Blocked IPs Table */}
      <div className={s.tableCard} style={{ marginTop: '24px' }}>
        <div className={s.tableHeader} style={{ background: 'rgba(255, 71, 87, 0.05)' }}>
          <span className={s.tableTitle} style={{ color: 'var(--accent-red)' }}>
            Blocked Threat Management
            {blockedIps.length > 0 && (
              <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: 8 }}>
                ({blockedIps.length})
              </span>
            )}
          </span>
        </div>

        <div className={s.tableWrap}>
          {blockedIps.length === 0 ? (
            <div className={s.emptyState}>
              <p>No IP addresses currently blocked</p>
            </div>
          ) : (
            <table className={s.table}>
              <thead>
                <tr>
                  <th>Blocked IP</th>
                  <th>Location</th>
                  <th>Reason</th>
                  <th>Blocked At</th>
                  <th>AI Recommendation</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {blockedIps.map((b, i) => {
                  const actionClass = b.ai_insight?.action_suggested?.toLowerCase() || 'neutral';
                  return (
                    <tr key={i}>
                      <td className={s.mono} style={{ color: 'var(--accent-red)' }}>{b.ip}</td>
                      <td>
                        <div className={s.locationCell}>
                          <span className={s.country}>{b.country || 'Unknown'}</span>
                          <span className={s.city}>{b.city || 'Unknown'}</span>
                        </div>
                      </td>
                      <td>{b.reason || 'Manual Block'}</td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                        {b.blocked_at ? new Date(b.blocked_at).toLocaleString() : '—'}
                      </td>
                      <td>
                        {b.ai_insight ? (
                          <div className={s.aiBadge}>
                            <span className={`${s.aiRecText} ${s[actionClass]}`}>
                              {b.ai_insight.recommendation}
                            </span>
                            <p className={s.aiReasoning}>{b.ai_insight.reasoning}</p>
                            <span className={s.aiSub}>
                              Confidence: {(b.ai_insight.confidence * 100).toFixed(0)}% | 
                              Avg Score: {b.ai_insight.avg_threat_score}%
                            </span>
                          </div>
                        ) : (
                          <span className={s.textMuted}>Processing...</span>
                        )}
                      </td>
                      <td>
                        <button className={s.unblockBtn} onClick={() => handleUnblock(b.ip)}>
                          Unblock
                        </button>
                      </td>
                    </tr>
                  );
                })}
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

      {/* Settings Modal */}
      {isSettingsOpen && (
        <div className={s.modalOverlay} onClick={() => setIsSettingsOpen(false)}>
          <div className={s.settingsModal} onClick={e => e.stopPropagation()}>
            <div className={s.modalHeader}>
              <h3>System Settings</h3>
              <button className={s.closeBtn} onClick={() => setIsSettingsOpen(false)}>&times;</button>
            </div>
            <div className={s.modalBody}>
              <div className={s.settingGroup}>
                <label>Discord Webhook URL</label>
                <div className={s.inputRow}>
                  <input 
                    type="text" 
                    className={s.settingsInput}
                    value={webhookUrl} 
                    onChange={(e) => setWebhookUrl(e.target.value)}
                    placeholder="https://discord.com/api/webhooks/..."
                  />
                  <button onClick={handleUpdateSettings} className={s.saveBtn}>Save</button>
                </div>
                <p className={s.helpText}>Notifications will be sent for critical threats and autonomous recovery.</p>
              </div>
              <div className={s.testSection}>
                <button 
                  onClick={handleTestWebhook} 
                  disabled={isTestLoading || !webhookUrl}
                  className={s.testBtn}
                >
                  {isTestLoading ? 'Sending...' : 'Send Test Notification'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
