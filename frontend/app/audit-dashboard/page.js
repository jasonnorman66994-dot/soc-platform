"use client";
import { useEffect, useState, useCallback, useMemo } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost/api";
const MAX_THREAT_INDICATORS = 120;
const ANIMATED_THREAT_INDICATORS = 60;

export default function AuditDashboard() {
  const [stats, setStats] = useState(null);
  const [audit, setAudit] = useState(null);
  const [jitStatus, setJitStatus] = useState(null);
  const [threatFeed, setThreatFeed] = useState(null);
  const [agents, setAgents] = useState(null);
  const [drills, setDrills] = useState(null);
  const [highestRisk, setHighestRisk] = useState(null);
  const [emailDrive, setEmailDrive] = useState(null);
  const [nullRouting, setNullRouting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [windowDays, setWindowDays] = useState(30);

  const headers = useCallback(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
    return {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "X-Tenant-ID": typeof window !== "undefined" ? localStorage.getItem("tenant_id") || "default" : "default",
    };
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [stats_result, audit_result, jit_result, threat_result, agents_result, drills_result, risk_result, email_result] = await Promise.allSettled([
        fetch(`${API}/soar/stats?window_days=${windowDays}`, { headers: headers() }),
        fetch(`${API}/soar/audit?window_days=${windowDays}`, { headers: headers() }),
        fetch(`${API}/jit/status`, { headers: headers() }),
        fetch(`${API}/threat-intel/feed`, { headers: headers() }),
        fetch(`${API}/agents/status`, { headers: headers() }),
        fetch(`${API}/drills/history`, { headers: headers() }),
        fetch(`${API}/risk/highest-user`, { headers: headers() }),
        fetch(`${API}/email/drive-status`, { headers: headers() }),
      ]);
      if (stats_result.status === "fulfilled" && stats_result.value.ok) setStats(await stats_result.value.json());
      if (audit_result.status === "fulfilled" && audit_result.value.ok) setAudit(await audit_result.value.json());
      if (jit_result.status === "fulfilled" && jit_result.value.ok) setJitStatus(await jit_result.value.json());
      if (threat_result.status === "fulfilled" && threat_result.value.ok) setThreatFeed(await threat_result.value.json());
      if (agents_result.status === "fulfilled" && agents_result.value.ok) setAgents(await agents_result.value.json());
      if (drills_result.status === "fulfilled" && drills_result.value.ok) setDrills(await drills_result.value.json());
      if (risk_result.status === "fulfilled" && risk_result.value.ok) setHighestRisk(await risk_result.value.json());
      if (email_result.status === "fulfilled" && email_result.value.ok) setEmailDrive(await email_result.value.json());
    } catch (e) {
      console.error("AuditDashboard load error:", e);
    } finally {
      setLoading(false);
    }
  }, [headers, windowDays]);

  useEffect(() => { load(); }, [load]);

  const threat_indicators = (threatFeed?.indicators || []).slice(0, MAX_THREAT_INDICATORS);
  const animate_threat_indicators = threat_indicators.length <= ANIMATED_THREAT_INDICATORS;

  const sovereign_pulse = useMemo(() => {
    const trend = audit?.daily_trend || [];
    if (trend.length < 2) return null;
    const width = 320;
    const height = 72;
    const padding = 8;
    const counts = trend.map(d => d.count);
    const max_count = Math.max(...counts, 1);
    const mean = counts.reduce((s, v) => s + v, 0) / counts.length;
    const variance = counts.reduce((s, v) => s + (v - mean) ** 2, 0) / counts.length;
    const stddev = Math.sqrt(variance) || 1;
    const step = (width - padding * 2) / (trend.length - 1);
    const dots = trend.map((d, i) => {
      const x = padding + step * i;
      const y = height - padding - (d.count / max_count) * (height - padding * 2);
      const z = (d.count - mean) / stddev;
      const color = z > 3 ? "#ef4444" : z > 2 ? "#f59e0b" : "#14b8a6";
      const deviation_pct = mean > 0 ? Math.round(((d.count - mean) / mean) * 100) : 0;
      return { x, y, color, z: Math.round(z * 100) / 100, day: d.day, count: d.count, deviation_pct };
    });
    const path = dots.map((dot, i) => `${i === 0 ? "M" : "L"}${dot.x},${dot.y}`).join(" ");
    const latest = dots[dots.length - 1];
    return { width, height, path, dots, latest_z_score: latest?.z ?? 0, latest_deviation_pct: latest?.deviation_pct ?? 0, mean: Math.round(mean * 10) / 10, stddev: Math.round(stddev * 10) / 10 };
  }, [audit]);

  const email_pulse = useMemo(() => {
    const tlds = emailDrive?.flagged_tlds || [];
    if (!tlds.length) return null;
    const top = tlds[0];
    const width = 320;
    const height = 72;
    const padding = 8;
    const z = top.z_score || 0;
    const points = [
      { x: padding, y: height - padding, label: "baseline" },
      { x: width * 0.3, y: height - padding - 10, label: "rising" },
      { x: width * 0.6, y: height - padding - (z / (z + 2)) * (height - padding * 2), label: "spike" },
      { x: width - padding, y: height - padding - (z / (z + 4)) * (height - padding * 2) * 0.6, label: "current" },
    ];
    const path = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x},${p.y}`).join(" ");
    return { width, height, path, points, top, total_flagged: tlds.length };
  }, [emailDrive]);

  const handleNullRoute = async (tld) => {
    setNullRouting(true);
    try {
      await fetch(`${API}/email/nullroute-tld?tld=${encodeURIComponent(tld)}`, { method: "POST", headers: headers() });
      await load();
    } finally {
      setNullRouting(false);
    }
  };

  const card = { background: "#1e1e2e", borderRadius: 10, padding: 20, marginBottom: 16, border: "1px solid #333" };
  const kpi = { background: "#252540", borderRadius: 8, padding: 16, textAlign: "center", flex: 1, minWidth: 140 };
  const h2 = { color: "#e0e0ff", marginBottom: 12 };
  const label = { color: "#aaa", fontSize: 12, marginBottom: 4 };
  const value = { color: "#fff", fontSize: 28, fontWeight: 700 };
  const row = { display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 16 };
  const btn = { background: "#5b5fc7", color: "#fff", border: "none", borderRadius: 6, padding: "8px 18px", cursor: "pointer", fontWeight: 600 };

  return (
    <main style={{ minHeight: "100vh", background: "#12121a", color: "#e0e0e0", padding: 32, fontFamily: "Inter, system-ui, sans-serif" }}>
      <h1 style={{ color: "#e0e0ff", marginBottom: 8 }}>SOAR Audit Dashboard</h1>
      <p style={{ color: "#888", marginBottom: 24 }}>Operational health, user trends, and JIT session status</p>

      <div style={{ marginBottom: 20, display: "flex", alignItems: "center", gap: 12 }}>
        <label style={{ color: "#aaa" }}>Window (days):</label>
        <input type="number" min={1} max={90} value={windowDays} onChange={e => setWindowDays(Math.max(1, Math.min(90, +e.target.value || 30)))}
          style={{ background: "#1e1e2e", color: "#fff", border: "1px solid #444", borderRadius: 6, padding: "6px 12px", width: 80 }} />
        <button style={btn} onClick={load}>Refresh</button>
      </div>

      {loading && <p style={{ color: "#888" }}>Loading...</p>}

      {/* KPI Cards */}
      {stats && (
        <div style={row}>
          <div style={kpi}><div style={label}>Total Executions</div><div style={value}>{stats.total_executions}</div></div>
          <div style={kpi}><div style={label}>Deflected Threats</div><div style={value}>{stats.total_deflected_threats}</div></div>
          <div style={kpi}><div style={label}>Success Rate</div><div style={value}>{stats.success_rate}%</div></div>
          <div style={kpi}><div style={label}>Monitored Users</div><div style={value}>{stats.active_monitored_users}</div></div>
        </div>
      )}

      {/* Sovereign Pulse — System Health Sparkline */}
      {sovereign_pulse && (
        <div style={{ ...card, border: "1px solid #1e3a5f" }}>
          <h2 style={h2}>Sovereign Pulse</h2>
          <p style={{ color: "#888", fontSize: 12, marginBottom: 8 }}>Visual heartbeat of system health — daily execution deviation from baseline</p>
          <svg viewBox={`0 0 ${sovereign_pulse.width} ${sovereign_pulse.height}`} style={{ width: "100%", height: 88, display: "block" }} role="img" aria-label="Sovereign Pulse sparkline">
            <path d={sovereign_pulse.path} fill="none" stroke="#38bdf8" strokeWidth="3" strokeLinejoin="round" strokeLinecap="round" />
            {sovereign_pulse.dots.map((dot) => (
              <circle key={dot.day} cx={dot.x} cy={dot.y} r={5} fill={dot.color} stroke="#0f172a" strokeWidth="2">
                <title>{dot.day}: {dot.count} events (z={dot.z}, {dot.deviation_pct > 0 ? "+" : ""}{dot.deviation_pct}%)</title>
              </circle>
            ))}
          </svg>
          <div style={{ display: "flex", gap: 12, marginTop: 8, flexWrap: "wrap", alignItems: "center" }}>
            <div style={{ color: sovereign_pulse.latest_z_score > 3 ? "#ef4444" : sovereign_pulse.latest_z_score > 2 ? "#f59e0b" : "#6ee7b7", fontSize: 11 }}>
              Latest z-score: {sovereign_pulse.latest_z_score}
            </div>
            <span style={{ background: "#1e293b", borderRadius: 12, padding: "2px 10px", fontSize: 11, color: "#94a3b8" }}>
              Mean: {sovereign_pulse.mean}
            </span>
            <span style={{ background: "#1e293b", borderRadius: 12, padding: "2px 10px", fontSize: 11, color: "#94a3b8" }}>
              Stddev: {sovereign_pulse.stddev}
            </span>
            <span style={{
              background: Math.abs(sovereign_pulse.latest_deviation_pct) > 50 ? "#7f1d1d" : Math.abs(sovereign_pulse.latest_deviation_pct) > 25 ? "#78350f" : "#14532d",
              borderRadius: 12, padding: "2px 10px", fontSize: 11, fontWeight: 600,
              color: Math.abs(sovereign_pulse.latest_deviation_pct) > 50 ? "#fca5a5" : Math.abs(sovereign_pulse.latest_deviation_pct) > 25 ? "#fde68a" : "#86efac",
            }}>
              Baseline Deviation: {sovereign_pulse.latest_deviation_pct > 0 ? "+" : ""}{sovereign_pulse.latest_deviation_pct}%
            </span>
          </div>
        </div>
      )}

      {/* Email Infiltration — Electric Purple Pulse */}
      {email_pulse && (
        <div style={{ ...card, border: "1px solid #7c3aed" }}>
          <h2 style={{ color: "#c4b5fd", marginBottom: 12 }}>Email Infiltration</h2>
          <p style={{ color: "#888", fontSize: 12, marginBottom: 8 }}>
            Link-density spike from <strong style={{ color: "#a78bfa" }}>{email_pulse.top.tld}</strong> — z-score {email_pulse.top.z_score} (&gt;3.5σ threshold)
          </p>
          <svg viewBox={`0 0 ${email_pulse.width} ${email_pulse.height}`} style={{ width: "100%", height: 88, display: "block" }} role="img" aria-label="Email Infiltration sparkline">
            <path d={email_pulse.path} fill="none" stroke="#a855f7" strokeWidth="3" strokeLinejoin="round" strokeLinecap="round" />
            {email_pulse.points.map((pt) => (
              <circle key={pt.label} cx={pt.x} cy={pt.y} r={5} fill="#a855f7" stroke="#0f172a" strokeWidth="2">
                <title>{pt.label}</title>
              </circle>
            ))}
          </svg>
          <div style={{ display: "flex", gap: 12, marginTop: 8, flexWrap: "wrap", alignItems: "center" }}>
            <span style={{ background: "#4c1d95", borderRadius: 12, padding: "2px 10px", fontSize: 11, color: "#c4b5fd" }}>
              z-score: {email_pulse.top.z_score}
            </span>
            <span style={{ background: "#1e293b", borderRadius: 12, padding: "2px 10px", fontSize: 11, color: "#94a3b8" }}>
              Link Density: {email_pulse.top.current_avg_link_density} (mean: {email_pulse.top.baseline_mean})
            </span>
            <span style={{ background: "#1e293b", borderRadius: 12, padding: "2px 10px", fontSize: 11, color: "#94a3b8" }}>
              Msgs This Hour: {email_pulse.top.current_hour_msgs}
            </span>
            {emailDrive?.current_hour_intercepted > 0 && (
              <span style={{ background: "#450a0a", borderRadius: 12, padding: "2px 10px", fontSize: 11, color: "#fca5a5" }}>
                Intercepted: {emailDrive.current_hour_intercepted}
              </span>
            )}
          </div>
          <div style={{ marginTop: 12 }}>
            <button
              onClick={() => handleNullRoute(email_pulse.top.tld)}
              disabled={nullRouting}
              style={{
                background: nullRouting ? "#4c1d95" : "#7c3aed",
                color: "#fff",
                border: "1px solid #a855f7",
                borderRadius: 6,
                padding: "8px 18px",
                cursor: nullRouting ? "wait" : "pointer",
                fontWeight: 600,
                fontSize: 13,
              }}
            >
              {nullRouting ? "Null-Routing..." : `Null-Route Current Spam Drive (${email_pulse.top.tld})`}
            </button>
          </div>
        </div>
      )}

      {/* Context Badges */}
      {(highestRisk || jitStatus || stats) && (
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 16 }}>
          {highestRisk?.user_id && (
            <div style={{ background: "#3b0764", border: "1px solid #7c3aed", borderRadius: 10, padding: "8px 14px", display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 11, color: "#c4b5fd" }}>Highest Risk User</span>
              <strong style={{ color: "#f5f3ff", fontSize: 13 }}>{highestRisk.user_id}</strong>
              <span style={{
                background: highestRisk.max_z_score > 3 ? "#7f1d1d" : highestRisk.max_z_score > 2 ? "#78350f" : "#14532d",
                color: highestRisk.max_z_score > 3 ? "#fca5a5" : highestRisk.max_z_score > 2 ? "#fde68a" : "#86efac",
                borderRadius: 12, padding: "1px 8px", fontSize: 11, fontWeight: 600,
              }}>
                z={highestRisk.max_z_score?.toFixed(1)} ({highestRisk.event_type})
              </span>
              {highestRisk.z_score_meta?.mean > 0 && (
                <span style={{
                  background: "#1e293b", borderRadius: 12, padding: "1px 8px", fontSize: 10, color: "#94a3b8",
                }}>
                  Baseline Deviation: {Math.round(((highestRisk.z_score_meta.current - highestRisk.z_score_meta.mean) / highestRisk.z_score_meta.mean) * 100)}%
                </span>
              )}
            </div>
          )}
          {jitStatus && jitStatus.count > 0 && (
            <div style={{ background: "#450a0a", border: "1px solid #dc2626", borderRadius: 10, padding: "8px 14px", display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 11, color: "#fca5a5" }}>JIT Revoked</span>
              <strong style={{ color: "#fef2f2", fontSize: 13 }}>{jitStatus.count}</strong>
            </div>
          )}
          {stats && (
            <div style={{ background: "#052e16", border: "1px solid #16a34a", borderRadius: 10, padding: "8px 14px", display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 11, color: "#86efac" }}>Deflection Rate</span>
              <strong style={{ color: "#f0fdf4", fontSize: 13 }}>{stats.success_rate}%</strong>
            </div>
          )}
          {threatFeed && (
            <div style={{ background: "#1e1b4b", border: "1px solid #6366f1", borderRadius: 10, padding: "8px 14px", display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 11, color: "#a5b4fc" }}>Shared Intel</span>
              <strong style={{ color: "#eef2ff", fontSize: 13 }}>{threatFeed.shared_count || 0}</strong>
            </div>
          )}
        </div>
      )}

      {/* JIT Revocation Status */}
      {jitStatus && (
        <div style={card}>
          <h2 style={h2}>JIT Session Revocations</h2>
          {jitStatus.count === 0
            ? <p style={{ color: "#6f6" }}>No active revocations</p>
            : (
              <>
                <p style={{ color: "#f66", fontWeight: 600 }}>{jitStatus.count} user(s) currently revoked</p>
                <ul style={{ listStyle: "none", padding: 0, margin: "8px 0" }}>
                  {jitStatus.revoked_users.map(u => <li key={u} style={{ color: "#faa", padding: "4px 0", borderBottom: "1px solid #333" }}>⛔ {u}</li>)}
                </ul>
              </>
            )}
        </div>
      )}

      {/* Playbook Breakdown */}
      {audit && audit.by_playbook && (
        <div style={card}>
          <h2 style={h2}>Playbook Breakdown</h2>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #444" }}>
                <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>Playbook</th>
                <th style={{ textAlign: "right", padding: 8, color: "#aaa" }}>Total</th>
                <th style={{ textAlign: "right", padding: 8, color: "#aaa" }}>Success</th>
                <th style={{ textAlign: "right", padding: 8, color: "#aaa" }}>Failed</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(audit.by_playbook).map(([name, d]) => (
                <tr key={name} style={{ borderBottom: "1px solid #2a2a3a" }}>
                  <td style={{ padding: 8, color: "#ddf" }}>{name}</td>
                  <td style={{ padding: 8, textAlign: "right", color: "#fff" }}>{d.total}</td>
                  <td style={{ padding: 8, textAlign: "right", color: "#6f6" }}>{d.success}</td>
                  <td style={{ padding: 8, textAlign: "right", color: "#f66" }}>{d.failed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Daily Trend */}
      {audit && audit.daily_trend && audit.daily_trend.length > 0 && (
        <div style={card}>
          <h2 style={h2}>Daily Execution Trend</h2>
          <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 120, padding: "8px 0" }}>
            {audit.daily_trend.map(d => {
              const maxCount = Math.max(...audit.daily_trend.map(x => x.count), 1);
              const h = Math.max(4, (d.count / maxCount) * 100);
              return (
                <div key={d.day} style={{ display: "flex", flexDirection: "column", alignItems: "center", flex: 1 }}>
                  <div style={{ background: "#5b5fc7", width: "100%", maxWidth: 32, height: h, borderRadius: "4px 4px 0 0" }} title={`${d.day}: ${d.count}`} />
                  <span style={{ fontSize: 9, color: "#888", marginTop: 4, transform: "rotate(-45deg)", whiteSpace: "nowrap" }}>{d.day.slice(5)}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Deflected Details */}
      {stats && stats.deflected_details && stats.deflected_details.length > 0 && (
        <div style={card}>
          <h2 style={h2}>Deflected Threat Details</h2>
          <ul style={{ listStyle: "none", padding: 0 }}>
            {stats.deflected_details.map((d, i) => (
              <li key={i} style={{ padding: "8px 0", borderBottom: "1px solid #2a2a3a", color: "#ddf" }}>
                <strong>{d.playbook || "unknown"}</strong> — {d.reason || "no reason"} (risk: {d.risk_score ?? "N/A"}, ML: {d.ml_anomaly_score ?? "N/A"})
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recent Actions */}
      {audit && audit.recent_actions && audit.recent_actions.length > 0 && (
        <div style={card}>
          <h2 style={h2}>Recent SOAR Actions</h2>
          <ul style={{ listStyle: "none", padding: 0 }}>
            {audit.recent_actions.map((a, i) => (
              <li key={i} style={{ padding: "6px 0", borderBottom: "1px solid #2a2a3a", fontSize: 13 }}>
                <span style={{ color: a.status === "success" ? "#6f6" : "#f66", fontWeight: 600 }}>{a.status}</span>
                {" "}— {a.action} ({a.playbook || "?"}) — risk {a.risk_score ?? "?"} — {a.timestamp}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Global Threat Map */}
      {threatFeed && threatFeed.indicators && (
        <div style={card}>
          <h2 style={h2}>Global Threat Intel Map</h2>
          <p style={{ color: "#888", fontSize: 12, marginBottom: 12 }}>
            Sources: {(threatFeed.feed_sources || []).join(", ")} | Shared Intelligence: {threatFeed.shared_count || 0}
          </p>
          <div style={{ position: "relative", background: "#151528", borderRadius: 8, padding: 20, minHeight: 200, overflow: "hidden" }}>
            {/* Stylized world map outline */}
            <svg viewBox="0 0 800 400" style={{ width: "100%", height: "auto", opacity: 0.2 }}>
              <ellipse cx="400" cy="200" rx="380" ry="180" fill="none" stroke="#5b5fc7" strokeWidth="1" />
              <line x1="20" y1="200" x2="780" y2="200" stroke="#5b5fc7" strokeWidth="0.5" />
              <line x1="400" y1="20" x2="400" y2="380" stroke="#5b5fc7" strokeWidth="0.5" />
              <ellipse cx="400" cy="200" rx="380" ry="60" fill="none" stroke="#5b5fc7" strokeWidth="0.5" />
              <ellipse cx="400" cy="200" rx="380" ry="120" fill="none" stroke="#5b5fc7" strokeWidth="0.5" />
            </svg>
            {/* Threat indicators plotted as pulsing dots */}
            {threat_indicators.map((ind) => {
              const hash = [...ind.ip].reduce((a, c) => a + c.charCodeAt(0), 0);
              const x = 10 + (hash * 7) % 80;
              const y = 10 + (hash * 13) % 80;
              const risk_color = ind.risk >= 90 ? "#f44" : ind.risk >= 70 ? "#f90" : "#fa0";
              const indicator_key = `${ind.ip}:${ind.source || "global"}:${ind.category || "unknown"}`;
              return (
                <div key={indicator_key} title={`${ind.ip} — ${ind.category} (risk: ${ind.risk})`}
                  style={{
                    position: "absolute", left: `${x}%`, top: `${y}%`,
                    width: 12, height: 12, borderRadius: "50%",
                    background: risk_color, opacity: 0.85,
                    boxShadow: `0 0 8px ${risk_color}`,
                    animation: animate_threat_indicators ? "pulse 2s infinite" : "none",
                    cursor: "pointer",
                    border: ind.shared_intelligence ? "2px solid #c084fc" : "none",
                  }}>
                  {ind.shared_intelligence ? (
                    <span style={{
                      position: "absolute", top: -15, left: -18,
                      background: "#4c1d95", color: "#ddd6fe",
                      borderRadius: 10, fontSize: 9, padding: "1px 5px", whiteSpace: "nowrap",
                    }}>Shared Intel</span>
                  ) : null}
                </div>
              );
            })}
          </div>
          <p style={{ color: "#888", fontSize: 11, marginTop: 10 }}>
            Displaying top {threat_indicators.length} of {threatFeed.total || threat_indicators.length} indicators by risk.
          </p>
          <style>{`@keyframes pulse { 0%,100% { transform: scale(1); opacity: 0.85; } 50% { transform: scale(1.4); opacity: 0.5; } }`}</style>
          <table style={{ width: "100%", borderCollapse: "collapse", marginTop: 16 }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #444" }}>
                <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>IP</th>
                <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>Category</th>
                <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>Source</th>
                <th style={{ textAlign: "right", padding: 8, color: "#aaa" }}>Risk</th>
                <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>Tags</th>
                <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>Diplomat</th>
              </tr>
            </thead>
            <tbody>
              {threat_indicators.map((ind) => {
                const indicator_key = `${ind.ip}:${ind.source || "global"}:${ind.category || "unknown"}`;
                return (
                <tr key={indicator_key} style={{ borderBottom: "1px solid #2a2a3a" }}>
                  <td style={{ padding: 8, color: "#faa", fontFamily: "monospace" }}>{ind.ip}</td>
                  <td style={{ padding: 8, color: "#ddf" }}>{ind.category}</td>
                  <td style={{ padding: 8, color: "#aac" }}>{ind.source}</td>
                  <td style={{ padding: 8, textAlign: "right", color: ind.risk >= 90 ? "#f44" : ind.risk >= 70 ? "#f90" : "#fa0", fontWeight: 700 }}>{ind.risk}</td>
                  <td style={{ padding: 8, color: "#888" }}>{(ind.tags || []).join(", ")}</td>
                  <td style={{ padding: 8 }}>
                    {ind.shared_intelligence ? (
                      <span style={{ background: "#4c1d95", color: "#ddd6fe", borderRadius: 10, padding: "2px 8px", fontSize: 11 }}>Shared Intelligence</span>
                    ) : (
                      <span style={{ color: "#666", fontSize: 11 }}>-</span>
                    )}
                  </td>
                </tr>
              )})}
            </tbody>
          </table>
        </div>
      )}

      {/* System Health — Distributed Agents */}
      {agents && (
        <div style={card}>
          <h2 style={h2}>System Health — Distributed Agents</h2>
          {agents.total === 0
            ? <p style={{ color: "#888" }}>No agents registered yet. Deploy agents/soc_agent.py to begin telemetry collection.</p>
            : (
              <>
                <div style={row}>
                  <div style={kpi}>
                    <div style={label}>Active Agents</div>
                    <div style={{ ...value, color: "#6f6" }}>{agents.total}</div>
                  </div>
                  <div style={kpi}>
                    <div style={label}>Total Events</div>
                    <div style={value}>{agents.agents.reduce((s, a) => s + (a.event_count || 0), 0)}</div>
                  </div>
                </div>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid #444" }}>
                      <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>Agent ID</th>
                      <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>Hostname</th>
                      <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>Status</th>
                      <th style={{ textAlign: "right", padding: 8, color: "#aaa" }}>Events</th>
                      <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>Last Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {agents.agents.map(a => (
                      <tr key={a.agent_id} style={{ borderBottom: "1px solid #2a2a3a" }}>
                        <td style={{ padding: 8, color: "#ddf", fontFamily: "monospace" }}>{a.agent_id}</td>
                        <td style={{ padding: 8, color: "#ccc" }}>{a.hostname || "—"}</td>
                        <td style={{ padding: 8, color: a.status === "active" ? "#6f6" : "#f90" }}>{a.status}</td>
                        <td style={{ padding: 8, textAlign: "right", color: "#fff" }}>{a.event_count}</td>
                        <td style={{ padding: 8, color: "#888", fontSize: 12 }}>{a.last_seen || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
        </div>
      )}

      {/* Drill Success — Security Validation */}
      {drills && (
        <div style={card}>
          <h2 style={h2}>Security Drill Results</h2>
          {drills.total === 0
            ? <p style={{ color: "#888" }}>No drills executed yet. Run via Voice Command or POST /drills/run.</p>
            : (
              <>
                <div style={row}>
                  <div style={kpi}>
                    <div style={label}>Total Drills</div>
                    <div style={value}>{drills.total}</div>
                  </div>
                  <div style={kpi}>
                    <div style={label}>Passed</div>
                    <div style={{ ...value, color: "#6f6" }}>{drills.drills.filter(d => d.overall === "pass").length}</div>
                  </div>
                  <div style={kpi}>
                    <div style={label}>Partial</div>
                    <div style={{ ...value, color: "#f90" }}>{drills.drills.filter(d => d.overall === "partial").length}</div>
                  </div>
                  <div style={kpi}>
                    <div style={label}>Failed</div>
                    <div style={{ ...value, color: "#f44" }}>{drills.drills.filter(d => d.overall === "fail").length}</div>
                  </div>
                </div>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid #444" }}>
                      <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>Drill ID</th>
                      <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>Type</th>
                      <th style={{ textAlign: "center", padding: 8, color: "#aaa" }}>Score</th>
                      <th style={{ textAlign: "center", padding: 8, color: "#aaa" }}>Overall</th>
                      <th style={{ textAlign: "left", padding: 8, color: "#aaa" }}>Completed</th>
                    </tr>
                  </thead>
                  <tbody>
                    {drills.drills.map(d => (
                      <tr key={d.drill_id} style={{ borderBottom: "1px solid #2a2a3a" }}>
                        <td style={{ padding: 8, color: "#ddf", fontFamily: "monospace", fontSize: 12 }}>{d.drill_id}</td>
                        <td style={{ padding: 8, color: "#ccc" }}>{d.drill_type}</td>
                        <td style={{ padding: 8, textAlign: "center", color: "#fff", fontWeight: 600 }}>{d.score}</td>
                        <td style={{ padding: 8, textAlign: "center" }}>
                          <span style={{
                            background: d.overall === "pass" ? "#1a4a1a" : d.overall === "partial" ? "#4a3a0a" : "#4a1a1a",
                            color: d.overall === "pass" ? "#6f6" : d.overall === "partial" ? "#f90" : "#f44",
                            padding: "2px 10px", borderRadius: 12, fontSize: 12, fontWeight: 600,
                          }}>{d.overall}</span>
                        </td>
                        <td style={{ padding: 8, color: "#888", fontSize: 12 }}>{d.completed_at || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
        </div>
      )}
    </main>
  );
}
