"use client";
import { useEffect, useState, useCallback } from "react";

export default function AuditDashboard() {
  const [stats, setStats] = useState(null);
  const [audit, setAudit] = useState(null);
  const [jitStatus, setJitStatus] = useState(null);
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
      const [statsRes, auditRes, jitRes] = await Promise.all([
        fetch(`${process.env.NEXT_PUBLIC_API || "http://localhost:8000"}/soar/stats?window_days=${windowDays}`, { headers: headers() }),
        fetch(`${process.env.NEXT_PUBLIC_API || "http://localhost:8000"}/soar/audit?window_days=${windowDays}`, { headers: headers() }),
        fetch(`${process.env.NEXT_PUBLIC_API || "http://localhost:8000"}/jit/status`, { headers: headers() }),
      ]);
      if (statsRes.ok) setStats(await statsRes.json());
      if (auditRes.ok) setAudit(await auditRes.json());
      if (jitRes.ok) setJitStatus(await jitRes.json());
    } catch (e) {
      console.error("AuditDashboard load error:", e);
    } finally {
      setLoading(false);
    }
  }, [headers, windowDays]);

  useEffect(() => { load(); }, [load]);

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
    </main>
  );
}
