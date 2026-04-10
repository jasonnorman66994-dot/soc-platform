"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost/api";
const WS = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost/ws";

export default function CommandCenterPage() {
  const [useDemoMode, setUseDemoMode] = useState(true);
  const [manualLogin, setManualLogin] = useState({ tenant: "", email: "", password: "", apiKey: "" });
  const [loginError, setLoginError] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [refreshToken, setRefreshToken] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [userInfo, setUserInfo] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [execStats, setExecStats] = useState(null);
  const [wsState, setWsState] = useState("disconnected");
  const [ingestResult, setIngestResult] = useState(null);
  const [adminTokenInput, setAdminTokenInput] = useState("dev-admin-token");
  const [adminAccessToken, setAdminAccessToken] = useState("");
  const [adminRefreshToken, setAdminRefreshToken] = useState("");
  const [adminError, setAdminError] = useState("");
  const [adminLeads, setAdminLeads] = useState([]);
  const [adminFunnel, setAdminFunnel] = useState(null);
  const [adminWebhookMetrics, setAdminWebhookMetrics] = useState(null);
  const [adminBoardReport, setAdminBoardReport] = useState(null);
  const [boardWindowDays, setBoardWindowDays] = useState("30");
  const [boardIncidentLimit, setBoardIncidentLimit] = useState("10");

  const authHeaders = useMemo(
    () => ({
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
      "X-Tenant-ID": tenantId,
    }),
    [accessToken, tenantId]
  );

  const ingestHeaders = useMemo(
    () => ({
      "Content-Type": "application/json",
      "X-Tenant-ID": tenantId,
      "X-API-Key": apiKey,
    }),
    [tenantId, apiKey]
  );

  useEffect(() => {
    if (useDemoMode) {
      bootstrapDemoTenant();
    }
  }, [useDemoMode]);

  useEffect(() => {
    if (!accessToken || !tenantId) return;
    fetchAlerts();
    fetchIncidents();
    fetchExecutiveStats();

    const ws = new WebSocket(`${WS}?tenant_id=${encodeURIComponent(tenantId)}&token=${encodeURIComponent(accessToken)}`);
    ws.onopen = () => setWsState("connected");
    ws.onclose = () => setWsState("disconnected");
    ws.onmessage = async () => {
      await fetchAlerts();
      await fetchIncidents();
      await fetchExecutiveStats();
    };

    const heartbeat = setInterval(() => {
      if (ws.readyState === ws.OPEN) ws.send("ping");
    }, 4000);

    return () => {
      clearInterval(heartbeat);
      ws.close();
    };
  }, [accessToken, tenantId]);

  async function bootstrapDemoTenant() {
    const res = await fetch(`${API}/demo/bootstrap`);
    const data = await res.json();
    setTenantId(data.tenant_id || "");
    setApiKey(data.api_key || "");
    await login(data.analyst?.email, data.analyst?.password, data.tenant_id);
  }

  async function login(email, password, tenant) {
    setLoginError("");
    const res = await fetch(`${API}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Tenant-ID": tenant },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      setLoginError(data?.detail || "Login failed");
      return;
    }
    setAccessToken(data.access_token || "");
    setRefreshToken(data.refresh_token || "");
    setUserInfo(data.user || null);
  }

  async function loginManual() {
    setTenantId(manualLogin.tenant);
    setApiKey(manualLogin.apiKey);
    await login(manualLogin.email, manualLogin.password, manualLogin.tenant);
  }

  async function refreshAccess() {
    if (!refreshToken || !tenantId) return;
    const res = await fetch(`${API}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Tenant-ID": tenantId },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    const data = await res.json();
    if (data.access_token) setAccessToken(data.access_token);
  }

  async function fetchAlerts() {
    const res = await fetch(`${API}/alerts`, { headers: authHeaders });
    const data = await res.json();
    setAlerts(Array.isArray(data) ? data : []);
  }

  async function fetchIncidents() {
    const res = await fetch(`${API}/incidents`, { headers: authHeaders });
    const data = await res.json();
    setIncidents(Array.isArray(data) ? data : []);
  }

  async function fetchExecutiveStats() {
    const res = await fetch(`${API}/dashboard/executive`, { headers: authHeaders });
    const data = await res.json();
    setExecStats(data?.tenant_id ? data : null);
  }

  async function sendTestIngest() {
    const payload = {
      user_id: "demo.user",
      event_type: "email",
      subject: "URGENT: Verify my password",
      sender_domain: "evil.com",
      raw: { stage: "email_delivered" },
    };
    const res = await fetch(`${API}/ingest`, {
      method: "POST",
      headers: ingestHeaders,
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    setIngestResult(data);
    await fetchAlerts();
    await fetchIncidents();
    await fetchExecutiveStats();
  }

  async function blockIp() {
    if (!incidents[0]) return;
    await fetch(`${API}/respond/block-ip?ip=203.0.113.42&incident_id=${incidents[0].id}`, {
      method: "POST",
      headers: authHeaders,
    });
    await fetchIncidents();
    await fetchExecutiveStats();
  }

  async function runAttackSimulation() {
    const res = await fetch(`${API}/demo/simulate-attack`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({ user_id: "demo.user", source_country: "UK", destination_country: "US" }),
    });
    const data = await res.json();
    setIngestResult(data);
    await fetchAlerts();
    await fetchIncidents();
    await fetchExecutiveStats();
  }

  async function createAdminSession() {
    setAdminError("");
    const res = await fetch(`${API}/admin/session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ admin_token: adminTokenInput }),
    });
    const data = await res.json();
    if (!res.ok) {
      setAdminError(data?.detail || "Admin session failed");
      return;
    }
    setAdminAccessToken(data.access_token || "");
    setAdminRefreshToken(data.refresh_token || "");
  }

  async function refreshAdminSession() {
    if (!adminRefreshToken) return;
    const res = await fetch(`${API}/admin/session/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: adminRefreshToken }),
    });
    const data = await res.json();
    if (!res.ok) {
      setAdminError(data?.detail || "Admin refresh failed");
      return;
    }
    setAdminAccessToken(data.access_token || "");
    setAdminRefreshToken(data.refresh_token || "");
  }

  async function revokeAdminSession() {
    if (!adminRefreshToken) return;
    await fetch(`${API}/admin/session/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: adminRefreshToken }),
    });
    setAdminAccessToken("");
    setAdminRefreshToken("");
  }

  async function loadAdminData() {
    if (!adminAccessToken) return;
    const headers = { Authorization: `Bearer ${adminAccessToken}` };
    const [leadsRes, funnelRes, webhookRes] = await Promise.all([
      fetch(`${API}/admin/leads?limit=25`, { headers }),
      fetch(`${API}/admin/funnel`, { headers }),
      fetch(`${API}/admin/webhooks/metrics?limit=40`, { headers }),
    ]);

    const leads = await leadsRes.json();
    const funnel = await funnelRes.json();
    const webhooks = await webhookRes.json();

    setAdminLeads(Array.isArray(leads) ? leads : []);
    setAdminFunnel(funnel?.total_leads !== undefined ? funnel : null);
    setAdminWebhookMetrics(webhooks?.summary_last_7_days ? webhooks : null);
  }

  async function cleanupReplayFingerprints() {
    if (!adminAccessToken) return;
    await fetch(`${API}/admin/webhooks/cleanup`, {
      method: "POST",
      headers: { Authorization: `Bearer ${adminAccessToken}` },
    });
    await loadAdminData();
  }

  function buildBoardReportQuery() {
    const safeWindowDays = Math.max(7, Math.min(Number.parseInt(boardWindowDays || "30", 10) || 30, 180));
    const safeIncidentLimit = Math.max(3, Math.min(Number.parseInt(boardIncidentLimit || "10", 10) || 10, 50));
    const query = new URLSearchParams({
      window_days: String(safeWindowDays),
      incident_limit: String(safeIncidentLimit),
    });
    return { safeWindowDays, safeIncidentLimit, query: query.toString() };
  }

  async function loadBoardReport() {
    if (!adminAccessToken) return;
    const { safeWindowDays, safeIncidentLimit, query } = buildBoardReportQuery();
    const res = await fetch(`${API}/admin/reports/board?${query}`, {
      headers: { Authorization: `Bearer ${adminAccessToken}` },
    });
    const data = await res.json();
    if (!res.ok) {
      setAdminError(data?.detail || "Board report load failed");
      return;
    }
    setBoardWindowDays(String(safeWindowDays));
    setBoardIncidentLimit(String(safeIncidentLimit));
    setAdminError("");
    setAdminBoardReport(data?.generated_at ? data : null);
  }

  async function downloadBoardReport() {
    if (!adminAccessToken) return;
    const { safeWindowDays, safeIncidentLimit, query } = buildBoardReportQuery();
    const res = await fetch(`${API}/admin/reports/board.md?${query}`, {
      headers: { Authorization: `Bearer ${adminAccessToken}` },
    });
    const body = await res.text();
    if (!res.ok) {
      setAdminError(body || "Board report download failed");
      return;
    }

    const blob = new Blob([body], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `board-report-${safeWindowDays}d-${safeIncidentLimit}incidents.md`;
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setBoardWindowDays(String(safeWindowDays));
    setBoardIncidentLimit(String(safeIncidentLimit));
    setAdminError("");
  }

  return (
    <main style={{ minHeight: "100vh", padding: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <h1 style={{ margin: 0, color: "#60a5fa" }}>SOC Platform Command Center</h1>
        <Link href="/" style={{ color: "#94a3b8", textDecoration: "none", border: "1px solid #334155", borderRadius: 8, padding: "8px 10px" }}>
          Back to Product Site
        </Link>
      </div>

      <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
        <button style={useDemoMode ? btn : btnSecondary} onClick={() => setUseDemoMode(true)}>Demo Mode</button>
        <button style={!useDemoMode ? btn : btnSecondary} onClick={() => setUseDemoMode(false)}>Live Tenant Mode</button>
      </div>

      {!useDemoMode ? (
        <section style={{ ...card, marginTop: 12 }}>
          <h3 style={h3}>Manual Tenant Login</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 8 }}>
            <input style={input} placeholder="Tenant ID" value={manualLogin.tenant} onChange={(e) => setManualLogin((s) => ({ ...s, tenant: e.target.value }))} />
            <input style={input} placeholder="Email" value={manualLogin.email} onChange={(e) => setManualLogin((s) => ({ ...s, email: e.target.value }))} />
            <input style={input} type="password" placeholder="Password" value={manualLogin.password} onChange={(e) => setManualLogin((s) => ({ ...s, password: e.target.value }))} />
            <input style={input} placeholder="Ingest API Key" value={manualLogin.apiKey} onChange={(e) => setManualLogin((s) => ({ ...s, apiKey: e.target.value }))} />
          </div>
          <div style={{ marginTop: 8 }}>
            <button style={btn} onClick={loginManual}>Connect Tenant</button>
          </div>
          {loginError ? <p style={{ color: "#f87171", marginBottom: 0 }}>{loginError}</p> : null}
        </section>
      ) : null}

      <p style={{ color: "#94a3b8", marginTop: 6 }}>
        Tenant: <strong>{tenantId || "-"}</strong> | User: <strong>{userInfo?.email || "-"}</strong> | Role: <strong>{userInfo?.role || "-"}</strong> | WebSocket: <strong>{wsState}</strong>
      </p>

      <div style={{ display: "flex", gap: 12, marginTop: 12, flexWrap: "wrap" }}>
        <button onClick={sendTestIngest} style={btn}>POST /ingest Test Attack</button>
        <button onClick={runAttackSimulation} style={btn}>POST /demo/simulate-attack</button>
        <button onClick={blockIp} style={btn}>POST /respond/block-ip</button>
        <button onClick={refreshAccess} style={btnSecondary}>Refresh Access Token</button>
        <button onClick={fetchAlerts} style={btnSecondary}>Refresh Alerts</button>
        <button onClick={fetchIncidents} style={btnSecondary}>Refresh Incidents</button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))", gap: 12, marginTop: 16 }}>
        <section style={card}><h3 style={h3}>Total Incidents</h3><div>{execStats?.total_incidents ?? "-"}</div></section>
        <section style={card}><h3 style={h3}>MTTD (sec)</h3><div>{Math.round(execStats?.mttd_seconds || 0)}</div></section>
        <section style={card}><h3 style={h3}>MTTR (sec)</h3><div>{Math.round(execStats?.mttr_seconds || 0)}</div></section>
        <section style={card}><h3 style={h3}>Risk Points</h3><div>{(execStats?.risk_score_trend || []).length}</div></section>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 14, marginTop: 16 }}>
        <section style={card}>
          <h3 style={h3}>Alerts ({alerts.length})</h3>
          <ul style={list}>
            {alerts.slice(0, 8).map((a) => (
              <li key={a.id || `${a.rule_id}-${a.timestamp}`} style={row}>
                <span>{a.summary || a.title || a.rule_id}</span>
                <span style={{ color: sev(a.severity) }}>{a.severity}</span>
              </li>
            ))}
          </ul>
        </section>

        <section style={card}>
          <h3 style={h3}>Incidents ({incidents.length})</h3>
          <ul style={list}>
            {incidents.slice(0, 8).map((i) => (
              <li key={i.id} style={row}>
                <span>{i.entity || "unknown-entity"}</span>
                <span style={{ color: sev(i.severity) }}>{i.severity}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section style={{ ...card, marginTop: 16 }}>
        <h3 style={h3}>Admin Operations Panel</h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))", gap: 8 }}>
          <input style={input} placeholder="Internal admin token" value={adminTokenInput} onChange={(e) => setAdminTokenInput(e.target.value)} />
          <input style={input} type="number" min="7" max="180" placeholder="Board window days (7-180)" value={boardWindowDays} onChange={(e) => setBoardWindowDays(e.target.value)} />
          <input style={input} type="number" min="3" max="50" placeholder="Incident limit (3-50)" value={boardIncidentLimit} onChange={(e) => setBoardIncidentLimit(e.target.value)} />
          <button style={btn} onClick={createAdminSession}>Create Admin Session</button>
          <button style={btnSecondary} onClick={refreshAdminSession}>Refresh Admin Session</button>
          <button style={btnSecondary} onClick={revokeAdminSession}>Revoke Admin Session</button>
          <button style={btn} onClick={loadAdminData}>Load Admin Analytics</button>
          <button style={btn} onClick={loadBoardReport}>Load Board Report</button>
          <button style={btnSecondary} onClick={downloadBoardReport}>Download Board Report</button>
          <button style={btnSecondary} onClick={cleanupReplayFingerprints}>Cleanup Replay Fingerprints</button>
        </div>
        {adminError ? <p style={{ color: "#f87171", marginBottom: 0 }}>{adminError}</p> : null}

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 10, marginTop: 12 }}>
          <div style={miniCard}><div style={miniTitle}>Total Leads</div><div>{adminFunnel?.total_leads ?? "-"}</div></div>
          <div style={miniCard}><div style={miniTitle}>Converted Signups</div><div>{adminFunnel?.converted_signups ?? "-"}</div></div>
          <div style={miniCard}><div style={miniTitle}>Conversion Rate</div><div>{adminFunnel ? `${Math.round((adminFunnel.conversion_rate || 0) * 100)}%` : "-"}</div></div>
          <div style={miniCard}><div style={miniTitle}>Webhook Summary Rows</div><div>{(adminWebhookMetrics?.summary_last_7_days || []).length}</div></div>
          <div style={miniCard}><div style={miniTitle}>Board Report Window</div><div>{adminBoardReport?.window_days ? `${adminBoardReport.window_days}d` : "-"}</div></div>
          <div style={miniCard}><div style={miniTitle}>Board Open Incidents</div><div>{adminBoardReport?.incident_summary?.open_incidents ?? "-"}</div></div>
        </div>

        <div style={{ marginTop: 12 }}>
          <h4 style={{ margin: 0, color: "#cbd5e1" }}>Board Snapshot</h4>
          <ul style={list}>
            <li style={row}><span>Generated At</span><span>{adminBoardReport?.generated_at || "-"}</span></li>
            <li style={row}><span>Total Tenants</span><span>{adminBoardReport?.tenant_summary?.total_tenants ?? "-"}</span></li>
            <li style={row}><span>Critical Incidents</span><span>{adminBoardReport?.incident_summary?.critical_incidents ?? "-"}</span></li>
            <li style={row}><span>Lead Conversion</span><span>{adminBoardReport ? `${Math.round((adminBoardReport.commercial_summary?.conversion_rate || 0) * 100)}%` : "-"}</span></li>
          </ul>
        </div>

        <div style={{ marginTop: 12 }}>
          <h4 style={{ margin: 0, color: "#cbd5e1" }}>Recent Leads ({adminLeads.length})</h4>
          <ul style={list}>
            {adminLeads.slice(0, 8).map((l) => (
              <li key={l.id} style={row}>
                <span>{l.email}</span>
                <span>{l.converted_to_signup ? "converted" : "new"}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {ingestResult && (
        <pre style={{ marginTop: 16, background: "#0f172a", border: "1px solid #1e293b", padding: 12, borderRadius: 8, overflow: "auto" }}>
          {JSON.stringify(ingestResult, null, 2)}
        </pre>
      )}
    </main>
  );
}

const btn = {
  background: "#2563eb",
  color: "white",
  border: "none",
  borderRadius: 8,
  padding: "10px 12px",
  cursor: "pointer",
};

const btnSecondary = {
  ...btn,
  background: "#1e293b",
  border: "1px solid #334155",
};

const card = {
  background: "#0f172a",
  border: "1px solid #1e293b",
  borderRadius: 10,
  padding: 12,
};

const h3 = { marginTop: 0, marginBottom: 8, color: "#cbd5e1" };

const list = { listStyle: "none", padding: 0, margin: 0, display: "grid", gap: 6 };

const row = {
  display: "flex",
  justifyContent: "space-between",
  borderBottom: "1px solid #1e293b",
  paddingBottom: 6,
};

const input = {
  background: "#0b1220",
  color: "#e2e8f0",
  border: "1px solid #334155",
  borderRadius: 8,
  padding: "9px 10px",
};

const miniCard = {
  background: "#0b1220",
  border: "1px solid #334155",
  borderRadius: 8,
  padding: 10,
};

const miniTitle = {
  color: "#94a3b8",
  fontSize: 12,
};

function sev(s) {
  if (s === "critical") return "#ef4444";
  if (s === "high") return "#f97316";
  if (s === "medium") return "#eab308";
  return "#22c55e";
}
