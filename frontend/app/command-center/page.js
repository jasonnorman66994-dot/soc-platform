"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost/api";
const WS = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost/ws";

function getDefaultScheduleForm() {
  return {
    name: "Weekly Board Report",
    description: "Automated weekly board report export",
    format: "markdown",
    frequency: "weekly",
    day_of_week: 1,
    day_of_month: 1,
    hour_of_day: 9,
    window_days: 30,
    incident_limit: 10,
    recipients: "",
    enabled: true,
  };
}

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
  const [reportSchedules, setReportSchedules] = useState([]);
  const [scheduleForm, setScheduleForm] = useState(getDefaultScheduleForm());
  const [editingScheduleId, setEditingScheduleId] = useState(null);
  const [scheduleRunSummary, setScheduleRunSummary] = useState("");
  const [scheduleSummary, setScheduleSummary] = useState({ total: 0, enabled: 0, paused: 0, due: 0 });
  const [scenarioCatalog, setScenarioCatalog] = useState([]);
  const [simulationForm, setSimulationForm] = useState({
    scenario: "credential_compromise_chain",
    user_id: "demo.user",
    source_country: "UK",
    destination_country: "US",
    iterations: 1,
    include_noise: false,
    dry_run: false,
  });
  const [simulationResult, setSimulationResult] = useState(null);
  const [analyticsWindowDays, setAnalyticsWindowDays] = useState("14");
  const [analyticsLoading, setAnalyticsLoading] = useState(false);
  const [analyticsError, setAnalyticsError] = useState("");
  const [uebaSummary, setUebaSummary] = useState(null);
  const [mlAnomalies, setMlAnomalies] = useState(null);
  const [advancedAnalytics, setAdvancedAnalytics] = useState(null);
  const [toast, setToast] = useState(null);

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
    fetchScenarioCatalog();
    loadAdvancedAnalytics();

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
    const safeIterations = Math.max(1, Math.min(Number.parseInt(String(simulationForm.iterations), 10) || 1, 5));
    try {
      const res = await fetch(`${API}/demo/simulate-attack`, {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({
          user_id: simulationForm.user_id || "demo.user",
          source_country: simulationForm.source_country || "UK",
          destination_country: simulationForm.destination_country || "US",
          scenario: simulationForm.scenario,
          iterations: safeIterations,
          include_noise: !!simulationForm.include_noise,
          dry_run: !!simulationForm.dry_run,
        }),
      });

      const bodyText = await res.text();
      let data = null;
      try {
        data = bodyText ? JSON.parse(bodyText) : null;
      } catch {
        data = null;
      }

      if (!res.ok) {
        const message = data?.detail || bodyText || "Simulation failed";
        setToast({ type: "error", message });
        return;
      }

      setIngestResult(data);
      setSimulationResult(data);
      setToast({
        type: "success",
        message: `Simulation completed: ${data?.scenario || "scenario"} (${data?.event_count ?? 0} events)`,
      });
      await fetchAlerts();
      await fetchIncidents();
      await fetchExecutiveStats();
      await loadAdvancedAnalytics();
    } catch {
      setToast({ type: "error", message: "Simulation request failed unexpectedly" });
    }
  }

  function getSafeAnalyticsWindow() {
    return Math.max(1, Math.min(Number.parseInt(analyticsWindowDays || "14", 10) || 14, 60));
  }

  async function fetchScenarioCatalog() {
    if (!accessToken || !tenantId) return;
    const res = await fetch(`${API}/demo/scenarios`, { headers: authHeaders });
    const data = await res.json();
    setScenarioCatalog(Array.isArray(data?.scenarios) ? data.scenarios : []);
  }

  async function loadUebaAnalytics() {
    if (analyticsLoading) return;
    setAnalyticsError("");
    setAnalyticsLoading(true);
    try {
      const safeWindow = getSafeAnalyticsWindow();
      const res = await fetch(`${API}/analytics/ueba?window_days=${safeWindow}`, { headers: authHeaders });
      const data = await res.json();
      if (!res.ok) {
        const message = data?.detail || "Failed to load UEBA analytics";
        setAnalyticsError(message);
        setToast({ type: "error", message });
        return;
      }
      setAnalyticsWindowDays(String(safeWindow));
      setUebaSummary(data?.ueba || null);
      setToast({
        type: "success",
        message: `UEBA loaded for ${safeWindow} day window`,
      });
    } catch {
      const message = "Failed to load UEBA analytics";
      setAnalyticsError(message);
      setToast({ type: "error", message });
    } finally {
      setAnalyticsLoading(false);
    }
  }

  async function loadMlAnalytics() {
    if (analyticsLoading) return;
    setAnalyticsError("");
    setAnalyticsLoading(true);
    try {
      const safeWindow = getSafeAnalyticsWindow();
      const res = await fetch(`${API}/analytics/ml-anomalies?window_days=${safeWindow}`, { headers: authHeaders });
      const data = await res.json();
      if (!res.ok) {
        const message = data?.detail || "Failed to load ML anomalies";
        setAnalyticsError(message);
        setToast({ type: "error", message });
        return;
      }
      setAnalyticsWindowDays(String(safeWindow));
      setMlAnomalies(data?.ml || null);
      setToast({
        type: "success",
        message: `ML anomalies loaded (${data?.ml?.total_anomalies ?? 0} found)`,
      });
    } catch {
      const message = "Failed to load ML anomalies";
      setAnalyticsError(message);
      setToast({ type: "error", message });
    } finally {
      setAnalyticsLoading(false);
    }
  }

  async function loadAdvancedAnalytics() {
    if (analyticsLoading) return;
    setAnalyticsError("");
    setAnalyticsLoading(true);
    try {
      const safeWindow = getSafeAnalyticsWindow();
      const res = await fetch(`${API}/analytics/advanced?window_days=${safeWindow}`, { headers: authHeaders });
      const data = await res.json();
      if (!res.ok) {
        const message = data?.detail || "Failed to load advanced analytics";
        setAnalyticsError(message);
        setToast({ type: "error", message });
        return;
      }
      setAnalyticsWindowDays(String(safeWindow));
      setAdvancedAnalytics(data?.advanced || null);
      setUebaSummary(data?.advanced?.ueba || data?.ueba || null);
      setMlAnomalies(data?.advanced?.ml || data?.ml || null);
      setToast({
        type: "success",
        message: `Advanced analytics loaded (${safeWindow} day window)`,
      });
    } catch {
      const message = "Failed to load advanced analytics";
      setAnalyticsError(message);
      setToast({ type: "error", message });
    } finally {
      setAnalyticsLoading(false);
    }
  }

  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 2800);
    return () => clearTimeout(timer);
  }, [toast]);

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

  async function loadReportSchedules() {
    if (!adminAccessToken) return;
    const res = await fetch(`${API}/admin/reports/schedules`, {
      headers: { Authorization: `Bearer ${adminAccessToken}` },
    });
    const data = await res.json();
    if (!res.ok) {
      setAdminError(data?.detail || "Failed to load schedules");
      return;
    }
    setReportSchedules(data || []);
    await loadScheduleSummary();
    setAdminError("");
  }

  async function loadScheduleSummary() {
    if (!adminAccessToken) return;
    const res = await fetch(`${API}/admin/reports/schedules/summary`, {
      headers: { Authorization: `Bearer ${adminAccessToken}` },
    });
    const data = await res.json();
    if (!res.ok) {
      return;
    }
    setScheduleSummary({
      total: Number.isInteger(data?.total) ? data.total : 0,
      enabled: Number.isInteger(data?.enabled) ? data.enabled : 0,
      paused: Number.isInteger(data?.paused) ? data.paused : 0,
      due: Number.isInteger(data?.due) ? data.due : 0,
    });
  }

  async function createReportSchedule() {
    if (!adminAccessToken) return;
    const res = await fetch(`${API}/admin/reports/schedules`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminAccessToken}`,
      },
      body: JSON.stringify(scheduleForm),
    });
    const data = await res.json();
    if (!res.ok) {
      setAdminError(data?.detail || "Failed to create schedule");
      return;
    }
    setAdminError("");
    await loadReportSchedules();
    setScheduleForm(getDefaultScheduleForm());
  }

  function beginEditSchedule(schedule) {
    setEditingScheduleId(schedule.id);
    setScheduleForm({
      name: schedule.name || "",
      description: schedule.description || "",
      format: schedule.format || "markdown",
      frequency: schedule.frequency || "weekly",
      day_of_week: typeof schedule.day_of_week === "number" ? schedule.day_of_week : null,
      day_of_month: typeof schedule.day_of_month === "number" ? schedule.day_of_month : null,
      hour_of_day: Number.isInteger(schedule.hour_of_day) ? schedule.hour_of_day : 9,
      window_days: Number.isInteger(schedule.window_days) ? schedule.window_days : 30,
      incident_limit: Number.isInteger(schedule.incident_limit) ? schedule.incident_limit : 10,
      recipients: schedule.recipients || "",
      enabled: !!schedule.enabled,
    });
  }

  function cancelEditSchedule() {
    setEditingScheduleId(null);
    setScheduleForm(getDefaultScheduleForm());
  }

  async function updateReportSchedule() {
    if (!adminAccessToken || !editingScheduleId) return;
    const res = await fetch(`${API}/admin/reports/schedules/${editingScheduleId}`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminAccessToken}`,
      },
      body: JSON.stringify(scheduleForm),
    });
    const data = await res.json();
    if (!res.ok) {
      setAdminError(data?.detail || "Failed to update schedule");
      return;
    }
    setAdminError("");
    setScheduleRunSummary("");
    setEditingScheduleId(null);
    setScheduleForm(getDefaultScheduleForm());
    await loadReportSchedules();
  }

  async function runDueSchedulesNow() {
    if (!adminAccessToken) return;
    const res = await fetch(`${API}/admin/reports/schedules/run-due`, {
      method: "POST",
      headers: { Authorization: `Bearer ${adminAccessToken}` },
    });
    const data = await res.json();
    if (!res.ok) {
      setAdminError(data?.detail || "Failed to run due schedules");
      return;
    }
    setAdminError("");
    setScheduleRunSummary(
      `Run due summary: found ${data?.found ?? 0}, executed ${data?.executed_count ?? 0}, failed ${data?.failed_count ?? 0}`
    );
    await loadReportSchedules();
  }

  async function deleteReportSchedule(scheduleId) {
    if (!adminAccessToken) return;
    if (!confirm("Delete this schedule?")) return;
    const res = await fetch(`${API}/admin/reports/schedules/${scheduleId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${adminAccessToken}` },
    });
    const data = await res.json();
    if (!res.ok) {
      setAdminError(data?.detail || "Failed to delete schedule");
      return;
    }
    setAdminError("");
    await loadReportSchedules();
  }

  async function toggleReportSchedule(scheduleId, currentEnabled) {
    if (!adminAccessToken) return;
    const res = await fetch(`${API}/admin/reports/schedules/${scheduleId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminAccessToken}` },
      body: JSON.stringify({ enabled: !currentEnabled }),
    });
    const data = await res.json();
    if (!res.ok) {
      setAdminError(data?.detail || "Failed to toggle schedule");
      return;
    }
    setAdminError("");
    await loadReportSchedules();
  }

  async function runReportSchedule(scheduleId) {
    if (!adminAccessToken) return;
    const res = await fetch(`${API}/admin/reports/schedules/${scheduleId}/run`, {
      method: "POST",
      headers: { Authorization: `Bearer ${adminAccessToken}` },
    });
    const data = await res.json();
    if (!res.ok) {
      setAdminError(data?.detail || "Failed to run schedule");
      return;
    }

    if (data?.report?.generated_at) {
      setAdminBoardReport(data.report);
    }

    if (data?.format === "markdown" && data?.content) {
      const blob = new Blob([data.content], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `board-report-schedule-${scheduleId}.md`;
      link.style.display = "none";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    if (data?.format === "json" && data?.report) {
      const blob = new Blob([JSON.stringify(data.report, null, 2)], { type: "application/json;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `board-report-schedule-${scheduleId}.json`;
      link.style.display = "none";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    setAdminError("");
    await loadReportSchedules();
  }

  return (
    <main style={{ minHeight: "100vh", padding: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <h1 style={{ margin: 0, color: "#60a5fa" }}>SOC Platform Command Center</h1>
        <Link href="/" style={{ color: "#94a3b8", textDecoration: "none", border: "1px solid #334155", borderRadius: 8, padding: "8px 10px" }}>
          Back to Product Site
        </Link>
      </div>

      {toast ? (
        <div
          role={toast.type === "error" ? "alert" : "status"}
          aria-live={toast.type === "error" ? "assertive" : "polite"}
          aria-atomic="true"
          style={{
            position: "fixed",
            right: 18,
            top: 18,
            zIndex: 3000,
            background: toast.type === "error" ? "#7f1d1d" : "#064e3b",
            color: "#f8fafc",
            border: `1px solid ${toast.type === "error" ? "#ef4444" : "#22c55e"}`,
            borderRadius: 8,
            padding: "10px 12px",
            boxShadow: "0 12px 30px rgba(2, 6, 23, 0.5)",
            maxWidth: 320,
            fontSize: 13,
            display: "flex",
            gap: 8,
            alignItems: "flex-start",
          }}
        >
          <span style={{ flex: 1 }}>{toast.message}</span>
          <button
            onClick={() => setToast(null)}
            style={{
              background: "transparent",
              border: "1px solid rgba(248, 250, 252, 0.6)",
              color: "#f8fafc",
              borderRadius: 6,
              cursor: "pointer",
              padding: "0 6px",
              lineHeight: "18px",
            }}
            aria-label="Dismiss notification"
          >
            x
          </button>
        </div>
      ) : null}

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
        <button onClick={runAttackSimulation} style={btn}>Run Safe-Lab Simulation</button>
        <button onClick={blockIp} style={btn}>POST /respond/block-ip</button>
        <button onClick={refreshAccess} style={btnSecondary}>Refresh Access Token</button>
        <button onClick={fetchAlerts} style={btnSecondary}>Refresh Alerts</button>
        <button onClick={fetchIncidents} style={btnSecondary}>Refresh Incidents</button>
      </div>

      <section style={{ ...card, marginTop: 16 }}>
        <h3 style={h3}>Safe-Lab Scenario Simulation</h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 8 }}>
          <select
            style={input}
            value={simulationForm.scenario}
            onChange={(e) => setSimulationForm((s) => ({ ...s, scenario: e.target.value }))}
          >
            {(scenarioCatalog.length ? scenarioCatalog : [{ id: "credential_compromise_chain", name: "Credential Compromise Chain" }]).map((s) => (
              <option key={s.id} value={s.id}>{s.name || s.id}</option>
            ))}
          </select>
          <input
            style={input}
            placeholder="User ID"
            value={simulationForm.user_id}
            onChange={(e) => setSimulationForm((s) => ({ ...s, user_id: e.target.value }))}
          />
          <input
            style={input}
            placeholder="Source Country"
            value={simulationForm.source_country}
            onChange={(e) => setSimulationForm((s) => ({ ...s, source_country: e.target.value }))}
          />
          <input
            style={input}
            placeholder="Destination Country"
            value={simulationForm.destination_country}
            onChange={(e) => setSimulationForm((s) => ({ ...s, destination_country: e.target.value }))}
          />
          <input
            style={input}
            type="number"
            min="1"
            max="5"
            placeholder="Iterations"
            value={simulationForm.iterations}
            onChange={(e) => setSimulationForm((s) => ({ ...s, iterations: e.target.value }))}
          />
        </div>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 8 }}>
          <label style={{ color: "#cbd5e1", display: "flex", gap: 6, alignItems: "center" }}>
            <input
              type="checkbox"
              checked={simulationForm.include_noise}
              onChange={(e) => setSimulationForm((s) => ({ ...s, include_noise: e.target.checked }))}
            />
            Include Noise
          </label>
          <label style={{ color: "#cbd5e1", display: "flex", gap: 6, alignItems: "center" }}>
            <input
              type="checkbox"
              checked={simulationForm.dry_run}
              onChange={(e) => setSimulationForm((s) => ({ ...s, dry_run: e.target.checked }))}
            />
            Dry Run
          </label>
          <button onClick={runAttackSimulation} style={btn}>POST /demo/simulate-attack</button>
        </div>
        {simulationResult ? (
          <ul style={{ ...list, marginTop: 10 }}>
            <li style={row}><span>Scenario</span><span>{simulationResult.scenario || "-"}</span></li>
            <li style={row}><span>Events Emitted</span><span>{simulationResult.event_count ?? "-"}</span></li>
            <li style={row}><span>Iterations</span><span>{simulationResult.iterations ?? "-"}</span></li>
            <li style={row}><span>Dry Run</span><span>{simulationResult.dry_run ? "yes" : "no"}</span></li>
          </ul>
        ) : null}
      </section>

      <section style={{ ...card, marginTop: 16 }}>
        <h3 style={h3}>Advanced Analytics (UEBA + ML)</h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: 8 }}>
          <input
            style={input}
            type="number"
            min="1"
            max="60"
            value={analyticsWindowDays}
            onChange={(e) => setAnalyticsWindowDays(e.target.value)}
            placeholder="Window days (1-60)"
          />
          <button style={btnSecondary} onClick={loadUebaAnalytics} disabled={analyticsLoading}>Load UEBA</button>
          <button style={btnSecondary} onClick={loadMlAnalytics} disabled={analyticsLoading}>Load ML Anomalies</button>
          <button style={btn} onClick={loadAdvancedAnalytics} disabled={analyticsLoading}>Load Advanced</button>
        </div>
        {analyticsError ? <p style={{ color: "#f87171", marginBottom: 0 }}>{analyticsError}</p> : null}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 10, marginTop: 10 }}>
          <div style={miniCard}><div style={miniTitle}>Window (days)</div><div>{analyticsWindowDays}</div></div>
          <div style={miniCard}><div style={miniTitle}>UEBA Users</div><div>{uebaSummary?.total_users ?? "-"}</div></div>
          <div style={miniCard}><div style={miniTitle}>UEBA High Risk</div><div>{uebaSummary?.high_risk_users ?? "-"}</div></div>
          <div style={miniCard}><div style={miniTitle}>ML Anomalies</div><div>{mlAnomalies?.total_anomalies ?? "-"}</div></div>
          <div style={miniCard}><div style={miniTitle}>Events (Advanced)</div><div>{advancedAnalytics?.overview?.event_count ?? "-"}</div></div>
          <div style={miniCard}><div style={miniTitle}>Alerts (Advanced)</div><div>{advancedAnalytics?.overview?.alert_count ?? "-"}</div></div>
        </div>
        {analyticsLoading ? <p style={{ color: "#94a3b8", marginBottom: 0 }}>Loading analytics...</p> : null}
      </section>

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

        <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid #1e293b" }}>
          <h4 style={{ margin: 0, marginBottom: 8, color: "#cbd5e1" }}>Report Export Schedule</h4>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 6 }}>
            <input style={input} type="text" placeholder="Schedule name" value={scheduleForm.name} onChange={(e) => setScheduleForm({ ...scheduleForm, name: e.target.value })} />
            <select style={input} value={scheduleForm.frequency} onChange={(e) => setScheduleForm({ ...scheduleForm, frequency: e.target.value })}>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
            {scheduleForm.frequency === "weekly" ? (
              <input style={input} type="number" min="0" max="6" placeholder="Day (0=Mon, 6=Sun)" value={scheduleForm.day_of_week ?? ""} onChange={(e) => setScheduleForm({ ...scheduleForm, day_of_week: e.target.value === "" ? null : Number.parseInt(e.target.value, 10), day_of_month: null })} />
            ) : null}
            {scheduleForm.frequency === "monthly" ? (
              <input style={input} type="number" min="1" max="28" placeholder="Day of month (1-28)" value={scheduleForm.day_of_month ?? ""} onChange={(e) => setScheduleForm({ ...scheduleForm, day_of_month: e.target.value === "" ? null : Number.parseInt(e.target.value, 10), day_of_week: null })} />
            ) : null}
            <input style={input} type="number" min="0" max="23" placeholder="Hour (0-23)" value={scheduleForm.hour_of_day} onChange={(e) => setScheduleForm({ ...scheduleForm, hour_of_day: Number.parseInt(e.target.value) })} />
            <select style={input} value={scheduleForm.format} onChange={(e) => setScheduleForm({ ...scheduleForm, format: e.target.value })}>
              <option value="markdown">Markdown</option>
              <option value="json">JSON</option>
            </select>
            <button style={btn} onClick={loadReportSchedules}>Load Schedules</button>
            {editingScheduleId ? (
              <button style={btn} onClick={updateReportSchedule}>Update Schedule</button>
            ) : (
              <button style={btn} onClick={createReportSchedule}>Create Schedule</button>
            )}
            {editingScheduleId ? (
              <button style={btnSecondary} onClick={cancelEditSchedule}>Cancel Edit</button>
            ) : null}
            <button style={btnSecondary} onClick={runDueSchedulesNow}>Run Due Now</button>
          </div>
          {scheduleRunSummary ? <p style={{ marginBottom: 0, color: "#34d399" }}>{scheduleRunSummary}</p> : null}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))", gap: 8, marginTop: 10 }}>
            <div style={miniCard}><div style={miniTitle}>Total</div><div>{scheduleSummary.total}</div></div>
            <div style={miniCard}><div style={miniTitle}>Enabled</div><div>{scheduleSummary.enabled}</div></div>
            <div style={miniCard}><div style={miniTitle}>Paused</div><div>{scheduleSummary.paused}</div></div>
            <div style={miniCard}><div style={miniTitle}>Due Now</div><div>{scheduleSummary.due}</div></div>
          </div>
          {reportSchedules.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <h5 style={{ margin: 0, marginBottom: 6, color: "#94a3b8" }}>Active Schedules:</h5>
              <ul style={list}>
                {reportSchedules.map((s) => (
                  <li key={s.id} style={{ ...row, cursor: "pointer", paddingRight: 6, alignItems: "center", justifyContent: "space-between" }}>
                    <span>{s.name} ({s.frequency} @ {s.hour_of_day}:00{typeof s.day_of_week === "number" ? `, dow ${s.day_of_week}` : ""}{typeof s.day_of_month === "number" ? `, dom ${s.day_of_month}` : ""}{s.next_run ? `, next ${new Date(s.next_run).toLocaleString()}` : ", paused"})</span>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button style={{ ...btnSecondary, padding: "4px 8px", fontSize: "12px" }} onClick={() => beginEditSchedule(s)}>Edit</button>
                      <button style={{ ...btnSecondary, padding: "4px 8px", fontSize: "12px" }} onClick={() => runReportSchedule(s.id)}>Run Now</button>
                      <button style={{ ...btnSecondary, padding: "4px 8px", fontSize: "12px", borderColor: s.enabled ? "#f59e0b" : "#22c55e", color: s.enabled ? "#f59e0b" : "#22c55e" }} onClick={() => toggleReportSchedule(s.id, s.enabled)}>{s.enabled ? "Pause" : "Resume"}</button>
                      <button style={{ ...btn, background: "#dc2626", padding: "4px 8px", fontSize: "12px" }} onClick={() => deleteReportSchedule(s.id)}>Delete</button>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
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
