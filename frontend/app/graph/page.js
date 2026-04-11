"use client";

import { useEffect, useMemo, useState } from "react";
import AttackGraph from "../../components/AttackGraph";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost/api";

function scoreColor(score) {
  if (score >= 85) return "#ef4444";
  if (score >= 60) return "#f97316";
  if (score >= 35) return "#eab308";
  return "#22c55e";
}

export default function GraphPage() {
  const [tenantId, setTenantId] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [intelData, setIntelData] = useState(null);
  const [selectedIncidentUser, setSelectedIncidentUser] = useState("");
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function bootstrapAndLoad() {
      setLoading(true);
      setError("");
      try {
        const bootRes = await fetch(`${API}/demo/bootstrap`);
        const boot = await bootRes.json();
        const tenant = boot?.tenant_id || "";
        setTenantId(tenant);

        const loginRes = await fetch(`${API}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Tenant-ID": tenant },
          body: JSON.stringify({ email: "admin@company.com", password: "admin123" }),
        });
        const login = await loginRes.json();
        if (!loginRes.ok || !login?.access_token) {
          throw new Error(login?.detail || "Graph login failed");
        }

        setAccessToken(login.access_token);
        const intelRes = await fetch(`${API}/intelligence/overview?window_minutes=180&event_limit=280`, {
          headers: {
            Authorization: `Bearer ${login.access_token}`,
            "X-Tenant-ID": tenant,
          },
        });
        const intel = await intelRes.json();
        if (!intelRes.ok) {
          throw new Error(intel?.detail || "Failed to load intelligence overview");
        }

        setIntelData(intel);
        if (Array.isArray(intel?.intelligence) && intel.intelligence[0]?.user) {
          setSelectedIncidentUser(intel.intelligence[0].user);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load intelligence graph");
      } finally {
        setLoading(false);
      }
    }

    bootstrapAndLoad();
  }, []);

  const graphData = useMemo(() => {
    const nodes = [];
    const edges = [];
    const rawNodes = intelData?.graph?.nodes || [];
    const rawEdges = intelData?.graph?.edges || [];

    const focusUser = selectedIncidentUser || null;
    const focusUserNode = focusUser ? `user:${focusUser}` : null;
    const focusIps = new Set();
    const focusEventNodes = new Set();
    if (focusUserNode) {
      rawEdges.forEach((edge) => {
        if (edge.from === focusUserNode && String(edge.to || "").startsWith("ip:")) {
          focusIps.add(edge.to);
        }
        if (edge.from === focusUserNode && String(edge.to || "").startsWith("event:")) {
          focusEventNodes.add(edge.to);
        }
      });
    }

    const users = rawNodes.filter((n) => n.type === "user");
    const ips = rawNodes.filter((n) => n.type === "ip");
    const events = rawNodes.filter((n) => n.type === "event");

    users.forEach((n, idx) => {
      const active = n.id === focusUserNode;
      const color = scoreColor(Number(n.risk_score || 0));
      nodes.push({
        id: n.id,
        data: { label: `User: ${n.label}` },
        position: { x: 80, y: 60 + idx * 120 },
        style: {
          background: "#020617",
          color,
          border: `2px solid ${active ? "#22d3ee" : color}`,
          borderRadius: 10,
          minWidth: 180,
        },
      });
    });

    ips.forEach((n, idx) => {
      const active = focusIps.has(n.id);
      nodes.push({
        id: n.id,
        data: { label: `IP: ${n.label}` },
        position: { x: 430, y: 60 + idx * 90 },
        style: {
          background: "#020617",
          color: "#f97316",
          border: `2px solid ${active ? "#22d3ee" : "#f97316"}`,
          borderRadius: 10,
          minWidth: 180,
          opacity: focusUserNode && !active ? 0.5 : 1,
        },
      });
    });

    events.forEach((n, idx) => {
      const active = focusEventNodes.has(n.id);
      nodes.push({
        id: n.id,
        data: { label: `Event: ${n.label}` },
        position: { x: 780, y: 60 + idx * 70 },
        style: {
          background: "#020617",
          color: "#eab308",
          border: `2px solid ${active ? "#22d3ee" : "#eab308"}`,
          borderRadius: 10,
          minWidth: 210,
          opacity: focusUserNode && !active ? 0.4 : 1,
        },
      });
    });

    rawEdges.forEach((edge, idx) => {
      const active =
        !focusUserNode ||
        edge.from === focusUserNode ||
        edge.to === focusUserNode ||
        focusIps.has(edge.from) ||
        focusIps.has(edge.to) ||
        focusEventNodes.has(edge.from) ||
        focusEventNodes.has(edge.to);

      edges.push({
        id: `e:${idx}:${edge.from}:${edge.to}:${edge.label}`,
        source: edge.from,
        target: edge.to,
        label: edge.label,
        animated: active,
        style: { opacity: active ? 1 : 0.2 },
      });
    });

    return { nodes, edges };
  }, [intelData, selectedIncidentUser]);

  const timelineSlice = useMemo(() => {
    if (!selectedIncidentUser) return [];
    return (intelData?.graph?.nodes || [])
      .filter((item) => item.type === "event")
      .slice(-8);
  }, [intelData, selectedIncidentUser]);

  function onNodeClick(_evt, node) {
    const details = (intelData?.graph?.nodes || []).find((n) => n.id === node.id) || null;
    setSelectedNode(details);
    if (String(node.id).startsWith("user:")) {
      setSelectedIncidentUser(String(node.id).replace("user:", ""));
    }
  }

  return (
    <main style={{ padding: 20, display: "grid", gap: 12 }}>
      <h1 style={{ margin: 0, color: "#60a5fa" }}>Incident Intelligence Graph</h1>
      <p style={{ margin: 0, color: "#94a3b8" }}>
        Tenant: {tenantId || "-"} | Auth: {accessToken ? "connected" : "pending"}
      </p>
      {loading ? <p style={{ color: "#94a3b8" }}>Loading intelligence...</p> : null}
      {error ? <p style={{ color: "#f87171" }}>{error}</p> : null}

      {!loading && !error ? (
        <>
          <section style={panel}>
            <h3 style={title}>Incident Queue</h3>
            <div style={{ display: "grid", gap: 8 }}>
              {(intelData?.intelligence || []).map((item) => (
                <button
                  key={item.user}
                  onClick={() => setSelectedIncidentUser(item.user)}
                  style={{
                    textAlign: "left",
                    background: item.user === selectedIncidentUser ? "#0c4a6e" : "#0f172a",
                    border: `1px solid ${item.user === selectedIncidentUser ? "#22d3ee" : "#334155"}`,
                    color: "#e2e8f0",
                    borderRadius: 8,
                    padding: "8px 10px",
                    cursor: "pointer",
                  }}
                >
                  {item.user} | Risk {item.risk_score}/100 | {item.patterns.join(", ") || "no patterns"}
                </button>
              ))}
            </div>
          </section>

          <AttackGraph nodes={graphData.nodes} edges={graphData.edges} onNodeClick={onNodeClick} />

          <section style={panel}>
            <h3 style={title}>Node Intelligence</h3>
            {selectedNode ? (
              <pre style={pre}>{JSON.stringify(selectedNode, null, 2)}</pre>
            ) : (
              <p style={{ color: "#94a3b8", margin: 0 }}>Click a graph node to inspect relationships and context.</p>
            )}
          </section>

          <section style={panel}>
            <h3 style={title}>Timeline Slice</h3>
            <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 6 }}>
              {timelineSlice.map((item) => (
                <li key={item.id} style={{ borderBottom: "1px solid #1e293b", paddingBottom: 6, color: "#cbd5e1" }}>
                  {item.timestamp || "-"} | {item.label}
                </li>
              ))}
            </ul>
          </section>
        </>
      ) : null}
    </main>
  );
}

const panel = {
  background: "rgba(15, 23, 42, 0.78)",
  border: "1px solid rgba(14, 165, 233, 0.35)",
  borderRadius: 16,
  padding: 14,
};

const title = { marginTop: 0, marginBottom: 10, fontFamily: "Space Grotesk, Sora, sans-serif" };

const pre = {
  margin: 0,
  background: "#020617",
  border: "1px solid #1e293b",
  borderRadius: 8,
  padding: 10,
  overflowX: "auto",
  color: "#e2e8f0",
};
