"use client";

import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import AttackGraph from "../../components/AttackGraph";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost/api";

function scoreColor(score) {
  if (score >= 85) return "#ef4444";
  if (score >= 60) return "#f97316";
  if (score >= 35) return "#eab308";
  return "#22c55e";
}

export default function GraphPage() {
  const [tenant_id, set_tenant_id] = useState("");
  const [access_token, set_access_token] = useState("");
  const [intel_data, set_intel_data] = useState(null);
  const [selected_incident_user, set_selected_incident_user] = useState("");
  const [selected_node, set_selected_node] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function bootstrap_and_load() {
      setLoading(true);
      setError("");
      try {
        const boot_res = await axios.get(`${API}/demo/bootstrap`);
        const boot = boot_res.data;
        const tenant = boot?.tenant_id || "";
        set_tenant_id(tenant);

        const login_res = await axios.post(
          `${API}/auth/login`,
          { email: "admin@company.com", password: "admin123" },
          { headers: { "Content-Type": "application/json", "X-Tenant-ID": tenant } }
        );
        const login = login_res.data;
        if(!login?.access_token)
        {
          throw new Error(login?.detail || "Graph login failed");
        }

        set_access_token(login.access_token);
        const intel_res = await axios.get(`${API}/intelligence/overview?window_minutes=180&event_limit=280`, {
          headers: {
            Authorization: `Bearer ${login.access_token}`,
            "X-Tenant-ID": tenant,
          },
        });
        const intel = intel_res.data;

        set_intel_data(intel);
        if(Array.isArray(intel?.intelligence) && intel.intelligence[0]?.user)
        {
          set_selected_incident_user(intel.intelligence[0].user);
        }
      } catch (err) {
        if(axios.isAxiosError(err))
        {
          const msg = err.response?.data?.detail || err.message || "Failed to load intelligence graph";
          setError(msg);
        }
        else
        {
          setError(err instanceof Error ? err.message : "Failed to load intelligence graph");
        }
      } finally {
        setLoading(false);
      }
    }

    bootstrap_and_load();
  }, []);

  const graph_data = useMemo(() => {
    const nodes = [];
    const edges = [];
    const raw_nodes = intel_data?.graph?.nodes || [];
    const raw_edges = intel_data?.graph?.edges || [];

    const focus_user = selected_incident_user || null;
    const focus_user_node = focus_user ? `user:${focus_user}` : null;
    const focus_ips = new Set();
    const focus_event_nodes = new Set();
    if(focus_user_node)
    {
      raw_edges.forEach((edge) => {
        if(edge.from === focus_user_node && String(edge.to || "").startsWith("ip:"))
        {
          focus_ips.add(edge.to);
        }
        if(edge.from === focus_user_node && String(edge.to || "").startsWith("event:"))
        {
          focus_event_nodes.add(edge.to);
        }
      });
    }

    const users = raw_nodes.filter((n) => n.type === "user");
    const ips = raw_nodes.filter((n) => n.type === "ip");
    const events = raw_nodes.filter((n) => n.type === "event");

    users.forEach((n, idx) => {
      const active = n.id === focus_user_node;
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
      const active = focus_ips.has(n.id);
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
          opacity: focus_user_node && !active ? 0.5 : 1,
        },
      });
    });

    events.forEach((n, idx) => {
      const active = focus_event_nodes.has(n.id);
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
          opacity: focus_user_node && !active ? 0.4 : 1,
        },
      });
    });

    raw_edges.forEach((edge, idx) => {
      const active =
        !focus_user_node ||
        edge.from === focus_user_node ||
        edge.to === focus_user_node ||
        focus_ips.has(edge.from) ||
        focus_ips.has(edge.to) ||
        focus_event_nodes.has(edge.from) ||
        focus_event_nodes.has(edge.to);

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
  }, [intel_data, selected_incident_user]);

  const timeline_slice = useMemo(() => {
    if (!selected_incident_user) return [];
    const raw_nodes = intel_data?.graph?.nodes || [];
    const raw_edges = intel_data?.graph?.edges || [];
    const user_node_id = `user:${selected_incident_user}`;

    const linked_event_ids = new Set(
      raw_edges
        .filter((edge) => edge.from === user_node_id && String(edge.to || "").startsWith("event:"))
        .map((edge) => edge.to)
    );

    const get_time = (value) => {
      const t = Date.parse(value || "");
      return Number.isNaN(t) ? 0 : t;
    };

    return raw_nodes
      .filter((item) => item.type === "event")
      .filter((item) => linked_event_ids.size === 0 || linked_event_ids.has(item.id))
      .sort((a, b) => get_time(b.timestamp) - get_time(a.timestamp))
      .slice(0, 8);
  }, [intel_data, selected_incident_user]);

  function on_node_click(_evt, node) {
    const details = (intel_data?.graph?.nodes || []).find((n) => n.id === node.id) || null;
    set_selected_node(details);
    if(String(node.id).startsWith("user:"))
    {
      set_selected_incident_user(String(node.id).replace("user:", ""));
    }
  }

  return (
    <main style={{ padding: 20, display: "grid", gap: 12 }}>
      <h1 style={{ margin: 0, color: "#60a5fa" }}>Incident Intelligence Graph</h1>
      <p style={{ margin: 0, color: "#94a3b8" }}>
        Tenant: {tenant_id || "-"} | Auth: {access_token ? "connected" : "pending"}
      </p>
      {loading ? <p style={{ color: "#94a3b8" }}>Loading intelligence...</p> : null}
      {error ? <p style={{ color: "#f87171" }}>{error}</p> : null}

      {!loading && !error ? (
        <>
          <section style={panel}>
            <h3 style={title}>Incident Queue</h3>
            <div style={{ display: "grid", gap: 8 }}>
              {(intel_data?.intelligence || []).map((item) => (
                <button
                  key={item.user}
                  onClick={() => set_selected_incident_user(item.user)}
                  style={{
                    textAlign: "left",
                    background: item.user === selected_incident_user ? "#0c4a6e" : "#0f172a",
                    border: `1px solid ${item.user === selected_incident_user ? "#22d3ee" : "#334155"}`,
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

          <AttackGraph nodes={graph_data.nodes} edges={graph_data.edges} onNodeClick={on_node_click} />

          <section style={panel}>
            <h3 style={title}>Node Intelligence</h3>
            {selected_node ? (
              <pre style={pre}>{JSON.stringify(selected_node, null, 2)}</pre>
            ) : (
              <p style={{ color: "#94a3b8", margin: 0 }}>Click a graph node to inspect relationships and context.</p>
            )}
          </section>

          <section style={panel}>
            <h3 style={title}>Timeline Slice</h3>
            <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 6 }}>
              {timeline_slice.map((item) => (
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
