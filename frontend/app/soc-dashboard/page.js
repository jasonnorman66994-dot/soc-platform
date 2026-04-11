"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import axios from "axios";

import AlertFeed from "../../components/AlertFeed";
import AttackGraph from "../../components/AttackGraph";
import Timeline from "../../components/Timeline";
import { connectSocSocket } from "../../lib/socket";

const SOC_API = process.env.NEXT_PUBLIC_SOC_CORE_API_URL || "http://localhost:8000";
const SOC_WS = process.env.NEXT_PUBLIC_SOC_CORE_WS_URL || "ws://localhost:8000/ws/alerts";

function buildGraphData(records) {
  const nodes = [];
  const edges = [];
  const node_seen = new Set();

  function addNode(id, label, x, y, color) {
    if (node_seen.has(id)) return;
    node_seen.add(id);
    nodes.push({
      id,
      data: { label },
      position: { x, y },
      style: {
        background: "#020617",
        color,
        border: `1px solid ${color}`,
        borderRadius: 10,
        padding: 8,
      },
    });
  }

  records.slice(0, 12).forEach((record, index) => {
    const event = record.event || {};
    const user = event.user || "anonymous";
    const ip = event.ip || "unknown_ip";
    const event_type = event.event_type || "event";

    const user_id = `user:${user}`;
    const ip_id = `ip:${ip}`;
    const event_id = `event:${index}:${event_type}`;

    addNode(user_id, `User: ${user}`, 80, 80 + index * 36, "#38bdf8");
    addNode(ip_id, `IP: ${ip}`, 380, 80 + index * 36, "#f97316");
    addNode(event_id, `Event: ${event_type}`, 700, 80 + index * 36, "#eab308");

    edges.push({ id: `${ip_id}-${user_id}-${index}`, source: ip_id, target: user_id, animated: true });
    edges.push({ id: `${user_id}-${event_id}-${index}`, source: user_id, target: event_id });
  });

  return { nodes, edges };
}

export default function SocDashboardPage() {
  const [streamRecords, setStreamRecords] = useState([]);
  const [historyEvents, setHistoryEvents] = useState([]);
  const [historyAlerts, setHistoryAlerts] = useState([]);
  const [historyIncidents, setHistoryIncidents] = useState([]);
  const [socketState, setSocketState] = useState("disconnected");
  const [replayIndex, setReplayIndex] = useState(-1);
  const [isReplaying, setIsReplaying] = useState(false);

  const timeline_events = useMemo(() => {
    const streamed = streamRecords.map((item) => item.event).filter(Boolean);
    return [...streamed, ...historyEvents].slice(0, 30);
  }, [streamRecords, historyEvents]);

  const graph_data = useMemo(() => buildGraphData(streamRecords), [streamRecords]);

  useEffect(() => {
    async function bootstrap() {
      const [events_res, alerts_res, incidents_res] = await Promise.all([
        axios.get(`${SOC_API}/events?limit=40`),
        axios.get(`${SOC_API}/alerts?limit=40`),
        axios.get(`${SOC_API}/incidents?limit=20`),
      ]);

      const events_data = events_res.data;
      const alerts_data = alerts_res.data;
      const incidents_data = incidents_res.data;

      setHistoryEvents(Array.isArray(events_data) ? events_data : []);
      setHistoryAlerts(Array.isArray(alerts_data) ? alerts_data : []);
      setHistoryIncidents(Array.isArray(incidents_data) ? incidents_data : []);
    }

    bootstrap();

    const disconnect = connectSocSocket({
      url: SOC_WS,
      onStateChange: setSocketState,
      onMessage: (payload) => {
        setStreamRecords((current) => [payload, ...current].slice(0, 60));
      },
    });

    return disconnect;
  }, []);

  useEffect(() => {
    if (!isReplaying || timeline_events.length === 0) return;

    setReplayIndex(0);
    const timer = setInterval(() => {
      setReplayIndex((current) => {
        const next = current + 1;
        if(next >= timeline_events.length)
        {
          setIsReplaying(false);
          return -1;
        }
        return next;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [isReplaying, timeline_events.length]);

  return (
    <main style={page}>
      <div style={glow_a} />
      <div style={glow_b} />

      <header style={header}>
        <div>
          <p style={kicker}>SOC Command Center</p>
          <h1 style={title}>Real-Time Threat Operations Dashboard</h1>
        </div>
        <div style={header_actions}>
          <span style={{ ...status_chip, borderColor: socketState === "connected" ? "#22c55e" : "#ef4444" }}>
            Socket: {socketState}
          </span>
          <Link href="/command-center" style={ghost_btn}>Go to Command Center</Link>
        </div>
      </header>

      <section style={metrics}>
        <article style={metric_card}><p style={metric_label}>Streamed Records</p><p style={metric_value}>{streamRecords.length}</p></article>
        <article style={metric_card}><p style={metric_label}>Persisted Alerts</p><p style={metric_value}>{historyAlerts.length}</p></article>
        <article style={metric_card}><p style={metric_label}>Open Incidents</p><p style={metric_value}>{historyIncidents.length}</p></article>
        <article style={metric_card}>
          <p style={metric_label}>Replay Controls</p>
          <button onClick={() => setIsReplaying((v) => !v)} style={replay_btn}>
            {isReplaying ? "Stop Replay" : "Play Timeline Replay"}
          </button>
        </article>
      </section>

      <section style={grid_top}>
        <AlertFeed records={streamRecords} />
        <Timeline events={timeline_events} replayIndex={replayIndex} />
      </section>

      <section style={grid_bottom}>
        <AttackGraph nodes={graph_data.nodes} edges={graph_data.edges} />
      </section>
    </main>
  );
}

const page = {
  minHeight: "100vh",
  padding: "20px clamp(16px, 3vw, 44px) 30px",
  color: "#e2e8f0",
  background: "radial-gradient(circle at 20% 10%, #0f766e 0%, #0f172a 34%, #020617 100%)",
  position: "relative",
  overflow: "hidden",
};

const glow_a = {
  position: "absolute",
  top: -80,
  right: -100,
  width: 280,
  height: 280,
  borderRadius: "50%",
  background: "rgba(45, 212, 191, 0.2)",
  filter: "blur(40px)",
};

const glow_b = {
  position: "absolute",
  left: -80,
  bottom: -110,
  width: 300,
  height: 300,
  borderRadius: "50%",
  background: "rgba(249, 115, 22, 0.14)",
  filter: "blur(40px)",
};

const header = {
  position: "relative",
  zIndex: 2,
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: 14,
  flexWrap: "wrap",
};

const kicker = {
  margin: 0,
  color: "#2dd4bf",
  textTransform: "uppercase",
  fontSize: 12,
  letterSpacing: "0.08em",
};

const title = {
  margin: "6px 0 0",
  fontFamily: "Space Grotesk, Sora, sans-serif",
  fontSize: "clamp(1.7rem, 4vw, 3rem)",
};

const header_actions = { display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" };
const status_chip = { border: "1px solid", borderRadius: 999, padding: "6px 12px", fontSize: 12, background: "#020617" };
const ghost_btn = {
  border: "1px solid rgba(148, 163, 184, 0.5)",
  color: "#e2e8f0",
  textDecoration: "none",
  borderRadius: 999,
  padding: "8px 12px",
  fontSize: 13,
};

const metrics = {
  position: "relative",
  zIndex: 2,
  marginTop: 20,
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))",
  gap: 10,
};

const metric_card = {
  background: "rgba(15, 23, 42, 0.78)",
  border: "1px solid rgba(148, 163, 184, 0.2)",
  borderRadius: 12,
  padding: 12,
};

const metric_label = { margin: 0, color: "#94a3b8", fontSize: 12 };
const metric_value = { margin: "8px 0 0", fontSize: 24, fontWeight: 800 };
const replay_btn = {
  marginTop: 8,
  width: "100%",
  border: "none",
  borderRadius: 10,
  padding: "8px 10px",
  color: "#082f49",
  background: "linear-gradient(135deg,#67e8f9,#a7f3d0)",
  fontWeight: 700,
  cursor: "pointer",
};

const grid_top = {
  marginTop: 16,
  position: "relative",
  zIndex: 2,
  display: "grid",
  gap: 12,
  gridTemplateColumns: "minmax(280px, 1fr) minmax(280px, 1fr)",
};

const grid_bottom = { marginTop: 12, position: "relative", zIndex: 2 };
