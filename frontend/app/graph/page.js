"use client";

import { useMemo, useState } from "react";
import AttackGraph from "../../components/AttackGraph";

const SAMPLE = [
  {
    event: { user: "chidera", ip: "185.10.10.10", event_type: "failed_login" },
  },
  {
    event: { user: "chidera", ip: "185.10.10.10", event_type: "login_success" },
  },
  {
    event: { user: "chidera", ip: "185.10.10.10", event_type: "privilege_change" },
  },
];

function buildGraphData(records) {
  const nodes = [];
  const edges = [];
  const nodeIds = new Set();

  function addNode(id, label, x, y, color) {
    if (nodeIds.has(id)) return;
    nodeIds.add(id);
    nodes.push({
      id,
      data: { label },
      position: { x, y },
      style: { background: "#020617", color, border: `1px solid ${color}`, borderRadius: 10 },
    });
  }

  records.forEach((record, idx) => {
    const user = record.event.user;
    const ip = record.event.ip;
    const evt = record.event.event_type;

    const userId = `u:${user}`;
    const ipId = `ip:${ip}`;
    const eventId = `evt:${idx}:${evt}`;

    addNode(userId, `User: ${user}`, 120, 100 + idx * 100, "#38bdf8");
    addNode(ipId, `IP: ${ip}`, 420, 100 + idx * 100, "#f97316");
    addNode(eventId, `Event: ${evt}`, 720, 100 + idx * 100, "#eab308");

    edges.push({ id: `${ipId}-${userId}-${idx}`, source: ipId, target: userId, animated: true });
    edges.push({ id: `${userId}-${eventId}-${idx}`, source: userId, target: eventId });
  });

  return { nodes, edges };
}

export default function GraphPage() {
  const [records] = useState(SAMPLE);
  const graphData = useMemo(() => buildGraphData(records), [records]);

  return <main style={{ padding: 20 }}><AttackGraph nodes={graphData.nodes} edges={graphData.edges} /></main>;
}
